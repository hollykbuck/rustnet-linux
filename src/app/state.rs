use dashmap::DashMap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Instant, SystemTime};

use crate::app::logging::log_connection_event;
use crate::app::types::AppStats;
use crate::network::bogon::{Scope, classify};
use crate::network::dns::DnsResolver;
use crate::network::oui::OuiLookup;
use crate::network::parser::ParsedPacket;
use crate::network::types::{
    ApplicationProtocol, ArpOperation, Connection, Device, DpiInfo, NdpOperation, ProtocolState,
};

/// Global mapping for QUIC connection IDs to connection keys.
/// Used to track QUIC connections as they migrate across client IP/port changes.
pub static QUIC_CONNECTION_MAPPING: LazyLock<DashMap<Vec<u8>, String>> =
    LazyLock::new(DashMap::new);

use crate::app::logging::LogEvent;
use crossbeam::channel::Sender;

/// Update connection state based on a parsed packet
pub fn update_connection(
    connections: &DashMap<String, Connection>,
    parsed: ParsedPacket,
    stats: &AppStats,
    json_log_path: &Option<String>,
    _rtt_tracker: &Arc<Mutex<crate::network::types::RttTracker>>,
    dns_resolver: Option<&DnsResolver>,
    log_tx: &Sender<LogEvent>,
) {
    let key = parsed.connection_key.clone();
    let now = SystemTime::now();
    let instant_now = Instant::now();

    // Special handling for QUIC: check for connection migration via CID
    // We check if DPI identified QUIC and use its CID if available
    let final_key = if let Some(ref dpi) = parsed.dpi_result
        && let ApplicationProtocol::Quic(ref info) = dpi.application
    {
        let mut resolved_key = key.clone();

        // Try to match CID first (we'll just use connection_id as destination CID for now)
        if let Some(existing_key) = QUIC_CONNECTION_MAPPING.get(&info.connection_id) {
            resolved_key = existing_key.clone();
        }

        // Register CID for this connection key
        QUIC_CONNECTION_MAPPING.insert(info.connection_id.clone(), resolved_key.clone());
        resolved_key
    } else {
        key
    };

    connections
        .entry(final_key)
        .and_modify(|c| {
            // Update stats
            if parsed.is_outgoing {
                c.bytes_sent += parsed.packet_len as u64;
                c.packets_sent += 1;
            } else {
                c.bytes_received += parsed.packet_len as u64;
                c.packets_received += 1;
            }

            c.last_activity = now;

            // Update state (TCP, etc.)
            let old_state = c.protocol_state.clone();
            c.protocol_state = parsed.protocol_state.clone();

            // Log state transitions
            if old_state != c.protocol_state
                && let Some(log_path) = json_log_path
            {
                log_connection_event(log_path, "state_change", c, None, dns_resolver);
            }

            // Update DPI info if available
            if let Some(ref dpi) = parsed.dpi_result {
                c.dpi_info = Some(DpiInfo {
                    application: dpi.application.clone(),
                    last_update_time: instant_now,
                });
            }
        })
        .or_insert_with(|| {
            // Log new connection
            stats.connections_tracked.fetch_add(1, Ordering::Relaxed);

            let conn = Connection {
                protocol: parsed.protocol,
                local_addr: parsed.local_addr,
                remote_addr: parsed.remote_addr,
                protocol_state: parsed.protocol_state,
                pid: parsed.process_id,
                process_name: parsed.process_name,
                connection_direction: Some(parsed.is_outgoing),
                bytes_sent: if parsed.is_outgoing {
                    parsed.packet_len as u64
                } else {
                    0
                },
                bytes_received: if parsed.is_outgoing {
                    0
                } else {
                    parsed.packet_len as u64
                },
                packets_sent: if parsed.is_outgoing { 1 } else { 0 },
                packets_received: if parsed.is_outgoing { 0 } else { 1 },
                created_at: now,
                last_activity: now,
                closed_at: None,
                service_name: None,
                dpi_info: parsed.dpi_result.map(|d| DpiInfo {
                    application: d.application,
                    last_update_time: instant_now,
                }),
                geoip_info: None,
                is_historic: false,
                current_incoming_rate_bps: 0.0,
                current_outgoing_rate_bps: 0.0,
                rate_tracker: crate::network::types::RateTracker::new(),
                tcp_analytics: None,
                initial_rtt: None,
            };

            // Async log new connection
            if let Some(log_path) = json_log_path {
                let _ = log_tx.try_send(LogEvent::Connection {
                    json_log_path: log_path.clone(),
                    event_type: "connection_new".to_string(),
                    connection: conn.clone(),
                    duration_secs: None,
                    source_hostname: dns_resolver.and_then(|r| r.get_hostname(&conn.local_addr.ip())),
                    dest_hostname: dns_resolver.and_then(|r| r.get_hostname(&conn.remote_addr.ip())),
                });
            }

            conn
        });
}

/// Update device discovery tracker with info from a parsed packet
pub fn update_device(
    devices: &DashMap<String, Device>,
    parsed: ParsedPacket,
    oui_lookup: Option<Arc<OuiLookup>>,
) {
    let now = SystemTime::now();

    // Check if this packet provides a definitive IP-MAC binding (ARP or DHCP)
    let is_dhcp = if let Some(ref dpi) = parsed.dpi_result {
        matches!(dpi.application, ApplicationProtocol::Dhcp(_))
    } else {
        false
    };

    // Helper to update or create a device entry.
    // `force` bypasses the scope check (used for explicit ARP mappings).
    let upsert_device = |ip: IpAddr, mac: Option<String>, is_sent: bool, force: bool| {
        // Skip multicast and broadcast IPs
        if ip.is_multicast() || ip.is_unspecified() {
            return;
        }

        // Special handling for IPv4 broadcast
        if let IpAddr::V4(v4) = ip
            && (v4.is_broadcast() || v4.octets()[3] == 255)
        {
            return;
        }

        // Signal strength: ARP and DHCP are definitive.
        let is_definitive = force || is_dhcp;

        // Apply heuristic: only trust IP-MAC association if the IP is local/private,
        // or if it's an explicit ARP/DHCP confirmation.
        if !is_definitive {
            let scope = classify(ip);
            match scope {
                Scope::Private | Scope::LinkLocal | Scope::UniqueLocal | Scope::Cgnat => {}
                _ => return, // Don't trust public/other IPs for local discovery
            }
        }

        // We need at least a MAC address to identify a unique hardware device
        let mac_addr = match mac {
            Some(m) if !m.is_empty() && m != "00:00:00:00:00:00" && m != "ff:ff:ff:ff:ff:ff" => m,
            _ => return,
        };

        let protocol_str = parsed.protocol.to_string();

        devices
            .entry(mac_addr.clone())
            .and_modify(|d| {
                // Collect all IPs seen for this MAC
                d.ips.insert(ip);

                d.last_seen = now;
                d.is_online = true;
                if is_sent {
                    d.bytes_sent += parsed.packet_len as u64;
                } else {
                    d.bytes_received += parsed.packet_len as u64;
                }
                d.protocols.insert(protocol_str.clone());

                // Update open ports and discovery details
                if let Some(ref dpi) = parsed.dpi_result {
                    let mut name_from_protocol = None;
                    let detail = match &dpi.application {
                        ApplicationProtocol::NetBios(info) => {
                            if let Some(name) = &info.name {
                                name_from_protocol = Some(name.clone());
                                format!("NetBIOS:{}", name)
                            } else {
                                "NetBIOS".to_string()
                            }
                        }
                        ApplicationProtocol::Mdns(info) => {
                            if let Some(name) = &info.query_name {
                                name_from_protocol = Some(name.clone());
                                format!("mDNS:{}", name)
                            } else {
                                "mDNS".to_string()
                            }
                        }
                        ApplicationProtocol::Dhcp(info) => {
                            if let Some(host) = &info.hostname {
                                name_from_protocol = Some(host.clone());
                                format!("DHCP:{}", host)
                            } else {
                                "DHCP".to_string()
                            }
                        }
                        ApplicationProtocol::Dns(info) => {
                            if let Some(name) = &info.query_name {
                                format!("DNS:{}", name)
                            } else {
                                "DNS".to_string()
                            }
                        }
                        _ => String::new(),
                    };

                    if let Some(name) = name_from_protocol
                        && d.hostname.is_none()
                    {
                        d.hostname = Some(name);
                    }

                    if !detail.is_empty() {
                        d.discovery_details.insert(detail);
                    }
                }

                // Track active ports
                let port = if is_sent {
                    parsed.local_addr.port()
                } else {
                    parsed.remote_addr.port()
                };
                if port > 0 && port < 32768 {
                    // Only track "server" ports (well-known or registered)
                    // This is a heuristic - usually client ports are high
                    d.open_ports.entry(port).or_insert_with(String::new);
                }
            })
            .or_insert_with(|| {
                let vendor = oui_lookup
                    .as_ref()
                    .and_then(|oui| oui.lookup(&mac_addr).map(String::from));
                let mut protocols = std::collections::HashSet::new();
                protocols.insert(protocol_str);

                let mut discovery_details = std::collections::HashSet::new();
                let mut open_ports = std::collections::BTreeMap::new();
                let mut ips = std::collections::HashSet::new();
                ips.insert(ip);

                let mut hostname = None;
                if let Some(ref dpi) = parsed.dpi_result {
                    let mut name_from_protocol = None;
                    let detail = match &dpi.application {
                        ApplicationProtocol::NetBios(info) => {
                            if let Some(name) = &info.name {
                                name_from_protocol = Some(name.clone());
                                format!("NetBIOS:{}", name)
                            } else {
                                "NetBIOS".to_string()
                            }
                        }
                        ApplicationProtocol::Mdns(info) => {
                            if let Some(name) = &info.query_name {
                                name_from_protocol = Some(name.clone());
                                format!("mDNS:{}", name)
                            } else {
                                "mDNS".to_string()
                            }
                        }
                        ApplicationProtocol::Dhcp(info) => {
                            if let Some(host) = &info.hostname {
                                name_from_protocol = Some(host.clone());
                                format!("DHCP:{}", host)
                            } else {
                                "DHCP".to_string()
                            }
                        }
                        ApplicationProtocol::Dns(info) => {
                            if let Some(name) = &info.query_name {
                                format!("DNS:{}", name)
                            } else {
                                "DNS".to_string()
                            }
                        }
                        _ => String::new(),
                    };

                    hostname = name_from_protocol;

                    if !detail.is_empty() {
                        discovery_details.insert(detail);
                    }
                }

                let port = if is_sent {
                    parsed.local_addr.port()
                } else {
                    parsed.remote_addr.port()
                };
                if port > 0 && port < 32768 {
                    open_ports.insert(port, String::new());
                }

                Device {
                    ips,
                    mac: mac_addr,
                    vendor,
                    hostname,
                    first_seen: now,
                    last_seen: now,
                    bytes_sent: if is_sent { parsed.packet_len as u64 } else { 0 },
                    bytes_received: if is_sent { 0 } else { parsed.packet_len as u64 },
                    protocols,
                    is_online: true,
                    is_gateway: false,
                    open_ports,
                    discovery_details,
                }
            });
    };

    // Update discovery based on protocol type
    if let ProtocolState::Arp(ref arp) = parsed.protocol_state {
        // For ARP, we have explicit sender mapping
        upsert_device(arp.sender_ip, Some(arp.sender_mac.clone()), true, true);

        // For replies, the target mapping is also definitive
        if arp.operation == ArpOperation::Reply {
            upsert_device(arp.target_ip, Some(arp.target_mac.clone()), false, true);
        }
    } else if let ProtocolState::Ndp(ref ndp) = parsed.protocol_state {
        // For NDP, handle similarly to ARP
        if let Some(src_mac) = &ndp.source_mac {
            upsert_device(ndp.source_ip, Some(src_mac.clone()), true, true);
        }

        // For Neighbor Advertisement, the target address binding is definitive
        if ndp.operation == NdpOperation::NeighborAdvertisement
            && let Some(target_mac) = &ndp.target_mac
        {
            upsert_device(ndp.target_ip, Some(target_mac.clone()), false, true);
        }
    } else {
        // For IP protocols, use the local and remote endpoints from the packet.
        // `upsert_device` will apply the scope heuristic internally.
        if parsed.is_outgoing {
            upsert_device(
                parsed.local_addr.ip(),
                parsed.local_mac.clone(),
                true,
                false,
            );
            upsert_device(
                parsed.remote_addr.ip(),
                parsed.remote_mac.clone(),
                false,
                false,
            );
        } else {
            upsert_device(
                parsed.local_addr.ip(),
                parsed.local_mac.clone(),
                false,
                false,
            );
            upsert_device(
                parsed.remote_addr.ip(),
                parsed.remote_mac.clone(),
                true,
                false,
            );
        }
    }
}

/// Sort listeners based on specified criteria
pub fn sort_listeners(
    listeners: &mut [crate::network::types::Listener],
    column: crate::ui::ServiceSortColumn,
    ascending: bool,
) {
    use crate::ui::ServiceSortColumn;

    listeners.sort_by(|a, b| {
        let (ord, default_asc) = match column {
            ServiceSortColumn::Protocol => (a.protocol.cmp(&b.protocol), true),
            ServiceSortColumn::LocalAddress => (a.local_addr.cmp(&b.local_addr), true),
            ServiceSortColumn::Service => (a.service_name.cmp(&b.service_name), true),
            ServiceSortColumn::Process => (a.process_name.cmp(&b.process_name), true),
            ServiceSortColumn::Connections => {
                (a.active_connections.cmp(&b.active_connections), false)
            }
        };
        if ascending == default_asc {
            ord
        } else {
            ord.reverse()
        }
    });
}

/// Sort devices based on specified criteria
pub fn sort_devices(devices: &mut [Device], column: crate::ui::DeviceSortColumn, ascending: bool) {
    use crate::ui::DeviceSortColumn;

    devices.sort_by(|a, b| {
        let ordering = match column {
            DeviceSortColumn::Status => a.is_online.cmp(&b.is_online),
            DeviceSortColumn::IpAddress => a.primary_ip().cmp(&b.primary_ip()),
            DeviceSortColumn::Hostname => a.hostname.cmp(&b.hostname),
            DeviceSortColumn::MacAddress => a.mac.cmp(&b.mac),
            DeviceSortColumn::Vendor => a.vendor.cmp(&b.vendor),
            DeviceSortColumn::LastSeen => a.last_seen.cmp(&b.last_seen),
            DeviceSortColumn::BytesReceived => a.bytes_received.cmp(&b.bytes_received),
            DeviceSortColumn::BytesSent => a.bytes_sent.cmp(&b.bytes_sent),
        };

        if ascending {
            ordering
        } else {
            ordering.reverse()
        }
    });
}

/// Sort connections based on the specified column and direction
pub fn sort_connections(
    connections: &mut [Connection],
    sort_column: crate::ui::SortColumn,
    ascending: bool,
) {
    use crate::ui::SortColumn;

    connections.sort_by(|a, b| {
        let ordering = match sort_column {
            SortColumn::CreatedAt => a.created_at.cmp(&b.created_at),
            SortColumn::BandwidthTotal => {
                (a.bytes_sent + a.bytes_received).cmp(&(b.bytes_sent + b.bytes_received))
            }
            SortColumn::Process => a.process_name.cmp(&b.process_name),
            SortColumn::LocalAddress => a.local_addr.cmp(&b.local_addr),
            SortColumn::RemoteAddress => a.remote_addr.cmp(&b.remote_addr),
            SortColumn::Location => a
                .geoip_info
                .as_ref()
                .map(|g| &g.country_code)
                .cmp(&b.geoip_info.as_ref().map(|g| &g.country_code)),
            SortColumn::Application => {
                let a_app = a.dpi_info.as_ref().map(|d| d.application.to_string());
                let b_app = b.dpi_info.as_ref().map(|d| d.application.to_string());
                a_app.cmp(&b_app)
            }
            SortColumn::Service => a.service_name.cmp(&b.service_name),
            SortColumn::State => a.state().cmp(&b.state()),
            SortColumn::Protocol => a.protocol.cmp(&b.protocol),
        };

        if ascending {
            ordering
        } else {
            ordering.reverse()
        }
    });
}
