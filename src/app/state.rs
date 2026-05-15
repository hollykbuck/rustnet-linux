use dashmap::DashMap;
use log::debug;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, SystemTime};

use crate::app::logging::log_connection_event;
use crate::app::types::AppStats;
use crate::network::bogon::{Scope, classify};
use crate::network::dns::DnsResolver;
use crate::network::merge::{create_connection_from_packet, merge_packet_into_connection};
use crate::network::oui::OuiLookup;
use crate::network::parser::ParsedPacket;
use crate::network::types::{
    ApplicationProtocol, ArpOperation, Connection, ConnectionKey, Device, Protocol, ProtocolState,
    RttTracker,
};

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
            ServiceSortColumn::Connections => (a.active_connections.cmp(&b.active_connections), false),
        };
        if ascending == default_asc {
            ord
        } else {
            ord.reverse()
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
                // Compare combined up+down bandwidth, handle NaN cases
                let a_total = a.current_incoming_rate_bps + a.current_outgoing_rate_bps;
                let b_total = b.current_incoming_rate_bps + b.current_outgoing_rate_bps;
                a_total
                    .partial_cmp(&b_total)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }

            SortColumn::Process => {
                let a_process = a.process_name.as_deref().unwrap_or("");
                let b_process = b.process_name.as_deref().unwrap_or("");
                a_process.cmp(b_process)
            }

            SortColumn::LocalAddress => a
                .local_addr
                .ip()
                .cmp(&b.local_addr.ip())
                .then_with(|| a.local_addr.port().cmp(&b.local_addr.port())),

            SortColumn::RemoteAddress => a
                .remote_addr
                .ip()
                .cmp(&b.remote_addr.ip())
                .then_with(|| a.remote_addr.port().cmp(&b.remote_addr.port())),

            SortColumn::Application => {
                let a_app = a.dpi_info.as_ref().map(|dpi| dpi.application.sort_key());
                let b_app = b.dpi_info.as_ref().map(|dpi| dpi.application.sort_key());
                a_app.cmp(&b_app)
            }

            SortColumn::Service => {
                let a_service = a.service_name.as_deref().unwrap_or("");
                let b_service = b.service_name.as_deref().unwrap_or("");
                a_service.cmp(b_service)
            }

            SortColumn::State => Ord::cmp(&a.state(), &b.state()),

            SortColumn::Location => {
                let a_loc = a
                    .geoip_info
                    .as_ref()
                    .and_then(|g| g.country_code.as_deref())
                    .unwrap_or("");
                let b_loc = b
                    .geoip_info
                    .as_ref()
                    .and_then(|g| g.country_code.as_deref())
                    .unwrap_or("");
                a_loc.cmp(b_loc)
            }

            SortColumn::Protocol => a.protocol.cmp(&b.protocol),
        };

        if ascending {
            ordering
        } else {
            ordering.reverse()
        }
    });
}

/// Global QUIC connection ID to connection key mapping
/// This allows tracking QUIC connections across connection ID changes
pub static QUIC_CONNECTION_MAPPING: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Maximum QUIC connection ID mappings to prevent unbounded growth.
pub const MAX_QUIC_MAPPINGS: usize = 10_000;

/// Maximum tracked connections to prevent memory exhaustion from port scans
/// or connection floods.
pub const MAX_CONNECTIONS: usize = 50_000;

/// Update or create a connection from a parsed packet
pub fn update_connection(
    connections: &DashMap<String, Connection>,
    parsed: ParsedPacket,
    stats: &AppStats,
    json_log_path: &Option<String>,
    rtt_tracker: &Arc<Mutex<RttTracker>>,
    dns_resolver: Option<&DnsResolver>,
) {
    let mut key = parsed.connection_key.clone();
    let now = SystemTime::now();

    // Track RTT for TCP connections using SYN/SYN-ACK timing
    let mut measured_rtt: Option<std::time::Duration> = None;
    if parsed.protocol == Protocol::Tcp
        && let Some(tcp_header) = &parsed.tcp_header
    {
        let conn_key = ConnectionKey::new(parsed.local_addr, parsed.remote_addr);

        if tcp_header.flags.syn && !tcp_header.flags.ack {
            // This is a SYN packet (outgoing connection initiation)
            if let Ok(mut tracker) = rtt_tracker.lock() {
                tracker.record_syn(conn_key);
            }
        } else if tcp_header.flags.syn && tcp_header.flags.ack {
            // This is a SYN-ACK packet (connection response)
            if let Ok(mut tracker) = rtt_tracker.lock() {
                measured_rtt = tracker.record_syn_ack(&conn_key);
            }
        }
    }

    // For QUIC packets, check if we have a connection ID mapping
    if parsed.protocol == Protocol::Udp
        && let Some(dpi_result) = &parsed.dpi_result
        && let ApplicationProtocol::Quic(quic_info) = &dpi_result.application
        && let Some(conn_id_hex) = &quic_info.connection_id_hex
        && let Ok(mut mapping) = QUIC_CONNECTION_MAPPING.lock()
    {
        if let Some(existing_key) = mapping.get(conn_id_hex) {
            key = existing_key.clone();
            debug!(
                "QUIC: Using existing connection key {} for Connection ID {}",
                key, conn_id_hex
            );
        } else {
            // Prevent unbounded growth of QUIC connection ID mappings
            if mapping.len() >= MAX_QUIC_MAPPINGS {
                debug!("QUIC mapping limit reached, clearing old entries");
                mapping.clear();
            }
            // New QUIC connection ID, create mapping
            mapping.insert(conn_id_hex.clone(), key.clone());
            debug!(
                "QUIC: Created new mapping {} -> {} for Connection ID {}",
                conn_id_hex, key, conn_id_hex
            );
        }
    }

    // Prevent unbounded growth from port scans or connection floods.
    // Only limit new connections; existing ones always get updated.
    if !connections.contains_key(&key) && connections.len() >= MAX_CONNECTIONS {
        debug!(
            "Connection limit reached ({}), dropping new connection: {}",
            MAX_CONNECTIONS, key
        );
        return;
    }

    connections
        .entry(key.clone())
        .and_modify(|conn| {
            let (new_retransmits, new_out_of_order, new_fast_retransmits) =
                merge_packet_into_connection(conn, &parsed, now);

            // Store RTT measurement if we got one from SYN-ACK
            if let Some(rtt) = measured_rtt
                && conn.initial_rtt.is_none()
            {
                conn.initial_rtt = Some(rtt);
                debug!("RTT measured for {}: {:?}", key, rtt);
            }

            // Update global statistics
            if new_retransmits > 0 {
                stats
                    .total_tcp_retransmits
                    .fetch_add(new_retransmits, Ordering::Relaxed);
            }
            if new_out_of_order > 0 {
                stats
                    .total_tcp_out_of_order
                    .fetch_add(new_out_of_order, Ordering::Relaxed);
            }
            if new_fast_retransmits > 0 {
                stats
                    .total_tcp_fast_retransmits
                    .fetch_add(new_fast_retransmits, Ordering::Relaxed);
            }
        })
        .or_insert_with(|| {
            debug!("New connection detected: {}", key);
            let mut conn = create_connection_from_packet(&parsed, now);

            // Store RTT measurement if we got one (unlikely for new connection, but handle it)
            if let Some(rtt) = measured_rtt {
                conn.initial_rtt = Some(rtt);
            }

            // Log new connection event if JSON logging is enabled
            if let Some(log_path) = json_log_path {
                log_connection_event(log_path, "new_connection", &conn, None, dns_resolver);
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
                // If the IP changed, only update it if the new signal is definitive
                // or if the existing IP is extremely stale (e.g. 1 hour).
                // This prevents gateway MACs from "jumping" between the IPs of
                // various routed internal hosts.
                if d.ip != ip {
                    let is_stale = d
                        .last_seen
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .is_ok_and(|_| {
                            d.last_seen.elapsed().unwrap_or_default() > Duration::from_secs(3600)
                        });

                    if is_definitive || is_stale {
                        d.ip = ip;
                    }
                }

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
                    let detail = match &dpi.application {
                        ApplicationProtocol::NetBios(info) => {
                            if let Some(name) = &info.name {
                                format!("NetBIOS:{}", name)
                            } else {
                                "NetBIOS".to_string()
                            }
                        }
                        ApplicationProtocol::Mdns(info) => {
                            if let Some(name) = &info.query_name {
                                format!("mDNS:{}", name)
                            } else {
                                "mDNS".to_string()
                            }
                        }
                        ApplicationProtocol::Dhcp(info) => {
                            if let Some(host) = &info.hostname {
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

                if let Some(ref dpi) = parsed.dpi_result {
                    let detail = match &dpi.application {
                        ApplicationProtocol::NetBios(info) => {
                            if let Some(name) = &info.name {
                                format!("NetBIOS:{}", name)
                            } else {
                                "NetBIOS".to_string()
                            }
                        }
                        ApplicationProtocol::Mdns(info) => {
                            if let Some(name) = &info.query_name {
                                format!("mDNS:{}", name)
                            } else {
                                "mDNS".to_string()
                            }
                        }
                        ApplicationProtocol::Dhcp(info) => {
                            if let Some(host) = &info.hostname {
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
                    ip,
                    mac: mac_addr,
                    vendor,
                    hostname: None, // Will be filled by background refresh if possible
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
