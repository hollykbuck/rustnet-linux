// network/platform/linux/routes.rs - Linux routing table provider (Netlink + procfs fallback)

use crate::network::types::RouteEntry;
use anyhow::{Context, Result};
use futures::stream::TryStreamExt;
use rtnetlink::new_connection;
use netlink_packet_route::route::{RouteMessage, RouteAttribute, RouteAddress};
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::AddressFamily;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct LinuxRouteProvider;

impl LinuxRouteProvider {
    /// Get system routing table entries using Netlink, falling back to procfs
    pub async fn get_routes() -> Result<Vec<RouteEntry>> {
        match Self::get_routes_netlink().await {
            Ok(routes) => Ok(routes),
            Err(e) => {
                log::warn!("Netlink routing lookup failed, falling back to procfs: {}", e);
                Self::get_routes_procfs()
            }
        }
    }

    /// Fetch routes using rtnetlink (supports multiple tables / PBR)
    async fn get_routes_netlink() -> Result<Vec<RouteEntry>> {
        let (connection, handle, _) = new_connection().context("Failed to connect to Netlink")?;
        tokio::spawn(connection);

        // 1. Get link list to map interface index -> name
        let mut links = handle.link().get().execute();
        let mut index_to_name = HashMap::new();
        while let Some(link) = links.try_next().await.context("Failed to get Netlink links")? {
            let index = link.header.index;
            for attr in link.attributes {
                if let LinkAttribute::IfName(name) = attr {
                    index_to_name.insert(index, name);
                }
            }
        }

        let mut routes = Vec::new();

        // 2. Fetch IPv4 and IPv6 routes
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut message = RouteMessage::default();
            message.header.address_family = family;
            
            let mut route_stream = handle.route().get(message).execute();
            while let Some(route) = route_stream
                .try_next()
                .await
                .context("Failed to get Netlink routes")?
            {
                let mut destination = None;
                let mut gateway = None;
                let mut interface = String::new();
                let mut metric = 0;
                let mut table_id = route.header.table as u32;
                let mut pref_src = None;

                for attr in &route.attributes {
                    match attr {
                        RouteAttribute::Destination(dest) => {
                            destination = route_address_to_ip(dest);
                        }
                        RouteAttribute::Gateway(gw) => {
                            gateway = route_address_to_ip(gw);
                        }
                        RouteAttribute::Oif(index) => {
                            if let Some(name) = index_to_name.get(index) {
                                interface = name.clone();
                            } else {
                                interface = index.to_string();
                            }
                        }
                        RouteAttribute::Priority(prio) => {
                            metric = *prio as i32;
                        }
                        RouteAttribute::Table(table) => {
                            table_id = *table;
                        }
                        RouteAttribute::PrefSource(src) => {
                            pref_src = route_address_to_ip(src);
                        }
                        _ => {}
                    }
                }

                let dest_addr = destination.unwrap_or(match family {
                    AddressFamily::Inet => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    _ => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                });

                let mut flags = 0x0001; // RTF_UP
                if gateway.is_some() {
                    flags |= 0x0002; // RTF_GATEWAY
                }

                routes.push(RouteEntry {
                    destination: dest_addr,
                    prefix_len: route.header.destination_prefix_length,
                    gateway,
                    netmask: prefix_to_mask(family, route.header.destination_prefix_length),
                    interface,
                    flags,
                    metric,
                    table_id,
                    protocol: Some(format!("{:?}", route.header.protocol)),
                    scope: Some(format!("{:?}", route.header.scope)),
                    pref_src,
                });
            }
        }

        Ok(routes)
    }

    /// Traditional procfs fallback (only main table)
    pub fn get_routes_procfs() -> Result<Vec<RouteEntry>> {
        let mut routes = Vec::new();

        // IPv4 Routes
        if let Ok(content) = fs::read_to_string("/proc/net/route") {
            for (i, line) in content.lines().enumerate() {
                if i == 0 {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 11 {
                    continue;
                }

                let iface = parts[0].to_string();
                let dest_hex = parts[1];
                let gw_hex = parts[2];
                let flags = u32::from_str_radix(parts[3], 16).unwrap_or(0);
                let metric = parts[6].parse::<i32>().unwrap_or(0);
                let mask_hex = parts[7];

                if let (Ok(dest), Ok(gw), Ok(mask)) = (
                    parse_hex_v4(dest_hex),
                    parse_hex_v4(gw_hex),
                    parse_hex_v4(mask_hex),
                ) {
                    routes.push(RouteEntry {
                        destination: IpAddr::V4(dest),
                        prefix_len: mask_to_prefix(mask),
                        gateway: if gw.is_unspecified() {
                            None
                        } else {
                            Some(IpAddr::V4(gw))
                        },
                        netmask: IpAddr::V4(mask),
                        interface: iface,
                        flags,
                        metric,
                        table_id: 254, // Default to main table for /proc/net/route
                        protocol: None,
                        scope: None,
                        pref_src: None,
                    });
                }
            }
        }

        // IPv6 Routes
        if let Ok(content) = fs::read_to_string("/proc/net/ipv6_route") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 10 {
                    continue;
                }

                let dest_hex = parts[0];
                let dest_prefix = u8::from_str_radix(parts[1], 16).unwrap_or(0);
                let nexthop_hex = parts[4];
                let metric = i32::from_str_radix(parts[5], 16).unwrap_or(0);
                let flags = u32::from_str_radix(parts[8], 16).unwrap_or(0);
                let iface = parts[9].to_string();

                if let (Ok(dest), Ok(nexthop)) = (parse_hex_v6(dest_hex), parse_hex_v6(nexthop_hex))
                {
                    routes.push(RouteEntry {
                        destination: IpAddr::V6(dest),
                        prefix_len: dest_prefix,
                        gateway: if nexthop.is_unspecified() {
                            None
                        } else {
                            Some(IpAddr::V6(nexthop))
                        },
                        netmask: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                        interface: iface,
                        flags,
                        metric,
                        table_id: 254, // Default to main table for /proc/net/route
                        protocol: None,
                        scope: None,
                        pref_src: None,
                    });
                }
            }
        }

        Ok(routes)
    }
}

fn route_address_to_ip(addr: &RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
        RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
        _ => None,
    }
}

fn prefix_to_mask(family: AddressFamily, prefix: u8) -> IpAddr {
    match family {
        AddressFamily::Inet => {
            let mask = if prefix >= 32 {
                u32::MAX
            } else if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(mask))
        }
        _ => {
            // Simplistic IPv6 mask
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        }
    }
}

fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    let octets = mask.octets();
    let mut prefix = 0;
    for &octet in &octets {
        prefix += octet.count_ones() as u8;
    }
    prefix
}

fn parse_hex_v4(hex: &str) -> Result<Ipv4Addr> {
    let val = u32::from_str_radix(hex, 16).context("Failed to parse IPv4 hex")?;
    // /proc/net/route uses little-endian hex for IPv4
    Ok(Ipv4Addr::from(val.swap_bytes()))
}

fn parse_hex_v6(hex: &str) -> Result<Ipv6Addr> {
    if hex.len() != 32 {
        return Err(anyhow::anyhow!("Invalid IPv6 hex length: {}", hex.len()));
    }

    let mut segments = [0u16; 8];
    for i in 0..8 {
        segments[i] = u16::from_str_radix(&hex[i * 4..i * 4 + 4], 16)
            .context("Failed to parse IPv6 segment hex")?;
    }

    Ok(Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    ))
}
