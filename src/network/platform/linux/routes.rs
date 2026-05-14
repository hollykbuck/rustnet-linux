// network/platform/linux/routes.rs - Linux /proc/net/route parser

use crate::network::types::RouteEntry;
use anyhow::{Context, Result};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct LinuxRouteProvider;

impl LinuxRouteProvider {
    pub fn get_routes() -> Result<Vec<RouteEntry>> {
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
                        gateway: if gw.is_unspecified() {
                            None
                        } else {
                            Some(IpAddr::V4(gw))
                        },
                        netmask: IpAddr::V4(mask),
                        interface: iface,
                        flags,
                        metric,
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
                let _dest_prefix = parts[1]; // We can use this to construct mask if needed
                let nexthop_hex = parts[4];
                let metric = i32::from_str_radix(parts[5], 16).unwrap_or(0);
                let flags = u32::from_str_radix(parts[8], 16).unwrap_or(0);
                let iface = parts[9].to_string();

                if let (Ok(dest), Ok(nexthop)) = (parse_hex_v6(dest_hex), parse_hex_v6(nexthop_hex))
                {
                    // Skip some internal/loopback routes that are very noisy if desired,
                    // but for now let's show everything like `ip -6 route`.
                    routes.push(RouteEntry {
                        destination: IpAddr::V6(dest),
                        gateway: if nexthop.is_unspecified() {
                            None
                        } else {
                            Some(IpAddr::V6(nexthop))
                        },
                        // Simplified netmask for IPv6 (just destination for now)
                        netmask: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                        interface: iface,
                        flags,
                        metric,
                    });
                }
            }
        }

        Ok(routes)
    }
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
