//! ICMP (Internet Control Message Protocol) parsing
//! Handles both ICMPv4 and ICMPv6

use crate::network::parser::ParsedPacket;
use crate::network::protocol::TransportParams;
use crate::network::types::{NdpInfo, NdpOperation, Protocol, ProtocolState};
use std::net::SocketAddr;

/// Parse an ICMP (IPv4) packet
pub fn parse(
    transport_data: &[u8],
    params: TransportParams,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> Option<ParsedPacket> {
    if transport_data.is_empty() {
        return None;
    }

    let icmp_type = transport_data[0];

    // Extract ICMP echo ID for request (8) and reply (0)
    let icmp_id = if transport_data.len() >= 6 && (icmp_type == 8 || icmp_type == 0) {
        Some(u16::from_be_bytes([transport_data[4], transport_data[5]]))
    } else {
        None
    };

    // Determine direction based on local IPs
    let is_outgoing = local_ips.contains(&params.src_ip);

    let (local_addr, remote_addr) = if is_outgoing {
        (
            SocketAddr::new(params.src_ip, 0),
            SocketAddr::new(params.dst_ip, 0),
        )
    } else {
        (
            SocketAddr::new(params.dst_ip, 0),
            SocketAddr::new(params.src_ip, 0),
        )
    };

    let (local_mac, remote_mac) = if is_outgoing {
        (params.src_mac.clone(), params.dst_mac.clone())
    } else {
        (params.dst_mac.clone(), params.src_mac.clone())
    };

    Some(ParsedPacket {
        connection_key: format!("ICMP:{}-ICMP:{}", local_addr, remote_addr),
        protocol: Protocol::Icmp,
        local_addr,
        remote_addr,
        local_mac,
        remote_mac,
        tcp_header: None,
        protocol_state: ProtocolState::Icmp { icmp_type, icmp_id },
        is_outgoing,
        packet_len: params.packet_len,
        dpi_result: None,
        process_name: params.process_name,
        process_id: params.process_id,
    })
}

/// Parse an ICMPv6 packet
pub fn parse_v6(
    transport_data: &[u8],
    params: TransportParams,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> Option<ParsedPacket> {
    if transport_data.is_empty() {
        return None;
    }

    let icmp_type = transport_data[0];

    // Extract ICMPv6 echo ID for request (128) and reply (129)
    let icmp_id = if transport_data.len() >= 6 && (icmp_type == 128 || icmp_type == 129) {
        Some(u16::from_be_bytes([transport_data[4], transport_data[5]]))
    } else {
        None
    };

    // Determine direction based on local IPs
    let is_outgoing = local_ips.contains(&params.src_ip);

    let (local_addr, remote_addr) = if is_outgoing {
        (
            SocketAddr::new(params.src_ip, 0),
            SocketAddr::new(params.dst_ip, 0),
        )
    } else {
        (
            SocketAddr::new(params.dst_ip, 0),
            SocketAddr::new(params.src_ip, 0),
        )
    };

    let (local_mac, remote_mac) = if is_outgoing {
        (params.src_mac.clone(), params.dst_mac.clone())
    } else {
        (params.dst_mac.clone(), params.src_mac.clone())
    };

    let mut protocol_state = ProtocolState::Icmp { icmp_type, icmp_id };

    // Handle NDP (Neighbor Discovery Protocol) types
    if (133..=137).contains(&icmp_type)
        && let Some(ndp) = parse_ndp(transport_data, &params)
    {
        protocol_state = ProtocolState::Ndp(ndp);
    }

    Some(ParsedPacket {
        connection_key: format!("ICMP:{}-ICMP:{}", local_addr, remote_addr),
        protocol: Protocol::Icmp,
        local_addr,
        remote_addr,
        local_mac,
        remote_mac,
        tcp_header: None,
        protocol_state,
        is_outgoing,
        packet_len: params.packet_len,
        dpi_result: None, // No DPI for ICMPv6
        process_name: params.process_name,
        process_id: params.process_id,
    })
}

fn parse_ndp(data: &[u8], params: &TransportParams) -> Option<NdpInfo> {
    let icmp_type = data[0];

    let operation = match icmp_type {
        133 => NdpOperation::RouterSolicitation,
        134 => NdpOperation::RouterAdvertisement,
        135 => NdpOperation::NeighborSolicitation,
        136 => NdpOperation::NeighborAdvertisement,
        137 => NdpOperation::Redirect,
        _ => return None,
    };

    let mut source_mac = params.src_mac.clone();
    let mut target_mac = params.dst_mac.clone();
    let mut target_ip = params.dst_ip;

    // For NS (135) and NA (136), we can extract Target Address and Options
    if (icmp_type == 135 || icmp_type == 136) && data.len() >= 24 {
        let mut target_addr_bytes = [0u8; 16];
        target_addr_bytes.copy_from_slice(&data[8..24]);
        target_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(target_addr_bytes));

        // Parse Options (starting at offset 24)
        let mut offset = 24;
        while data.len() >= offset + 2 {
            let opt_type = data[offset];
            let opt_len = (data[offset + 1] as usize) * 8;
            if opt_len == 0 || offset + opt_len > data.len() {
                break;
            }

            match opt_type {
                1
                    // Source Link-layer Address
                    if opt_len >= 8 => {
                        source_mac = Some(format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            data[offset + 2],
                            data[offset + 3],
                            data[offset + 4],
                            data[offset + 5],
                            data[offset + 6],
                            data[offset + 7]
                        ));
                    }
                2
                    // Target Link-layer Address
                    if opt_len >= 8 => {
                        target_mac = Some(format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            data[offset + 2],
                            data[offset + 3],
                            data[offset + 4],
                            data[offset + 5],
                            data[offset + 6],
                            data[offset + 7]
                        ));
                    }
                _ => {}
            }
            offset += opt_len;
        }
    }

    Some(NdpInfo {
        operation,
        source_mac,
        source_ip: params.src_ip,
        target_mac,
        target_ip,
        target_name: None,
    })
}
