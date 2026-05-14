use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::Write;
use crate::network::dns::DnsResolver;
use crate::network::types::{Connection, ApplicationProtocol, Protocol};

/// Open or create a file for appending with restrictive permissions (0o600 on Unix).
///
/// Ensures log files containing connection metadata are not world-readable.
pub fn open_log_file(path: &str) -> std::io::Result<File> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    Ok(file)
}

/// Helper function to log connection events as JSON
pub fn log_connection_event(
    json_log_path: &str,
    event_type: &str,
    conn: &Connection,
    duration_secs: Option<u64>,
    dns_resolver: Option<&DnsResolver>,
) {
    // Build JSON object based on event type
    let mut event = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "event": event_type,
        "protocol": conn.protocol.to_string(),
        "source_ip": conn.local_addr.ip().to_string(),
        "source_port": conn.local_addr.port(),
        "destination_ip": conn.remote_addr.ip().to_string(),
        "destination_port": conn.remote_addr.port(),
    });

    // Add hostname fields if DNS resolution is enabled and hostnames are resolved
    // Skip ARP connections to avoid feedback loop (DNS lookups generate ARP traffic)
    if let Some(resolver) = dns_resolver.filter(|_| conn.protocol != Protocol::Arp) {
        if let Some(hostname) = resolver.get_hostname(&conn.remote_addr.ip()) {
            event["destination_hostname"] = json!(hostname);
        }
        if let Some(hostname) = resolver.get_hostname(&conn.local_addr.ip()) {
            event["source_hostname"] = json!(hostname);
        }
    }

    // Add process information if available
    if let Some(pid) = conn.pid {
        event["pid"] = json!(pid);
    }
    if let Some(process_name) = &conn.process_name {
        event["process_name"] = json!(process_name);
    }

    // Add service name if available
    if let Some(service_name) = &conn.service_name {
        event["service_name"] = json!(service_name);
    }

    // Add connection direction (only for TCP when we observed the handshake)
    if let Some(is_outgoing) = conn.connection_direction {
        event["direction"] = json!(if is_outgoing { "outgoing" } else { "incoming" });
    }

    // Add DPI information if available
    if let Some(dpi) = &conn.dpi_info {
        event["dpi_protocol"] = json!(dpi.application.to_string());

        // Extract domain/hostname from DPI info
        match &dpi.application {
            ApplicationProtocol::Dns(info) => {
                if let Some(domain) = &info.query_name {
                    event["dpi_domain"] = json!(domain);
                }
            }
            ApplicationProtocol::Http(info) => {
                if let Some(host) = &info.host {
                    event["dpi_domain"] = json!(host);
                }
            }
            ApplicationProtocol::Https(info) => {
                if let Some(tls_info) = &info.tls_info
                    && let Some(sni) = &tls_info.sni
                {
                    event["dpi_domain"] = json!(sni);
                }
            }
            ApplicationProtocol::Quic(info) => {
                if let Some(tls_info) = &info.tls_info
                    && let Some(sni) = &tls_info.sni
                {
                    event["dpi_domain"] = json!(sni);
                }
            }
            _ => {}
        }
    }

    // Add GeoIP information if available
    if let Some(ref geoip) = conn.geoip_info {
        if let Some(ref cc) = geoip.country_code {
            event["geoip_country_code"] = json!(cc);
        }
        if let Some(ref name) = geoip.country_name {
            event["geoip_country_name"] = json!(name);
        }
        if let Some(asn) = geoip.asn {
            event["geoip_asn"] = json!(asn);
        }
        if let Some(ref org) = geoip.as_org {
            event["geoip_as_org"] = json!(org);
        }
        if let Some(ref city) = geoip.city {
            event["geoip_city"] = json!(city);
        }
        if let Some(ref postal) = geoip.postal_code {
            event["geoip_postal_code"] = json!(postal);
        }
    }

    // Add connection statistics for closed events
    if event_type == "connection_closed" {
        event["bytes_sent"] = json!(conn.bytes_sent);
        event["bytes_received"] = json!(conn.bytes_received);
        if let Some(duration) = duration_secs {
            event["duration_secs"] = json!(duration);
        }
    }

    // Write to file (restrictive permissions: 0o600 on Unix)
    if let Ok(mut file) = open_log_file(json_log_path)
        && let Ok(json_str) = serde_json::to_string(&event)
    {
        let _ = writeln!(file, "{}", json_str);
    }
}

/// Helper function to log connection info to PCAP sidecar file (JSONL format)
pub fn log_pcap_connection(pcap_path: &str, conn: &Connection) {
    let json_path = format!("{}.connections.jsonl", pcap_path);

    // Build base event without GeoIP fields
    let mut event = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "protocol": conn.protocol.to_string(),
        "local_addr": conn.local_addr.to_string(),
        "remote_addr": conn.remote_addr.to_string(),
        "pid": conn.pid,
        "process_name": conn.process_name,
        "first_seen": conn.created_at,
        "last_seen": conn.last_activity,
        "bytes_sent": conn.bytes_sent,
        "bytes_received": conn.bytes_received,
        "state": conn.state(),
    });

    // Only add GeoIP fields when they have actual values
    if let Some(ref geoip) = conn.geoip_info {
        if let Some(ref cc) = geoip.country_code {
            event["geoip_country_code"] = json!(cc);
        }
        if let Some(ref name) = geoip.country_name {
            event["geoip_country_name"] = json!(name);
        }
        if let Some(asn) = geoip.asn {
            event["geoip_asn"] = json!(asn);
        }
        if let Some(ref org) = geoip.as_org {
            event["geoip_as_org"] = json!(org);
        }
        if let Some(ref postal) = geoip.postal_code {
            event["geoip_postal_code"] = json!(postal);
        }
        if let Some(ref city) = geoip.city {
            event["geoip_city"] = json!(city);
        }
    }

    if let Ok(mut file) = open_log_file(&json_path)
        && let Ok(json_str) = serde_json::to_string(&event)
    {
        let _ = writeln!(file, "{}", json_str);
    }
}
