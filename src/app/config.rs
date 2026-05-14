/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Network interface to capture from (None for default)
    pub interface: Option<String>,
    /// Filter localhost connections
    pub filter_localhost: bool,
    /// UI refresh interval in milliseconds
    pub refresh_interval: u64,
    /// Enable deep packet inspection
    pub enable_dpi: bool,
    /// BPF filter for packet capture
    pub bpf_filter: Option<String>,
    /// JSON log file path for connection events
    pub json_log_file: Option<String>,
    /// PCAP export file path for Wireshark analysis
    pub pcap_export_file: Option<String>,
    /// Enable reverse DNS resolution for IP addresses
    pub resolve_dns: bool,
    /// Show PTR lookup connections in UI (when DNS resolution is enabled)
    pub show_ptr_lookups: bool,
    /// Path to GeoLite2-Country.mmdb database (None for auto-discovery)
    pub geoip_country_path: Option<String>,
    /// Path to GeoLite2-ASN.mmdb database (None for auto-discovery)
    pub geoip_asn_path: Option<String>,
    /// Path to GeoLite2-City.mmdb database (None for auto-discovery)
    pub geoip_city_path: Option<String>,
    /// Disable GeoIP lookups entirely
    pub disable_geoip: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: None,
            filter_localhost: true,
            refresh_interval: 1000,
            enable_dpi: true,
            bpf_filter: None, // No filter by default to see all packets
            json_log_file: None,
            pcap_export_file: None,
            resolve_dns: true,
            show_ptr_lookups: false,
            geoip_country_path: None,
            geoip_asn_path: None,
            geoip_city_path: None,
            disable_geoip: false,
        }
    }
}
