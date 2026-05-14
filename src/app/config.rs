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

impl Config {
    /// Create configuration from CLI argument matches
    pub fn from_matches(matches: &clap::ArgMatches) -> Self {
        let mut config = Self::default();

        if let Some(interface) = matches.get_one::<String>("interface") {
            config.interface = Some(interface.to_string());
        }

        if matches.get_flag("no-localhost") {
            config.filter_localhost = true;
        }

        if matches.get_flag("show-localhost") {
            config.filter_localhost = false;
        }

        if let Some(interval) = matches.get_one::<u64>("refresh-interval") {
            config.refresh_interval = *interval;
        }

        if matches.get_flag("no-dpi") {
            config.enable_dpi = false;
        }

        if let Some(json_log_path) = matches.get_one::<String>("json-log") {
            config.json_log_file = Some(json_log_path.to_string());
        }

        if let Some(pcap_path) = matches.get_one::<String>("pcap-export") {
            config.pcap_export_file = Some(pcap_path.to_string());
        }

        if let Some(bpf_filter) = matches.get_one::<String>("bpf-filter") {
            let filter = bpf_filter.trim();
            if !filter.is_empty() {
                config.bpf_filter = Some(filter.to_string());
            }
        }

        if matches.get_flag("no-resolve-dns") {
            config.resolve_dns = false;
        }

        if matches.get_flag("show-ptr-lookups") {
            config.show_ptr_lookups = true;
        }

        if matches.get_flag("no-geoip") {
            config.disable_geoip = true;
        }

        if let Some(country_path) = matches.get_one::<String>("geoip-country") {
            config.geoip_country_path = Some(country_path.to_string());
        }

        if let Some(asn_path) = matches.get_one::<String>("geoip-asn") {
            config.geoip_asn_path = Some(asn_path.to_string());
        }

        if let Some(city_path) = matches.get_one::<String>("geoip-city") {
            config.geoip_city_path = Some(city_path.to_string());
        }

        config
    }
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
