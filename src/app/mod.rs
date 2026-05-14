use anyhow::Result;
use dashmap::DashMap;
use log::{info, warn};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

pub mod config;
pub mod logging;
pub mod sandbox;
pub mod state;
pub mod threads;
pub mod types;

use crate::app::logging::log_pcap_connection;
use crate::app::state::QUIC_CONNECTION_MAPPING;
use crate::network::dns::DnsResolver;
use crate::network::geoip::{GeoIpConfig, GeoIpResolver};
use crate::network::interface_stats::{InterfaceRates, InterfaceStats};
use crate::network::oui::OuiLookup;
use crate::network::services::ServiceLookup;
use crate::network::types::{
    ApplicationProtocol, Connection, Device, DnsQueryType, Listener, RttTracker, TrafficHistory,
};
pub use config::Config;
pub use types::{AppStats, ProcessDetectionStatus, SandboxInfo};

/// Main application state
pub struct App {
    /// Configuration
    pub(crate) config: Config,

    /// Control flag for graceful shutdown
    pub(crate) should_stop: Arc<AtomicBool>,

    /// Active connections map (shared with background threads)
    pub(crate) connections: Arc<DashMap<String, Connection>>,

    /// Current connections snapshot for UI
    pub(crate) connections_snapshot: Arc<RwLock<Vec<Connection>>>,

    /// Historic (closed) connections for optional display
    pub(crate) historic_connections: Arc<DashMap<String, Connection>>,

    /// Whether to include historic connections in the snapshot
    pub(crate) show_historic: Arc<AtomicBool>,

    /// Service name lookup
    pub(crate) service_lookup: Arc<ServiceLookup>,

    /// OUI vendor lookup for MAC addresses
    pub(crate) oui_lookup: Option<Arc<OuiLookup>>,

    /// Application statistics
    pub(crate) stats: Arc<AppStats>,

    /// Loading state
    pub(crate) is_loading: Arc<AtomicBool>,

    /// Current network interface name
    pub(crate) current_interface: Arc<RwLock<Option<String>>>,

    /// Data link type for packet parsing (needed for PKTAP detection)
    pub(crate) linktype: Arc<RwLock<Option<i32>>>,

    /// Whether PKTAP is active (macOS only) - used to disable process enrichment
    pub(crate) pktap_active: Arc<AtomicBool>,

    /// Current process detection status (method and degradation info)
    pub(crate) process_detection_status: Arc<RwLock<ProcessDetectionStatus>>,

    /// Interface statistics (cumulative totals)
    pub(crate) interface_stats: Arc<DashMap<String, InterfaceStats>>,

    /// Interface rates (per-second rates)
    pub(crate) interface_rates: Arc<DashMap<String, InterfaceRates>>,

    /// Traffic history for graph visualization
    pub(crate) traffic_history: Arc<RwLock<TrafficHistory>>,

    /// RTT tracker for latency measurement
    pub(crate) rtt_tracker: Arc<Mutex<RttTracker>>,

    /// Active listening sockets on the system
    pub(crate) listeners: Arc<RwLock<Vec<Listener>>>,

    /// Discovered devices on local network
    pub(crate) devices: Arc<DashMap<String, Device>>,

    /// DNS resolver for reverse DNS lookups
    pub(crate) dns_resolver: Option<Arc<DnsResolver>>,

    /// GeoIP resolver for location/ASN lookups
    pub(crate) geoip_resolver: Option<Arc<GeoIpResolver>>,

    /// Sandbox status (Linux Landlock / macOS Seatbelt / Windows restricted token)
    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    pub(crate) sandbox_info: Arc<RwLock<SandboxInfo>>,
}

impl App {
    /// Create a new application instance
    pub fn new(config: Config) -> Result<Self> {
        // Load service definitions
        let service_lookup = ServiceLookup::from_embedded().unwrap_or_else(|e| {
            warn!("Failed to load embedded services: {}, using defaults", e);
            ServiceLookup::with_defaults()
        });

        // Load OUI vendor database
        let oui_lookup = match OuiLookup::from_embedded() {
            Ok(oui) => Some(Arc::new(oui)),
            Err(e) => {
                warn!("Failed to load OUI vendor database: {}", e);
                None
            }
        };

        // Initialize DNS resolver if enabled
        let dns_resolver = if config.resolve_dns {
            info!("DNS resolution enabled - starting background resolver");
            Some(Arc::new(DnsResolver::with_defaults()))
        } else {
            None
        };

        // Initialize GeoIP resolver
        let geoip_resolver = if config.disable_geoip {
            info!("GeoIP resolution disabled by configuration");
            None
        } else if config.geoip_country_path.is_some()
            || config.geoip_asn_path.is_some()
            || config.geoip_city_path.is_some()
        {
            // Use explicit paths from config
            let geoip_config = GeoIpConfig {
                country_db_path: config
                    .geoip_country_path
                    .as_ref()
                    .map(std::path::PathBuf::from),
                asn_db_path: config.geoip_asn_path.as_ref().map(std::path::PathBuf::from),
                city_db_path: config
                    .geoip_city_path
                    .as_ref()
                    .map(std::path::PathBuf::from),
                ..Default::default()
            };
            let resolver = GeoIpResolver::new(geoip_config);
            if resolver.is_available() {
                let (has_country, has_asn, has_city) = resolver.get_status();
                info!(
                    "GeoIP resolution enabled - Country: {}, ASN: {}, City: {}",
                    has_country, has_asn, has_city
                );
                Some(Arc::new(resolver))
            } else {
                warn!("GeoIP databases not found at specified paths - location display disabled");
                None
            }
        } else {
            // Auto-discover databases
            let resolver = GeoIpResolver::with_auto_discovery();
            if resolver.is_available() {
                let (has_country, has_asn, has_city) = resolver.get_status();
                info!(
                    "GeoIP resolution enabled - Country: {}, ASN: {}, City: {}",
                    has_country, has_asn, has_city
                );
                Some(Arc::new(resolver))
            } else {
                info!("GeoIP databases not found - location display disabled");
                None
            }
        };

        Ok(Self {
            config,
            should_stop: Arc::new(AtomicBool::new(false)),
            connections: Arc::new(DashMap::new()),
            connections_snapshot: Arc::new(RwLock::new(Vec::new())),
            historic_connections: Arc::new(DashMap::new()),
            show_historic: Arc::new(AtomicBool::new(false)),
            service_lookup: Arc::new(service_lookup),
            oui_lookup,
            stats: Arc::new(AppStats::default()),
            is_loading: Arc::new(AtomicBool::new(true)),
            current_interface: Arc::new(RwLock::new(None)),
            linktype: Arc::new(RwLock::new(None)),
            pktap_active: Arc::new(AtomicBool::new(false)),
            process_detection_status: Arc::new(RwLock::new(ProcessDetectionStatus::with_method(
                "initializing...",
            ))),
            interface_stats: Arc::new(DashMap::new()),
            interface_rates: Arc::new(DashMap::new()),
            traffic_history: Arc::new(RwLock::new(TrafficHistory::new(60))), // 60 seconds of history
            rtt_tracker: Arc::new(Mutex::new(RttTracker::new())),
            listeners: Arc::new(RwLock::new(Vec::new())),
            devices: Arc::new(DashMap::new()),
            dns_resolver,
            geoip_resolver,
            #[cfg(any(
                target_os = "linux",
                target_os = "windows",
                all(target_os = "macos", feature = "macos-sandbox")
            ))]
            sandbox_info: Arc::new(RwLock::new(SandboxInfo::default())),
        })
    }

    /// Get current connections for UI display
    pub fn get_connections(&self) -> Vec<Connection> {
        self.get_filtered_connections("")
    }

    /// Get filtered connections for UI display
    pub fn get_filtered_connections(&self, filter_query: &str) -> Vec<Connection> {
        let connections = self.connections_snapshot.read().unwrap().clone();

        // Filter out DNS PTR queries/responses when reverse DNS is enabled
        let hide_ptr_lookups = self.dns_resolver.is_some() && !self.config.show_ptr_lookups;

        let connections: Vec<Connection> = if hide_ptr_lookups {
            connections
                .into_iter()
                .filter(|conn| {
                    // Hide DNS PTR queries/responses (used for reverse DNS lookups)
                    if let Some(ref dpi) = conn.dpi_info
                        && let ApplicationProtocol::Dns(ref dns_info) = dpi.application
                        && dns_info.query_type == Some(DnsQueryType::PTR)
                    {
                        return false;
                    }
                    true
                })
                .collect()
        } else {
            connections
        };

        if filter_query.trim().is_empty() {
            return connections;
        }

        let filter = crate::filter::ConnectionFilter::parse(filter_query);
        connections
            .into_iter()
            .filter(|conn| filter.matches(conn))
            .collect()
    }

    /// Get interface statistics
    pub fn get_interface_stats(&self) -> Vec<InterfaceStats> {
        self.interface_stats
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get interface rates (bytes/sec)
    pub fn get_interface_rates(&self) -> HashMap<String, InterfaceRates> {
        self.interface_rates
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Get traffic history for graph visualization
    pub fn get_traffic_history(&self) -> TrafficHistory {
        self.traffic_history
            .read()
            .map(|h| h.clone())
            .unwrap_or_default()
    }

    /// Get application statistics
    pub fn get_stats(&self) -> AppStats {
        AppStats {
            packets_processed: AtomicU64::new(self.stats.packets_processed.load(Ordering::Relaxed)),
            packets_dropped: AtomicU64::new(self.stats.packets_dropped.load(Ordering::Relaxed)),
            connections_tracked: AtomicU64::new(
                self.stats.connections_tracked.load(Ordering::Relaxed),
            ),
            last_update: RwLock::new(*self.stats.last_update.read().unwrap()),
            total_tcp_retransmits: AtomicU64::new(
                self.stats.total_tcp_retransmits.load(Ordering::Relaxed),
            ),
            total_tcp_out_of_order: AtomicU64::new(
                self.stats.total_tcp_out_of_order.load(Ordering::Relaxed),
            ),
            total_tcp_fast_retransmits: AtomicU64::new(
                self.stats
                    .total_tcp_fast_retransmits
                    .load(Ordering::Relaxed),
            ),
        }
    }

    /// Get a snapshot of active listening sockets
    pub fn get_listeners(&self) -> Vec<Listener> {
        self.listeners
            .read()
            .expect("listeners lock poisoned")
            .clone()
    }

    /// Get a snapshot of discovered devices on the local network
    pub fn get_devices(&self) -> Vec<Device> {
        self.devices.iter().map(|d| d.value().clone()).collect()
    }

    /// Check if the application is still in its initial loading state
    pub fn is_loading(&self) -> bool {
        self.is_loading.load(Ordering::Relaxed)
    }

    /// Get the current network interface name
    pub fn get_current_interface(&self) -> Option<String> {
        self.current_interface.read().unwrap().clone()
    }

    /// Get the current process detection status (method and degradation info)
    pub fn get_process_detection_status(&self) -> ProcessDetectionStatus {
        self.process_detection_status
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Get sandbox status information
    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    pub fn get_sandbox_info(&self) -> SandboxInfo {
        self.sandbox_info
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Set sandbox status information
    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    pub fn set_sandbox_info(&self, info: SandboxInfo) {
        if let Ok(mut guard) = self.sandbox_info.write() {
            *guard = info;
        }
    }

    /// Get link layer information for the current interface
    /// Returns (link_layer_type_name, is_tunnel)
    pub fn get_link_layer_info(&self) -> (String, bool) {
        use crate::network::link_layer::LinkLayerType;

        if let Ok(linktype_opt) = self.linktype.read()
            && let Some(dlt) = *linktype_opt
        {
            // Get interface name to detect TUN/TAP more accurately
            let interface_name = self
                .current_interface
                .read()
                .ok()
                .and_then(|opt| opt.clone())
                .unwrap_or_default();

            let link_type = LinkLayerType::from_dlt_and_name(dlt, &interface_name);
            let type_name = format!("{:?}", link_type);
            let is_tunnel = link_type.is_tunnel();
            return (type_name, is_tunnel);
        }
        (String::from("Unknown"), false)
    }

    /// Get the DNS resolver if enabled
    pub fn get_dns_resolver(&self) -> Option<Arc<DnsResolver>> {
        self.dns_resolver.clone()
    }

    /// Check if DNS resolution is enabled
    pub fn is_dns_resolution_enabled(&self) -> bool {
        self.dns_resolver.is_some()
    }

    /// Get GeoIP database availability status.
    /// Returns (has_location, has_asn, has_city) where has_location is true when
    /// either the country or city database is loaded.
    pub fn get_geoip_status(&self) -> (bool, bool, bool) {
        match &self.geoip_resolver {
            Some(resolver) => resolver.get_status(),
            None => (false, false, false),
        }
    }

    /// Toggle the show_historic flag
    pub fn toggle_show_historic(&self) {
        let prev = self.show_historic.load(Ordering::Relaxed);
        self.show_historic.store(!prev, Ordering::Relaxed);
    }

    /// Set the show_historic flag directly
    pub fn set_show_historic(&self, value: bool) {
        self.show_historic.store(value, Ordering::Relaxed);
    }

    /// Clear all connections and related data, starting fresh
    /// This clears:
    /// - All tracked connections
    /// - Traffic history (graph data)
    /// - RTT measurements
    /// - QUIC connection mappings
    /// - Resets statistics counters
    pub fn clear_all_connections(&self) {
        info!("Clearing all connections and resetting statistics");

        // Clear the main connections map
        self.connections.clear();

        // Clear historic connections and reset toggle
        self.historic_connections.clear();
        self.show_historic.store(false, Ordering::Relaxed);

        // Clear the UI snapshot
        if let Ok(mut snapshot) = self.connections_snapshot.write() {
            snapshot.clear();
        }

        // Clear traffic history
        if let Ok(mut history) = self.traffic_history.write() {
            history.clear();
        }

        // Clear RTT tracker
        if let Ok(mut tracker) = self.rtt_tracker.lock() {
            tracker.clear();
        }

        // Clear QUIC connection ID mappings
        if let Ok(mut mapping) = QUIC_CONNECTION_MAPPING.lock() {
            mapping.clear();
        }

        // Reset statistics counters
        self.stats.packets_processed.store(0, Ordering::Relaxed);
        self.stats.packets_dropped.store(0, Ordering::Relaxed);
        self.stats.connections_tracked.store(0, Ordering::Relaxed);
        self.stats.total_tcp_retransmits.store(0, Ordering::Relaxed);
        self.stats
            .total_tcp_out_of_order
            .store(0, Ordering::Relaxed);
        self.stats
            .total_tcp_fast_retransmits
            .store(0, Ordering::Relaxed);

        info!("All connections cleared successfully");
    }

    /// Stop all threads gracefully
    pub fn stop(&self) {
        info!("Stopping application");
        self.should_stop.store(true, Ordering::Relaxed);

        // Write remaining active connections to PCAP sidecar JSONL file
        // (connections that haven't been cleaned up yet)
        if let Some(ref pcap_path) = self.config.pcap_export_file
            && let Ok(connections) = self.connections_snapshot.read()
        {
            let count = connections.len();
            let with_pids = connections.iter().filter(|c| c.pid.is_some()).count();

            for conn in connections.iter() {
                log_pcap_connection(pcap_path, conn);
            }

            info!(
                "Wrote {} remaining connections ({} with PIDs) to JSONL",
                count, with_pids
            );
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.stop();
        // Give threads time to stop gracefully
        thread::sleep(Duration::from_millis(100));
    }
}
