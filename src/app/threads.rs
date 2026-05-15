use anyhow::Result;
use crossbeam::channel::{self, Receiver, Sender};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::app::ProcessDetectionStatus;
use crate::app::logging::{log_connection_event, log_pcap_connection};
use crate::app::state::{QUIC_CONNECTION_MAPPING, update_connection, update_device};
use crate::network::capture::{CaptureConfig, PacketReader, setup_packet_capture};
use crate::network::interface_stats::{InterfaceStats, InterfaceStatsProvider};
use crate::network::parser::{PacketParser, ParserConfig};
use crate::network::platform::create_process_lookup;
use crate::network::services::ServiceLookup;
use crate::network::types::{Connection, Listener};

// Platform-specific interface stats provider
#[cfg(target_os = "freebsd")]
use crate::network::platform::FreeBSDStatsProvider as PlatformStatsProvider;
#[cfg(target_os = "linux")]
use crate::network::platform::LinuxStatsProvider as PlatformStatsProvider;
#[cfg(target_os = "macos")]
use crate::network::platform::MacOSStatsProvider as PlatformStatsProvider;
#[cfg(target_os = "windows")]
use crate::network::platform::WindowsStatsProvider as PlatformStatsProvider;

/// Maximum queued packets before backpressure drops packets.
const MAX_PACKET_QUEUE: usize = 10_000;
/// Maximum historic (closed) connections retained for display.
const MAX_HISTORIC_CONNECTIONS: usize = 5_000;

impl crate::app::App {
    /// Start all background threads
    pub async fn start(&self) -> Result<std::sync::mpsc::Receiver<()>> {
        info!("Starting network monitor application - async start called");

        // Use stored connection map
        let connections = Arc::clone(&self.connections);

        // Start packet capture pipeline
        self.start_packet_capture_pipeline(connections.clone())?;
        info!("Packet capture pipeline started");

        // Create channel to signal when process detection (incl. eBPF) is ready
        let (process_ready_tx, process_ready_rx) = std::sync::mpsc::sync_channel(1);

        // Start process enrichment thread (but delay for PKTAP detection on macOS)
        self.start_process_enrichment_conditional(connections.clone(), process_ready_tx)?;
        info!("Process enrichment thread (conditional) started");

        // Start GeoIP enrichment thread
        self.start_geoip_enrichment_thread(connections.clone())?;
        info!("GeoIP enrichment task spawned");

        // Start async logging task
        if let Some(log_rx) = self.log_rx.lock().unwrap().take() {
            let should_stop = Arc::clone(&self.should_stop);
            thread::Builder::new()
                .name("logging".to_string())
                .spawn(move || {
                    crate::app::logging::run_logging_task(log_rx, should_stop);
                })
                .expect("Failed to spawn logging thread");
            info!("Async logging thread started");
        }

        // Start snapshot provider for UI
        self.start_snapshot_provider(connections.clone(), Arc::clone(&self.historic_connections))?;
        info!("Snapshot provider task spawned");

        // Start cleanup thread
        self.start_cleanup_thread(connections.clone(), Arc::clone(&self.historic_connections))?;
        info!("Cleanup task spawned");

        // Start rate refresh thread
        self.start_rate_refresh_thread(connections)?;
        info!("Rate refresh task spawned");

        // Start interface stats collection thread
        self.start_interface_stats_thread()?;
        info!("Interface stats task spawned");

        // Start route refresh thread
        self.start_route_refresh_thread()?;
        info!("Route refresh task spawned");

        // Start traffic history thread for graph visualization
        self.start_traffic_history_thread()?;
        info!("Traffic history task spawned");

        // Start device enrichment thread (reverse DNS, etc.)
        self.start_device_enrichment_thread()?;
        info!("Device enrichment task spawned");

        Ok(process_ready_rx)
    }

    /// Start packet capture and processing pipeline
    fn start_packet_capture_pipeline(
        &self,
        connections: Arc<DashMap<String, Connection>>,
    ) -> Result<()> {
        // Create packet channel — sender batches packets, receiver gets Vec<Vec<u8>> per batch
        let (packet_tx, packet_rx) = channel::bounded::<Vec<Vec<u8>>>(MAX_PACKET_QUEUE);

        // Start capture thread
        self.start_capture_thread(packet_tx)?;

        // Start multiple packet processing threads
        // On low-core systems, 1-2 threads are usually enough and reduce context switching.
        // For a 2C/4T system like i5-7200U, this will now spawn 2 threads instead of 4.
        let available = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let num_processors = if available <= 2 {
            1
        } else if available <= 4 {
            2
        } else {
            4
        };

        info!(
            "Spawning {} packet processing threads (available cores: {})",
            num_processors, available
        );

        for i in 0..num_processors {
            self.start_packet_processor(
                i,
                packet_rx.clone(),
                connections.clone(),
                self.log_tx.clone(),
            );
        }

        Ok(())
    }

    /// Start packet capture thread
    fn start_capture_thread(&self, packet_tx: Sender<Vec<Vec<u8>>>) -> Result<()> {
        // Validate interface exists before spawning thread (fail fast)
        crate::network::capture::validate_interface(&self.config.interface)?;

        let capture_config = CaptureConfig {
            interface: self.config.interface.clone(),
            filter: self.config.bpf_filter.clone(),
            ..Default::default()
        };

        let should_stop = Arc::clone(&self.should_stop);
        let stats = Arc::clone(&self.stats);
        let current_interface = Arc::clone(&self.current_interface);
        let linktype_storage = Arc::clone(&self.linktype);
        let _pktap_active = Arc::clone(&self.pktap_active);
        let pcap_export_file = self.config.pcap_export_file.clone();

        thread::Builder::new()
            .name("pcap_tx".to_string())
            .spawn(move || {
            match setup_packet_capture(capture_config) {
                Ok((capture, device_name, linktype)) => {
                    // Store the actual interface name and linktype being used
                    *current_interface.write().unwrap() = Some(device_name.clone());
                    *linktype_storage.write().unwrap() = Some(linktype);

                    // Drop CAP_NET_RAW now that the socket is open (Linux only)
                    #[cfg(all(target_os = "linux", feature = "landlock"))]
                    {
                        if let Err(e) =
                            crate::network::platform::sandbox::capabilities::drop_cap_net_raw()
                        {
                            warn!("Failed to drop CAP_NET_RAW in capture thread: {}", e);
                        } else {
                            debug!("Dropped CAP_NET_RAW in capture thread");
                        }
                    }

                    // Check if PKTAP is active (linktype 149 or 258)
                    #[cfg(target_os = "macos")]
                    {
                        use crate::network::link_layer::pktap;
                        if pktap::is_pktap_linktype(linktype) {
                            _pktap_active.store(true, Ordering::Relaxed);
                            info!("✓ PKTAP is active - process metadata will be provided directly");
                        }
                    }

                    info!(
                        "Packet capture started successfully on interface: {} (linktype: {})",
                        device_name, linktype
                    );

                    // Initialize PCAP export if configured (must be before PacketReader consumes capture)
                    let mut pcap_savefile = if let Some(ref pcap_path) = pcap_export_file {
                        match capture.savefile(pcap_path) {
                            Ok(savefile) => {
                                info!("PCAP export started: {}", pcap_path);
                                Some(savefile)
                            }
                            Err(e) => {
                                error!("Failed to create PCAP savefile: {}", e);
                                None
                            }
                        }
                    } else {
                        None
                    };

                    let mut reader = PacketReader::new(capture);
                    let mut packets_read = 0u64;
                    let mut last_log = Instant::now();
                    let mut last_stats_check = Instant::now();
                    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(100);
                    let mut batch_deadline = Instant::now() + Duration::from_millis(100);

                    loop {
                        if should_stop.load(Ordering::Relaxed) {
                            info!("Capture thread stopping");
                            break;
                        }

                        match reader.next_packet() {
                            Ok(Some(packet)) => {
                                packets_read += 1;

                                // Log first packet immediately
                                if packets_read == 1 {
                                    info!("First packet captured! Size: {} bytes", packet.len());
                                }

                                // Log every 10000 packets or every 5 seconds
                                if packets_read.is_multiple_of(10000)
                                    || last_log.elapsed() > Duration::from_secs(5)
                                {
                                    info!("Read {} packets so far", packets_read);
                                    last_log = Instant::now();
                                }

                                // Write to PCAP file if enabled
                                if let Some(ref mut savefile) = pcap_savefile {
                                    use std::time::{SystemTime, UNIX_EPOCH};
                                    let now = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default();
                                    #[cfg(unix)]
                                    let ts = libc::timeval {
                                        tv_sec: now.as_secs() as libc::time_t,
                                        tv_usec: now.subsec_micros() as libc::suseconds_t,
                                    };
                                    #[cfg(windows)]
                                    let ts = libc::timeval {
                                        tv_sec: now.as_secs() as libc::c_long,
                                        tv_usec: now.subsec_micros() as libc::c_long,
                                    };
                                    let header = pcap::PacketHeader {
                                        ts,
                                        caplen: packet.len() as u32,
                                        len: packet.len() as u32,
                                    };
                                    savefile.write(&pcap::Packet {
                                        header: &header,
                                        data: &packet,
                                    });
                                }

                                batch.push(packet);

                                // Send batch when full or deadline reached
                                if batch.len() >= 100 || Instant::now() >= batch_deadline {
                                    let to_send = std::mem::replace(&mut batch, Vec::with_capacity(100));
                                    let batch_size = to_send.len() as u64;
                                    debug!("try_send: sending batch of {} packets", batch_size);
                                    match packet_tx.try_send(to_send) {
                                        Ok(()) => {}
                                        Err(crossbeam::channel::TrySendError::Full(_)) => {
                                            stats.packets_dropped.fetch_add(batch_size, Ordering::Relaxed);
                                        }
                                        Err(crossbeam::channel::TrySendError::Disconnected(_)) => {
                                            warn!("Packet channel closed");
                                            break;
                                        }
                                    }
                                    batch_deadline = Instant::now() + Duration::from_millis(100);
                                }
                            }
                            Ok(None) => {
                                // Timeout - flush partial batch if deadline reached
                                if !batch.is_empty() && Instant::now() >= batch_deadline {
                                    let to_send = std::mem::replace(&mut batch, Vec::with_capacity(100));
                                    let batch_size = to_send.len() as u64;
                                    debug!("try_send: flushing partial batch of {} packets", batch_size);
                                    match packet_tx.try_send(to_send) {
                                        Ok(()) => {}
                                        Err(crossbeam::channel::TrySendError::Full(_)) => {
                                            stats.packets_dropped.fetch_add(batch_size, Ordering::Relaxed);
                                        }
                                        Err(crossbeam::channel::TrySendError::Disconnected(_)) => {
                                            warn!("Packet channel closed");
                                            break;
                                        }
                                    }
                                    batch_deadline = Instant::now() + Duration::from_millis(100);
                                }

                                // Check stats every second
                                if last_stats_check.elapsed() > Duration::from_secs(1) {
                                    if let Ok(capture_stats) = reader.stats() {
                                        if capture_stats.received > 0 {
                                            debug!(
                                                "Capture stats - Received: {}, Dropped: {}",
                                                capture_stats.received, capture_stats.dropped
                                            );
                                        }
                                        stats
                                            .packets_dropped
                                            .store(capture_stats.dropped as u64, Ordering::Relaxed);
                                    }
                                    last_stats_check = Instant::now();
                                }
                            }
                            Err(e) => {
                                error!("Capture error: {}", e);
                                break;
                            }
                        }
                    }

                    // Flush PCAP savefile before exiting
                    if let Some(ref mut savefile) = pcap_savefile {
                        if let Err(e) = savefile.flush() {
                            error!("Failed to flush PCAP savefile: {}", e);
                        } else {
                            info!("PCAP export completed");
                        }
                    }

                    info!(
                        "Capture thread exiting, total packets read: {}",
                        packets_read
                    );
                }
                Err(e) => {
                    let error_msg = format!("{}", e);

                    // Check if this is a privilege error
                    if error_msg.contains("Insufficient privileges") {
                        error!("Failed to start packet capture due to insufficient privileges:");
                        // The error message already contains detailed instructions
                        for line in error_msg.lines() {
                            error!("{}", line);
                        }
                    } else {
                        error!("Failed to start packet capture: {}", e);
                        error!(
                            "Make sure you have permission to capture packets (try running with sudo)"
                        );
                    }

                    warn!("Application will run in process-only mode");
                }
            }
        })
        .expect("Failed to spawn pcap_tx thread");

        Ok(())
    }

    /// Start a packet processor thread
    fn start_packet_processor(
        &self,
        id: usize,
        packet_rx: Receiver<Vec<Vec<u8>>>,
        connections: Arc<DashMap<String, Connection>>,
        log_tx: Sender<crate::app::logging::LogEvent>,
    ) {
        let should_stop = Arc::clone(&self.should_stop);
        let stats = Arc::clone(&self.stats);
        let linktype_storage = Arc::clone(&self.linktype);
        let json_log_path = self.config.json_log_file.clone();
        let rtt_tracker = Arc::clone(&self.rtt_tracker);
        let dns_resolver = self.dns_resolver.clone();
        let oui_lookup = self.oui_lookup.clone();
        let devices = Arc::clone(&self.devices);
        let parser_config = ParserConfig {
            enable_dpi: self.config.enable_dpi,
            ..Default::default()
        };

        thread::Builder::new()
            .name(format!("pcap_rx_{}", id))
            .spawn(move || {
                info!("Packet processor {} started", id);

                // Drop CAP_NET_RAW immediately as this thread doesn't need it (Linux only)
                #[cfg(all(target_os = "linux", feature = "landlock"))]
                {
                    if let Err(e) =
                        crate::network::platform::sandbox::capabilities::drop_cap_net_raw()
                    {
                        warn!(
                            "Failed to drop CAP_NET_RAW in processor thread {}: {}",
                            id, e
                        );
                    } else {
                        debug!("Dropped CAP_NET_RAW in processor thread {}", id);
                    }
                }

                // Wait for linktype to be available
                let parser = loop {
                    if let Some(linktype) = *linktype_storage.read().unwrap() {
                        let mut parser = PacketParser::with_config(parser_config.clone())
                            .with_linktype(linktype);
                        if let Some(ref oui) = oui_lookup {
                            parser = parser.with_oui_lookup((**oui).clone());
                        }
                        break parser;
                    }
                    thread::sleep(Duration::from_millis(10));
                };
                let mut total_processed = 0u64;
                let mut last_log = Instant::now();

                loop {
                    if should_stop.load(Ordering::Relaxed) {
                        info!("Packet processor {} stopping", id);
                        break;
                    }

                    // Block until sender delivers a full batch (no spin, no polling)
                    let batch = match packet_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(batch) => {
                            debug!("pcap_rx_{}: received batch of {} packets", id, batch.len());
                            batch
                        }
                        Err(crossbeam::channel::RecvTimeoutError::Timeout) => continue,
                        Err(crossbeam::channel::RecvTimeoutError::Disconnected) => {
                            info!("pcap_rx_{}: channel disconnected, exiting", id);
                            return;
                        }
                    };

                    // Process batch.
                    let mut parsed_count = 0;
                    for packet_data in &batch {
                        let parse_result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                parser.parse_packet(packet_data)
                            }));
                        match parse_result {
                            Ok(Some(parsed)) => {
                                // Update connection tracker
                                update_connection(
                                    &connections,
                                    parsed.clone(),
                                    &stats,
                                    &json_log_path,
                                    &rtt_tracker,
                                    dns_resolver.as_deref(),
                                    &log_tx,
                                );

                                // Update device discovery tracker
                                update_device(&devices, parsed, oui_lookup.clone());

                                parsed_count += 1;
                            }
                            Ok(None) => {}
                            Err(_) => {
                                warn!(
                                    "pcap_rx_{}: parser panicked on a packet ({} bytes); skipping",
                                    id,
                                    packet_data.len()
                                );
                            }
                        }
                    }

                    total_processed += batch.len() as u64;
                    stats
                        .packets_processed
                        .fetch_add(batch.len() as u64, Ordering::Relaxed);

                    // Log progress
                    if total_processed.is_multiple_of(10000)
                        || last_log.elapsed() > Duration::from_secs(5)
                    {
                        debug!(
                            "Processor {}: {} packets processed ({} parsed)",
                            id, total_processed, parsed_count
                        );
                        last_log = Instant::now();
                    }
                }

                info!(
                    "Packet processor {} exiting, total processed: {}",
                    id, total_processed
                );
            })
            .unwrap_or_else(|_| panic!("Failed to spawn pcap_rx_{} thread", id));
    }

    /// Start process enrichment thread conditionally based on PKTAP status
    fn start_process_enrichment_conditional(
        &self,
        connections: Arc<DashMap<String, Connection>>,
        process_ready_tx: std::sync::mpsc::SyncSender<()>,
    ) -> Result<()> {
        let pktap_active = Arc::clone(&self.pktap_active);
        let should_stop = Arc::clone(&self.should_stop);
        let process_detection_status = Arc::clone(&self.process_detection_status);
        let listeners = Arc::clone(&self.listeners);
        let service_lookup = Arc::clone(&self.service_lookup);

        thread::Builder::new()
            .name("process-enrichment".to_string())
            .spawn(move || {
            // On macOS, wait for PKTAP detection to avoid unnecessary lsof calls
            #[cfg(target_os = "macos")]
            {
                // Wait up to 5 seconds for PKTAP detection with shorter polling intervals
                let wait_start = Instant::now();
                while wait_start.elapsed() < Duration::from_secs(5)
                    && !should_stop.load(Ordering::Relaxed)
                {
                    if pktap_active.load(Ordering::Relaxed) {
                        info!(
                            "🚫 Skipping process enrichment thread - PKTAP is active and provides process metadata"
                        );
                        if let Ok(mut status) = process_detection_status.write() {
                            *status = ProcessDetectionStatus::with_method("pktap");
                        }
                        let _ = process_ready_tx.send(());
                        return;
                    }
                    // Check more frequently for faster detection
                    thread::sleep(Duration::from_millis(50));
                }

                // Final check after timeout
                if pktap_active.load(Ordering::Relaxed) {
                    info!(
                        "🚫 Skipping process enrichment thread - PKTAP became active during startup"
                    );
                    if let Ok(mut status) = process_detection_status.write() {
                        *status = ProcessDetectionStatus::with_method("pktap");
                    }
                    let _ = process_ready_tx.send(());
                    return;
                } else {
                    info!(
                        "⚠️  PKTAP not detected after 5 seconds, starting process enrichment thread with lsof"
                    );
                    info!(
                        "    This may cause process name formatting differences with PKTAP if it activates later"
                    );
                }
            }

            // Start the actual process enrichment
            if let Err(e) = Self::run_process_enrichment(
                connections,
                should_stop,
                pktap_active,
                process_detection_status,
                process_ready_tx,
                listeners,
                service_lookup,
            ) {
                error!("Process enrichment thread failed: {}", e);
            }
        })
        .expect("Failed to spawn process-enrichment thread");

        Ok(())
    }

    /// Run the actual process enrichment logic
    fn run_process_enrichment(
        connections: Arc<DashMap<String, Connection>>,
        should_stop: Arc<AtomicBool>,
        pktap_active: Arc<AtomicBool>,
        process_detection_status: Arc<RwLock<ProcessDetectionStatus>>,
        process_ready_tx: std::sync::mpsc::SyncSender<()>,
        listeners: Arc<RwLock<Vec<Listener>>>,
        service_lookup: Arc<ServiceLookup>,
    ) -> Result<()> {
        use crate::network::platform::DegradationReason;

        // Check PKTAP status before creating process lookup
        let use_pktap = pktap_active.load(Ordering::Relaxed);

        let process_lookup = create_process_lookup(use_pktap)?;

        // Signal that process detection (including eBPF) is complete.
        let _ = process_ready_tx.send(());
        let interval = Duration::from_secs(2); // Use default interval

        // Build and set the detection status from the process lookup implementation
        if let Ok(mut status) = process_detection_status.write()
            && status.method != "pktap"
        {
            let method = process_lookup.get_detection_method().to_string();
            let degradation = process_lookup.get_degradation_reason();

            *status = if degradation != DegradationReason::None {
                ProcessDetectionStatus::degraded(
                    method,
                    degradation.unavailable_feature().unwrap_or("enhanced"),
                    degradation.description(),
                )
            } else {
                ProcessDetectionStatus::with_method(method)
            };
        }

        info!(
            "Process enrichment thread started with detection method: {}",
            process_lookup.get_detection_method()
        );
        // Initialize to 10 seconds ago to trigger immediate refresh
        let mut last_refresh = Instant::now() - Duration::from_secs(10);

        loop {
            if should_stop.load(Ordering::Relaxed) {
                info!("Process enrichment thread stopping");
                break;
            }

            // Check if PKTAP became active
            #[cfg(target_os = "macos")]
            if pktap_active.load(Ordering::Relaxed) {
                info!(
                    "🚫 PKTAP became active, stopping process enrichment thread to prevent conflicts"
                );
                break;
            }

            // Refresh process lookup periodically
            if last_refresh.elapsed() > Duration::from_secs(5) {
                if let Err(e) = process_lookup.refresh() {
                    debug!("Process lookup refresh failed: {}", e);
                }

                // Update listeners
                match process_lookup.get_listeners() {
                    Ok(mut new_listeners) => {
                        // Enrich listeners with service names
                        for listener in &mut new_listeners {
                            listener.service_name = service_lookup
                                .lookup(listener.local_addr.port(), listener.protocol)
                                .map(|s| s.to_string());

                            // Count active connections for this listener
                            let count = connections
                                .iter()
                                .filter(|c| {
                                    if c.is_historic || c.protocol != listener.protocol {
                                        return false;
                                    }

                                    // Match port
                                    if c.local_addr.port() != listener.local_addr.port() {
                                        return false;
                                    }

                                    // Match IP
                                    if listener.local_addr.ip().is_unspecified() {
                                        true
                                    } else {
                                        c.local_addr.ip() == listener.local_addr.ip()
                                    }
                                })
                                .count();
                            listener.active_connections = count;
                        }

                        if let Ok(mut l) = listeners.write() {
                            *l = new_listeners;
                        }
                    }
                    Err(e) => debug!("Failed to get listeners: {}", e),
                }

                last_refresh = Instant::now();
            }

            // Enrich connections without process info
            let mut enriched = 0;
            for mut entry in connections.iter_mut() {
                if let Some((pid, name)) = process_lookup.get_process_for_connection(&entry) {
                    let mut did_enrich = false;

                    // Only set process name if it's missing
                    if entry.process_name.is_none() {
                        entry.process_name = Some(name.clone());
                        did_enrich = true;
                    }

                    // Only set PID if it's missing
                    if entry.pid.is_none() {
                        entry.pid = Some(pid);
                        did_enrich = true;
                    }

                    if did_enrich {
                        enriched += 1;
                    }
                }
            }

            if enriched > 0 {
                debug!("Enriched {} connections with process info", enriched);
            }

            thread::sleep(interval);
        }

        Ok(())
    }

    /// Start snapshot provider task for UI updates
    fn start_snapshot_provider(
        &self,
        connections: Arc<DashMap<String, Connection>>,
        historic_connections: Arc<DashMap<String, Connection>>,
    ) -> Result<()> {
        let snapshot = Arc::clone(&self.connections_snapshot);
        let should_stop = Arc::clone(&self.should_stop);
        let stats = Arc::clone(&self.stats);
        let service_lookup = Arc::clone(&self.service_lookup);
        let show_historic = Arc::clone(&self.show_historic);
        let filter_localhost = self.config.filter_localhost;
        let refresh_interval = Duration::from_millis(self.config.refresh_interval);

        let enrich_and_filter = move |conn: &mut Connection,
                                      service_lookup: &ServiceLookup,
                                      filter_localhost: bool|
              -> bool {
            // Enrich with service name
            if conn.service_name.is_none() {
                if let Some(service) = service_lookup.lookup(conn.remote_addr.port(), conn.protocol)
                {
                    conn.service_name = Some(service.to_string());
                } else if let Some(service) =
                    service_lookup.lookup(conn.local_addr.port(), conn.protocol)
                {
                    conn.service_name = Some(service.to_string());
                }
            }
            // Apply localhost filter
            if filter_localhost
                && conn.local_addr.ip().is_loopback()
                && conn.remote_addr.ip().is_loopback()
            {
                return false;
            }
            true
        };

        let is_loading = Arc::clone(&self.is_loading);
        tokio::spawn(async move {
            info!("Snapshot provider task started");
            let mut first_snapshot = true;

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("Snapshot provider task stopping");
                    break;
                }

                // Create snapshot
                let start = Instant::now();
                let total_connections = connections.len();

                let mut snapshot_data: Vec<Connection> = connections
                    .iter()
                    .filter_map(|entry| {
                        let mut conn = entry.value().clone();
                        if enrich_and_filter(&mut conn, &service_lookup, filter_localhost)
                            && conn.is_active()
                        {
                            Some(conn)
                        } else {
                            None
                        }
                    })
                    .collect();

                // Append historic connections when toggle is on
                if show_historic.load(Ordering::Relaxed) {
                    let historic: Vec<Connection> = historic_connections
                        .iter()
                        .filter_map(|entry| {
                            let mut conn = entry.value().clone();
                            if enrich_and_filter(&mut conn, &service_lookup, filter_localhost) {
                                Some(conn)
                            } else {
                                None
                            }
                        })
                        .collect();
                    snapshot_data.extend(historic);
                }

                // Sort by creation time
                snapshot_data.sort_by_key(|a| a.created_at);

                let filtered_count = snapshot_data.len();

                // Update snapshot
                if let Ok(mut guard) = snapshot.write() {
                    *guard = snapshot_data;
                }

                // If this is the first successful snapshot, signal that loading is complete
                if first_snapshot {
                    is_loading.store(false, Ordering::Relaxed);
                    info!("First UI snapshot generated, loading screen cleared");
                    first_snapshot = false;
                }

                // Update stats
                stats
                    .connections_tracked
                    .store(total_connections as u64, Ordering::Relaxed);
                *stats.last_update.write().unwrap() = Instant::now();

                debug!(
                    "Snapshot updated in {:?} - Total: {}, Filtered: {}",
                    start.elapsed(),
                    total_connections,
                    filtered_count
                );

                tokio::time::sleep(refresh_interval).await;
            }
        });

        Ok(())
    }

    /// Start rate refresh task to update rates for idle connections
    fn start_rate_refresh_thread(
        &self,
        connections: Arc<DashMap<String, Connection>>,
    ) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);

        tokio::spawn(async move {
            info!("Rate refresh task started");

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("Rate refresh task stopping");
                    break;
                }

                for mut entry in connections.iter_mut() {
                    let conn = entry.value_mut();
                    let idle_secs = conn.last_activity.elapsed().unwrap_or_default().as_secs();
                    if idle_secs <= 30 || conn.has_nonzero_rates() {
                        conn.update_rates();
                        conn.refresh_rates();
                    }
                }

                // Run every 1 second
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }

    /// Start interface statistics collection task
    fn start_interface_stats_thread(&self) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);
        let interface_stats = Arc::clone(&self.interface_stats);
        let interface_rates = Arc::clone(&self.interface_rates);

        tokio::spawn(async move {
            info!("Interface stats collection task started");

            let provider = PlatformStatsProvider;
            let mut previous_stats: HashMap<String, InterfaceStats> = HashMap::new();

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("Interface stats task stopping");
                    break;
                }

                // Collect stats from all interfaces
                match provider.get_all_stats() {
                    Ok(stats_vec) => {
                        interface_stats.clear();
                        interface_rates.clear();

                        for stat in stats_vec {
                            if let Some(prev) = previous_stats.get(&stat.interface_name) {
                                let rates = stat.calculate_rates(prev);
                                interface_rates.insert(stat.interface_name.clone(), rates);
                            }

                            let name = stat.interface_name.clone();
                            interface_stats.insert(name.clone(), stat.clone());
                            previous_stats.insert(name, stat);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to collect interface stats: {}", e);
                    }
                }

                // Refresh every 2 seconds
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        Ok(())
    }

    /// Start route refresh task
    fn start_route_refresh_thread(&self) -> Result<()> {
        let routes = Arc::clone(&self.routes);
        let should_stop = Arc::clone(&self.should_stop);

        tokio::spawn(async move {
            info!("Route refresh task started");
            while !should_stop.load(Ordering::Relaxed) {
                #[cfg(target_os = "linux")]
                {
                    use crate::network::platform::LinuxRouteProvider;
                    match LinuxRouteProvider::get_routes() {
                        Ok(new_routes) => {
                            if let Ok(mut guard) = routes.write() {
                                *guard = new_routes;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to refresh routes: {}", e);
                        }
                    }
                }

                // Refresh every 5 seconds
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            info!("Route refresh task stopped");
        });

        Ok(())
    }

    /// Start traffic history task for graph visualization
    fn start_traffic_history_thread(&self) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);
        let traffic_history = Arc::clone(&self.traffic_history);
        let interface_rates = Arc::clone(&self.interface_rates);
        let connections_snapshot = Arc::clone(&self.connections_snapshot);
        let stats = Arc::clone(&self.stats);
        let rtt_tracker = Arc::clone(&self.rtt_tracker);

        tokio::spawn(async move {
            info!("Traffic history task started");

            let mut prev_packets: u64 = 0;
            let mut prev_retransmits: u64 = 0;

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("Traffic history task stopping");
                    break;
                }

                let (total_rx, total_tx) =
                    interface_rates
                        .iter()
                        .fold((0u64, 0u64), |(rx, tx), entry| {
                            (
                                rx + entry.value().rx_bytes_per_sec,
                                tx + entry.value().tx_bytes_per_sec,
                            )
                        });

                let connection_count = connections_snapshot
                    .read()
                    .map(|snap| snap.iter().filter(|c| !c.is_historic).count())
                    .unwrap_or(0);

                let current_packets = stats.packets_processed.load(Ordering::Relaxed);
                let current_retransmits = stats.total_tcp_retransmits.load(Ordering::Relaxed);

                let packets_delta = current_packets.saturating_sub(prev_packets);
                let retransmits_delta = current_retransmits.saturating_sub(prev_retransmits);

                prev_packets = current_packets;
                prev_retransmits = current_retransmits;

                let avg_rtt_ms = rtt_tracker
                    .lock()
                    .ok()
                    .and_then(|mut tracker| tracker.take_average_rtt(1));

                if let Ok(mut history) = traffic_history.write() {
                    history.add_sample(
                        total_rx,
                        total_tx,
                        connection_count,
                        packets_delta,
                        retransmits_delta,
                        avg_rtt_ms,
                    );
                }

                // Update every 1 second
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }

    /// Start GeoIP enrichment task
    fn start_geoip_enrichment_thread(
        &self,
        connections: Arc<DashMap<String, Connection>>,
    ) -> Result<()> {
        let geoip_resolver = match &self.geoip_resolver {
            Some(resolver) => Arc::clone(resolver),
            None => return Ok(()),
        };

        let should_stop = Arc::clone(&self.should_stop);

        tokio::spawn(async move {
            info!("GeoIP enrichment task started");
            let interval = Duration::from_millis(500);

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("GeoIP enrichment task stopping");
                    break;
                }

                let mut enriched = 0;
                for mut entry in connections.iter_mut() {
                    if entry.geoip_info.is_none() {
                        let remote_ip = entry.remote_addr.ip();
                        let info = geoip_resolver.lookup(remote_ip);
                        if info.has_data() {
                            entry.geoip_info = Some(info);
                            enriched += 1;
                        }
                    }
                }

                if enriched > 0 {
                    debug!("Enriched {} connections with GeoIP info", enriched);
                }

                tokio::time::sleep(interval).await;
            }
        });

        Ok(())
    }

    /// Start device enrichment task to populate hostnames for discovered devices
    fn start_device_enrichment_thread(&self) -> Result<()> {
        let devices = Arc::clone(&self.devices);
        let dns_resolver = self.dns_resolver.clone();
        let should_stop = Arc::clone(&self.should_stop);

        tokio::spawn(async move {
            info!("Device enrichment task started");
            let interval = Duration::from_secs(5);

            while !should_stop.load(Ordering::Relaxed) {
                if let Some(resolver) = &dns_resolver {
                    let mut updated = 0;
                    for mut entry in devices.iter_mut() {
                        let device = entry.value_mut();

                        // Try to get hostname from DNS resolver if missing
                        if device.hostname.is_none() {
                            for ip in &device.ips {
                                if let Some(hostname) = resolver.get_hostname(ip) {
                                    device.hostname = Some(hostname);
                                    updated += 1;
                                    break;
                                }
                            }
                        }
                    }
                    if updated > 0 {
                        debug!("Enriched {} devices with hostnames", updated);
                    }
                }

                tokio::time::sleep(interval).await;
            }
        });

        Ok(())
    }

    /// Start cleanup task to remove old connections
    fn start_cleanup_thread(
        &self,
        connections: Arc<DashMap<String, Connection>>,
        historic_connections: Arc<DashMap<String, Connection>>,
    ) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);
        let json_log_path = self.config.json_log_file.clone();
        let pcap_export_path = self.config.pcap_export_file.clone();
        let dns_resolver = self.dns_resolver.clone();
        let log_tx = self.log_tx.clone();

        tokio::spawn(async move {
            info!("Cleanup task started");

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("Cleanup task stopping");
                    break;
                }

                let now = SystemTime::now();
                let mut removed = 0;
                let mut removed_keys = Vec::new();
                let mut to_archive: Vec<(String, Connection)> = Vec::new();

                connections.retain(|key, conn| {
                    let should_keep = !conn.should_cleanup(now);

                    if !should_keep {
                        removed += 1;
                        removed_keys.push(key.clone());

                        let mut historic = conn.clone();
                        historic.is_historic = true;
                        historic.closed_at = Some(now);
                        let historic_key = format!(
                            "{}:{}",
                            key,
                            conn.created_at
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_nanos()
                        );
                        to_archive.push((historic_key, historic));

                        let duration_secs = now
                            .duration_since(conn.created_at)
                            .map(|d| d.as_secs())
                            .ok();

                        if let Some(log_path) = &json_log_path {
                            let _ = log_tx.try_send(crate::app::logging::LogEvent::Connection {
                                json_log_path: log_path.clone(),
                                event_type: "connection_closed".to_string(),
                                connection: conn.clone(),
                                duration_secs,
                                source_hostname: dns_resolver
                                    .as_deref()
                                    .and_then(|r| r.get_hostname(&conn.local_addr.ip())),
                                dest_hostname: dns_resolver
                                    .as_deref()
                                    .and_then(|r| r.get_hostname(&conn.remote_addr.ip())),
                            });
                        }

                        if let Some(pcap_path) = &pcap_export_path {
                            let _ = log_tx.try_send(crate::app::logging::LogEvent::Pcap {
                                pcap_path: pcap_path.clone(),
                                connection: conn.clone(),
                            });
                        }
                    }

                    should_keep
                });

                for (key, conn) in to_archive {
                    historic_connections.insert(key, conn);
                }

                if historic_connections.len() > MAX_HISTORIC_CONNECTIONS {
                    let mut entries: Vec<(String, SystemTime)> = historic_connections
                        .iter()
                        .map(|entry| {
                            let closed =
                                entry.value().closed_at.unwrap_or(entry.value().created_at);
                            (entry.key().clone(), closed)
                        })
                        .collect();
                    entries.sort_by_key(|(_, closed)| *closed);
                    let to_remove = historic_connections.len() - MAX_HISTORIC_CONNECTIONS;
                    for (key, _) in entries.into_iter().take(to_remove) {
                        historic_connections.remove(&key);
                    }
                }

                if !removed_keys.is_empty() {
                    QUIC_CONNECTION_MAPPING.retain(|_, conn_key| !removed_keys.contains(conn_key));
                }

                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        Ok(())
    }
}
