use std::sync::RwLock;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

/// Sandbox status information for UI display
#[cfg(any(
    target_os = "linux",
    target_os = "windows",
    all(target_os = "macos", feature = "macos-sandbox")
))]
#[derive(Debug, Clone, Default)]
pub struct SandboxInfo {
    /// Overall status description
    pub status: String,
    /// Whether network connections are blocked
    #[cfg(any(
        target_os = "linux",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    pub net_restricted: bool,
    // Linux-specific fields (Landlock + capabilities)
    /// Whether CAP_NET_RAW was dropped
    #[cfg(target_os = "linux")]
    pub cap_dropped: bool,
    /// Whether CAP_BPF/CAP_PERFMON were dropped
    #[cfg(target_os = "linux")]
    pub ebpf_caps_dropped: bool,
    /// Whether Landlock is available on this kernel
    #[cfg(target_os = "linux")]
    pub landlock_available: bool,
    /// Whether Landlock filesystem restrictions are applied
    #[cfg(target_os = "linux")]
    pub fs_restricted: bool,
    // macOS-specific fields (Seatbelt)
    /// Whether Seatbelt sandbox was applied
    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    pub seatbelt_applied: bool,
    /// Whether filesystem write restrictions are applied
    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    pub fs_restricted: bool,
    // Windows-specific fields (Restricted token + Job Object)
    /// Whether dangerous privileges were removed
    #[cfg(target_os = "windows")]
    pub privileges_removed: bool,
    /// Number of privileges removed
    #[cfg(target_os = "windows")]
    pub privileges_removed_count: u32,
    /// Whether job object was applied
    #[cfg(target_os = "windows")]
    pub job_object_applied: bool,
}

/// Process detection status information for UI display
#[derive(Debug, Clone, Default)]
pub struct ProcessDetectionStatus {
    /// The active detection method (e.g., "eBPF + procfs", "pktap", "lsof")
    pub method: String,
    /// Whether the detection is degraded from optimal
    pub is_degraded: bool,
    /// Human-readable reason for degradation (if any)
    pub degradation_reason: Option<String>,
    /// What feature is unavailable (e.g., "eBPF", "PKTAP")
    pub unavailable_feature: Option<String>,
}

impl ProcessDetectionStatus {
    /// Create a new status with just a method (no degradation)
    pub fn with_method(method: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            is_degraded: false,
            degradation_reason: None,
            unavailable_feature: None,
        }
    }

    /// Create a new degraded status
    pub fn degraded(
        method: impl Into<String>,
        unavailable_feature: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            is_degraded: true,
            degradation_reason: Some(reason.into()),
            unavailable_feature: Some(unavailable_feature.into()),
        }
    }
}

/// Application statistics
#[derive(Debug)]
pub struct AppStats {
    pub packets_processed: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub connections_tracked: AtomicU64,
    pub last_update: RwLock<Instant>,
    // TCP analytics totals (since program start)
    pub total_tcp_retransmits: AtomicU64,
    pub total_tcp_out_of_order: AtomicU64,
    pub total_tcp_fast_retransmits: AtomicU64,
}

impl Default for AppStats {
    fn default() -> Self {
        Self {
            packets_processed: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            connections_tracked: AtomicU64::new(0),
            last_update: RwLock::new(Instant::now()),
            total_tcp_retransmits: AtomicU64::new(0),
            total_tcp_out_of_order: AtomicU64::new(0),
            total_tcp_fast_retransmits: AtomicU64::new(0),
        }
    }
}
