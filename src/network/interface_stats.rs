use std::io;
use std::net::IpAddr;
use std::time::SystemTime;

/// Statistics for a network interface
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub interface_name: String,
    pub description: Option<String>,
    // Metadata
    pub mac_address: Option<String>,
    pub ipv4: Vec<IpAddr>,
    pub ipv6: Vec<IpAddr>,
    pub mtu: Option<u64>,
    pub operstate: Option<String>,
    pub flags: Option<u32>,
    // Traffic Counters
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub collisions: u64,
    pub timestamp: SystemTime,
}

impl InterfaceStats {
    /// Calculate rates from two snapshots
    pub fn calculate_rates(&self, previous: &InterfaceStats) -> InterfaceRates {
        let duration = self
            .timestamp
            .duration_since(previous.timestamp)
            .unwrap_or_default()
            .as_secs_f64();

        if duration == 0.0 {
            return InterfaceRates::default();
        }

        InterfaceRates {
            rx_bytes_per_sec: ((self.rx_bytes.saturating_sub(previous.rx_bytes)) as f64 / duration)
                as u64,
            tx_bytes_per_sec: ((self.tx_bytes.saturating_sub(previous.tx_bytes)) as f64 / duration)
                as u64,
        }
    }
}

/// Rate calculations for interface statistics
#[derive(Debug, Clone, Default)]
pub struct InterfaceRates {
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
}

/// Trait for platform-specific interface statistics providers
pub trait InterfaceStatsProvider: Send + Sync {
    /// Get statistics for all available interfaces
    fn get_all_stats(&self) -> Result<Vec<InterfaceStats>, io::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn mock_stats(name: &str, rx: u64, tx: u64, timestamp: SystemTime) -> InterfaceStats {
        InterfaceStats {
            interface_name: name.to_string(),
            description: None,
            mac_address: None,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            mtu: None,
            operstate: None,
            flags: None,
            rx_bytes: rx,
            tx_bytes: tx,
            rx_packets: 10,
            tx_packets: 5,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            collisions: 0,
            timestamp,
        }
    }

    #[test]
    fn test_rate_calculation() {
        let t1 = SystemTime::now();
        let t2 = t1 + Duration::from_secs(1);

        let stats1 = mock_stats("test", 1000, 500, t1);
        let stats2 = mock_stats("test", 2000, 1000, t2);

        let rates = stats2.calculate_rates(&stats1);
        assert_eq!(rates.rx_bytes_per_sec, 1000);
        assert_eq!(rates.tx_bytes_per_sec, 500);
    }

    #[test]
    fn test_rate_calculation_zero_duration() {
        let t = SystemTime::now();
        let stats1 = mock_stats("test", 1000, 500, t);
        let stats2 = stats1.clone();

        let rates = stats2.calculate_rates(&stats1);
        assert_eq!(rates.rx_bytes_per_sec, 0);
        assert_eq!(rates.tx_bytes_per_sec, 0);
    }

    #[test]
    fn test_rate_calculation_with_counter_wrapping() {
        let t1 = SystemTime::now();
        let t2 = t1 + Duration::from_secs(1);

        let stats1 = mock_stats("test", 1000, 500, t1);
        let stats2 = mock_stats("test", 500, 250, t2);

        let rates = stats2.calculate_rates(&stats1);
        // Should result in 0 due to saturating_sub
        assert_eq!(rates.rx_bytes_per_sec, 0);
        assert_eq!(rates.tx_bytes_per_sec, 0);
    }
}
