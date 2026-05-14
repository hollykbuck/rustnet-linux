use crate::app::{App, SandboxInfo};
use crate::network::geoip::GeoIpResolver;
use crate::network::platform::sandbox::{SandboxConfig, SandboxMode, SandboxStatus, apply_sandbox};
use log::warn;
use std::path::PathBuf;

/// Initialize and apply the security sandbox for the current platform.
///
/// This must be called after the application has started and opened its
/// initial resources (capture handles, log files, etc.).
pub fn initialize_sandbox(app: &App, matches: &clap::ArgMatches) -> anyhow::Result<()> {
    let config = &app.config;

    let sandbox_mode = if matches.get_flag("no-sandbox") {
        SandboxMode::Disabled
    } else if matches.get_flag("sandbox-strict") {
        SandboxMode::Strict
    } else {
        SandboxMode::BestEffort
    };

    #[cfg(all(target_os = "linux", feature = "landlock"))]
    {
        // Collect read paths (GeoIP databases)
        let read_paths: Vec<PathBuf> = GeoIpResolver::get_search_paths()
            .into_iter()
            .filter(|p| p.exists())
            .collect();

        let mut write_paths = Vec::new();

        // Add logs directory if logging is enabled
        if matches.get_one::<String>("log-level").is_some() {
            write_paths.push(PathBuf::from("logs"));
        }

        // Add JSON log path if specified
        if let Some(json_log_path) = &config.json_log_file {
            write_paths.push(PathBuf::from(json_log_path));
        }

        // Add PCAP export paths if specified (both .pcap and .pcap.connections.jsonl)
        if let Some(pcap_path) = &config.pcap_export_file {
            write_paths.push(PathBuf::from(pcap_path));
            write_paths.push(PathBuf::from(format!("{}.connections.jsonl", pcap_path)));
        }

        let sandbox_config = SandboxConfig {
            mode: sandbox_mode,
            block_network: true, // RustNet is passive, doesn't need TCP
            read_paths,
            write_paths,
        };

        match apply_sandbox(&sandbox_config) {
            Ok(result) => {
                let status_str = match result.status {
                    SandboxStatus::FullyEnforced => "Fully enforced",
                    SandboxStatus::PartiallyEnforced => "Partially enforced",
                    SandboxStatus::NotApplied => "Not applied",
                };

                app.set_sandbox_info(SandboxInfo {
                    status: status_str.to_string(),
                    cap_dropped: result.cap_net_raw_dropped,
                    ebpf_caps_dropped: result.ebpf_caps_dropped,
                    landlock_available: result.landlock_available,
                    fs_restricted: result.landlock_fs_applied,
                    net_restricted: result.landlock_net_applied,
                    ..Default::default()
                });
            }
            Err(e) => {
                if sandbox_mode == SandboxMode::Strict {
                    return Err(e.context("Sandbox enforcement required but failed"));
                }
                warn!("Sandbox application error (non-strict mode): {}", e);
                app.set_sandbox_info(SandboxInfo {
                    status: "Error".to_string(),
                    ..Default::default()
                });
            }
        }
    }

    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    {
        let log_dir = if matches.get_one::<String>("log-level").is_some() {
            Some("logs".to_string())
        } else {
            None
        };

        let geoip_paths: Vec<String> = {
            let mut paths = Vec::new();
            if let Some(ref p) = config.geoip_country_path {
                paths.push(p.clone());
            }
            if let Some(ref p) = config.geoip_asn_path {
                paths.push(p.clone());
            }
            if let Some(ref p) = config.geoip_city_path {
                paths.push(p.clone());
            }
            if paths.is_empty() && !config.disable_geoip {
                paths.extend(
                    GeoIpResolver::get_search_paths()
                        .into_iter()
                        .filter(|p| p.exists())
                        .map(|p| p.to_string_lossy().into_owned()),
                );
            }
            paths
        };

        let sandbox_config = SandboxConfig {
            mode: sandbox_mode,
            block_network: true,
            log_dir,
            json_log_path: config.json_log_file.clone(),
            pcap_export_path: config.pcap_export_file.clone(),
            geoip_paths,
        };

        match apply_sandbox(&sandbox_config) {
            Ok(result) => {
                let status_str = match result.status {
                    SandboxStatus::FullyEnforced => {
                        info!("Seatbelt sandbox fully enforced: {}", result.message);
                        "Fully enforced"
                    }
                    SandboxStatus::NotApplied => {
                        warn!("Seatbelt sandbox not applied: {}", result.message);
                        "Not applied"
                    }
                    _ => "Not applied",
                };

                app.set_sandbox_info(SandboxInfo {
                    status: status_str.to_string(),
                    seatbelt_applied: result.seatbelt_applied,
                    fs_restricted: result.fs_restricted,
                    net_restricted: result.net_blocked,
                    ..Default::default()
                });
            }
            Err(e) => {
                if sandbox_mode == SandboxMode::Strict {
                    return Err(e.context("Seatbelt sandbox enforcement required but failed"));
                }
                info!("Seatbelt sandbox error (non-strict mode): {}", e);
                app.set_sandbox_info(SandboxInfo {
                    status: "Error".to_string(),
                    ..Default::default()
                });
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let sandbox_config = SandboxConfig { mode: sandbox_mode };

        match apply_sandbox(&sandbox_config) {
            Ok(result) => {
                let status_str = match result.status {
                    SandboxStatus::FullyEnforced => {
                        info!("Windows sandbox fully enforced: {}", result.message);
                        "Fully enforced"
                    }
                    SandboxStatus::PartiallyEnforced => {
                        warn!("Windows sandbox partially enforced: {}", result.message);
                        "Partially enforced"
                    }
                    SandboxStatus::NotApplied => {
                        warn!("Windows sandbox not applied: {}", result.message);
                        "Not applied"
                    }
                };

                app.set_sandbox_info(SandboxInfo {
                    status: status_str.to_string(),
                    privileges_removed: result.privileges_removed,
                    privileges_removed_count: result.privileges_removed_count,
                    job_object_applied: result.job_object_applied,
                    ..Default::default()
                });
            }
            Err(e) => {
                if sandbox_mode == SandboxMode::Strict {
                    return Err(e.context("Windows sandbox enforcement required but failed"));
                }
                warn!("Windows sandbox error (non-strict mode): {}", e);
                app.set_sandbox_info(SandboxInfo {
                    status: "Error".to_string(),
                    ..Default::default()
                });
            }
        }
    }

    Ok(())
}
