use anyhow::Result;
use log::{LevelFilter, error, info};
use ratatui::prelude::CrosstermBackend;
use simplelog::{Config as LogConfig, WriteLogger};
use std::fs::{self, File};
use std::io;
use std::path::Path;

mod app;
mod cli;
mod filter;
mod network;
mod ui;

use crate::app::sandbox::initialize_sandbox;
use crate::app::{App, Config};
use crate::ui::run_ui_loop;

fn main() -> Result<()> {
    // Check for required dependencies on Windows
    #[cfg(target_os = "windows")]
    check_windows_dependencies()?;

    // Parse command line arguments
    let matches = cli::build_cli().get_matches();

    // Set up logging only if log-level was provided
    if let Some(log_level_str) = matches.get_one::<String>("log-level") {
        let log_level = log_level_str
            .parse::<LevelFilter>()
            .map_err(|_| anyhow::anyhow!("Invalid log level: {}", log_level_str))?;
        setup_logging(log_level)?;
    }

    // Check privileges BEFORE initializing TUI (so error messages are visible)
    check_privileges_early()?;

    info!("Starting RustNet Monitor");

    // Build configuration from command line arguments
    let config = Config::from_matches(&matches);

    // Check NO_COLOR environment variable and --no-color flag (https://no-color.org)
    let no_color =
        matches.get_flag("no-color") || std::env::var("NO_COLOR").is_ok_and(|v| !v.is_empty());
    if no_color {
        info!("Colors disabled (NO_COLOR)");
        ui::set_no_color(true);
    }

    // Set up terminal
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = ui::setup_terminal(backend)?;
    info!("Terminal UI initialized");

    // Create and start the application
    let mut app = App::new(config.clone())?;
    let process_ready_rx = app.start()?;
    info!("Application started");

    // Pre-create sidecar JSONL file for PCAP export
    if let Some(ref pcap_path) = config.pcap_export_file {
        let jsonl_path = format!("{}.connections.jsonl", pcap_path);
        if let Ok(_f) = std::fs::File::create(&jsonl_path) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = _f.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
        }
    }

    // Wait for process detection to initialize
    match process_ready_rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(()) => info!("Process detection initialized, safe to apply sandbox"),
        Err(_) => info!("Proceeding with sandbox application"),
    }

    // Apply platform-specific sandbox
    if let Err(e) = initialize_sandbox(&app, &matches)
        && matches.get_flag("sandbox-strict")
    {
        return Err(e);
    }

    // Run the UI loop
    let res = run_ui_loop(&mut terminal, &app);

    // Cleanup
    app.stop();
    ui::restore_terminal(&mut terminal)?;

    if let Err(err) = res {
        error!("Application error: {}", err);
        println!("Error: {}", err);
    }

    info!("RustNet Monitor shutting down");
    Ok(())
}

fn setup_logging(level: LevelFilter) -> Result<()> {
    let log_dir = Path::new("logs");
    if !log_dir.exists() {
        fs::create_dir_all(log_dir)?;
    }

    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    let log_file_path = log_dir.join(format!("rustnet_{}.log", timestamp));

    WriteLogger::init(level, LogConfig::default(), File::create(log_file_path)?)?;
    Ok(())
}

fn check_privileges_early() -> Result<()> {
    match network::privileges::check_packet_capture_privileges() {
        Ok(status) if !status.has_privileges => {
            eprintln!(
                "\n╔═══════════════════════════════════════════════════════════════════════════╗"
            );
            eprintln!(
                "║                   INSUFFICIENT PRIVILEGES                                 ║"
            );
            eprintln!(
                "╚═══════════════════════════════════════════════════════════════════════════╝\n"
            );
            eprintln!("{}", status.error_message());
            return Err(anyhow::anyhow!(
                "Insufficient privileges for packet capture"
            ));
        }
        Err(e) => {
            eprintln!("Warning: Failed to check privileges: {}\n", e);
        }
        _ => {}
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn check_windows_dependencies() -> Result<()> {
    use anyhow::anyhow;
    let wpcap_available = check_dll_available("wpcap.dll");
    let packet_available = check_dll_available("Packet.dll");

    if !wpcap_available || !packet_available {
        eprintln!(
            "\n╔═══════════════════════════════════════════════════════════════════════════╗"
        );
        eprintln!("║                          MISSING DEPENDENCY                               ║");
        eprintln!(
            "╚═══════════════════════════════════════════════════════════════════════════╝\n"
        );
        eprintln!("RustNet requires Npcap for packet capture on Windows.\n");
        if !wpcap_available {
            eprintln!("  ✗ wpcap.dll not found");
        }
        if !packet_available {
            eprintln!("  ✗ Packet.dll not found");
        }
        eprintln!(
            "\nTo fix this:\n  1. Download Npcap from: https://npcap.com/dist/\n  2. Run the installer\n  3. IMPORTANT: Check \"Install Npcap in WinPcap API-compatible Mode\"\n"
        );
        return Err(anyhow!(
            "Npcap is not installed or not in WinPcap compatible mode"
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn check_dll_available(dll_name: &str) -> bool {
    use std::ffi::CString;
    use windows::Win32::Foundation::{FreeLibrary, HMODULE};
    use windows::Win32::System::LibraryLoader::LoadLibraryA;
    use windows::core::PCSTR;

    let dll_cstring = CString::new(dll_name).unwrap();
    unsafe {
        if let Ok(h) = LoadLibraryA(PCSTR(dll_cstring.as_ptr() as *const u8))
            && h != HMODULE(std::ptr::null_mut())
        {
            let _ = FreeLibrary(h);
            true
        } else {
            false
        }
    }
}
