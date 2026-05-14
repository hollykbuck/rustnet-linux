use arboard::Clipboard;
use log::{error, info};
use crate::app::App;
use crate::ui::UIState;

/// Copy text to the system clipboard and update UI state with feedback.
pub fn copy_to_clipboard(text: &str, display_msg: &str, ui_state: &mut UIState, app: &App) {
    let result = Clipboard::new().and_then(|mut cb| cb.set_text(text));

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    let result = result.or_else(|_| {
        std::process::Command::new("wl-copy")
            .arg(text)
            .status()
            .map_err(|e| arboard::Error::Unknown {
                description: e.to_string(),
            })
            .and_then(|s| {
                if s.success() {
                    Ok(())
                } else {
                    Err(arboard::Error::Unknown {
                        description: "wl-copy failed".to_string(),
                    })
                }
            })
    });

    match result {
        Ok(()) => {
            info!("Copied to clipboard: {}", display_msg);
            ui_state.clipboard_message = Some((
                format!("Copied: {}", display_msg),
                std::time::Instant::now(),
            ));
        }
        Err(e) => {
            #[cfg(target_os = "linux")]
            let msg = if app.get_sandbox_info().fs_restricted {
                "Clipboard unavailable (sandbox active). Use --no-sandbox to enable.".to_string()
            } else {
                format!("Clipboard error: {}", e)
            };
            #[cfg(not(target_os = "linux"))]
            let msg = format!("Clipboard error: {}", e);

            error!("{}", msg);
            ui_state.clipboard_message = Some((msg, std::time::Instant::now()));
        }
    }
}

/// Placeholder string displayed when a value is unavailable.
pub const NONE_PLACEHOLDER: &str = "-";

/// Format rate to human readable form
pub fn format_rate(bytes_per_second: f64) -> String {
    const KB_PER_SEC: f64 = 1024.0;
    const MB_PER_SEC: f64 = KB_PER_SEC * 1024.0;
    const GB_PER_SEC: f64 = MB_PER_SEC * 1024.0;

    if bytes_per_second >= GB_PER_SEC {
        format!("{:.2} GB/s", bytes_per_second / GB_PER_SEC)
    } else if bytes_per_second >= MB_PER_SEC {
        format!("{:.2} MB/s", bytes_per_second / MB_PER_SEC)
    } else if bytes_per_second >= KB_PER_SEC {
        format!("{:.2} KB/s", bytes_per_second / KB_PER_SEC)
    } else if bytes_per_second > 0.0 {
        format!("{:.0} B/s", bytes_per_second)
    } else {
        NONE_PLACEHOLDER.to_string()
    }
}

/// Format rate to compact form for tight spaces
pub fn format_rate_compact(bytes_per_second: f64) -> String {
    const KB_PER_SEC: f64 = 1024.0;
    const MB_PER_SEC: f64 = KB_PER_SEC * 1024.0;
    const GB_PER_SEC: f64 = MB_PER_SEC * 1024.0;

    if bytes_per_second >= GB_PER_SEC {
        format!("{:.1}G", bytes_per_second / GB_PER_SEC)
    } else if bytes_per_second >= MB_PER_SEC {
        format!("{:.1}M", bytes_per_second / MB_PER_SEC)
    } else if bytes_per_second >= KB_PER_SEC {
        format!("{:.0}K", bytes_per_second / KB_PER_SEC)
    } else if bytes_per_second > 0.0 {
        format!("{:.0}B", bytes_per_second)
    } else {
        NONE_PLACEHOLDER.to_string()
    }
}

/// Format bytes to human readable form
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

pub fn format_system_time(time: std::time::SystemTime) -> String {
    use chrono::{DateTime, Local};
    let datetime: DateTime<Local> = time.into();
    datetime.format("%H:%M:%S").to_string()
}
