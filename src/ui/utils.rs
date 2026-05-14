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
