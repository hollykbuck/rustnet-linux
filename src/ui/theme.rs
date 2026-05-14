use ratatui::style::{Color, Modifier, Style};
use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag for NO_COLOR support (<https://no-color.org>)
pub static NO_COLOR: AtomicBool = AtomicBool::new(false);

/// Set the NO_COLOR flag
pub fn set_no_color(value: bool) {
    NO_COLOR.store(value, Ordering::Relaxed);
}

/// Apply style only if colors are enabled
pub fn style_if_colored(style: Style) -> Style {
    if NO_COLOR.load(Ordering::Relaxed) {
        Style::default()
    } else {
        style
    }
}

// Core Colors
pub const fn primary() -> Color { Color::Cyan }
pub const fn accent() -> Color { Color::Magenta }
pub const fn heading() -> Color { Color::Yellow }
pub const fn muted() -> Color { Color::DarkGray }
pub const fn label() -> Color { Color::Gray }
pub const fn key() -> Color { Color::Cyan }

// Status Colors
pub const fn ok() -> Color { Color::Green }
pub const fn warn() -> Color { Color::Yellow }
pub const fn err() -> Color { Color::Red }

// Protocol Colors
pub const fn proto_https() -> Color { Color::Green }
pub const fn proto_quic() -> Color { Color::Cyan }
pub const fn proto_http() -> Color { Color::Yellow }
pub const fn proto_dns() -> Color { Color::Blue }
pub const fn proto_ssh() -> Color { Color::Magenta }
pub const fn proto_other() -> Color { Color::White }

// Traffic Colors
pub const fn rx() -> Color { Color::Green }
pub const fn tx() -> Color { Color::Blue }

// TCP State Colors
pub const fn tcp_established() -> Color { Color::Green }
pub const fn tcp_opening() -> Color { Color::Yellow }
pub const fn tcp_closing() -> Color { Color::Red }
pub const fn tcp_waiting() -> Color { Color::DarkGray }
pub const fn tcp_closed() -> Color { Color::Gray }

// Helpers
pub const fn fg(color: Color) -> Style { Style::new().fg(color) }
pub const fn bold_fg(color: Color) -> Style { Style::new().fg(color).add_modifier(Modifier::BOLD) }
pub fn bold_underline_fg(color: Color) -> Style { Style::new().fg(color).add_modifier(Modifier::BOLD | Modifier::UNDERLINED) }

// UI Elements
pub fn row_highlight() -> Style {
    style_if_colored(Style::default().bg(Color::Rgb(40, 44, 52)).add_modifier(Modifier::BOLD))
}

pub fn status_bar_default() -> Style {
    style_if_colored(Style::default().bg(Color::DarkGray).fg(Color::White))
}

pub fn status_bar_confirm() -> Style {
    style_if_colored(Style::default().bg(err()).fg(Color::White).add_modifier(Modifier::BOLD))
}

pub fn status_bar_success() -> Style {
    style_if_colored(Style::default().bg(ok()).fg(Color::Black).add_modifier(Modifier::BOLD))
}

pub const fn field_local_addr() -> Color { Color::Rgb(152, 195, 121) }
pub const fn field_remote_addr() -> Color { Color::Rgb(97, 175, 239) }
pub const fn field_process() -> Color { Color::Rgb(224, 108, 117) }
pub const fn field_service() -> Color { Color::Rgb(209, 154, 102) }
pub const fn field_location() -> Color { Color::Rgb(198, 120, 221) }
pub const fn field_application() -> Color { Color::White }
