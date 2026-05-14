use ratatui::Terminal as RatatuiTerminal;
use std::collections::HashSet;
use std::time::{Instant, SystemTime};

pub mod theme;
pub mod utils;
pub mod components;
pub mod tabs;
pub mod event_loop;

pub use theme::*;
pub use utils::*;
pub use components::*;
pub use tabs::*;
pub use event_loop::run_ui_loop;

pub type Terminal<B> = RatatuiTerminal<B>;

/// Application UI State
#[derive(Debug, Clone)]
pub struct UIState {
    pub selected_tab: usize,
    pub selected_connection_key: Option<String>,
    pub selected_service_key: Option<String>,
    pub selected_device_key: Option<String>,
    pub scroll_offset: usize,
    pub grouped_scroll_offset: usize,
    pub services_scroll_offset: usize,
    pub devices_scroll_offset: usize,
    pub visible_rows: usize,
    pub show_help: bool,
    pub show_port_numbers: bool,
    pub show_hostnames: bool,
    pub show_historic: bool,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    pub grouping_enabled: bool,
    pub expanded_groups: HashSet<String>,
    pub filter_mode: bool,
    pub filter_query: String,
    pub filter_cursor_position: usize,
    pub quit_confirmation: bool,
    pub clear_confirmation: bool,
    pub clipboard_message: Option<(String, Instant)>,
    pub has_geoip: bool,
    pub details_view_mode: DetailsViewMode,
    pub last_click: Option<(u16, u16, Instant)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailsViewMode {
    Connection,
    Service,
    Device,
}

impl Default for UIState {
    fn default() -> Self {
        Self {
            selected_tab: 0,
            selected_connection_key: None,
            selected_service_key: None,
            selected_device_key: None,
            scroll_offset: 0,
            grouped_scroll_offset: 0,
            services_scroll_offset: 0,
            devices_scroll_offset: 0,
            visible_rows: 20,
            show_help: false,
            show_port_numbers: false,
            show_hostnames: true,
            show_historic: false,
            sort_column: SortColumn::CreatedAt,
            sort_ascending: true,
            grouping_enabled: false,
            expanded_groups: HashSet::new(),
            filter_mode: false,
            filter_query: String::new(),
            filter_cursor_position: 0,
            quit_confirmation: false,
            clear_confirmation: false,
            clipboard_message: None,
            has_geoip: false,
            details_view_mode: DetailsViewMode::Connection,
            last_click: None,
        }
    }
}

// ... (Rest of UIState methods and SortColumn, GroupedRow, ClickAction types will be here)
// I'll skip the full implementation for now and use replace to add it.
