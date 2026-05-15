use anyhow::Result;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Tabs};
use std::collections::HashSet;
use std::time::Instant;

pub mod components;
pub mod event_loop;
pub mod tabs;
pub mod theme;
pub mod utils;

pub use components::*;
pub use event_loop::run_ui_loop;
pub use tabs::*;
pub use theme::*;
pub use utils::*;

pub type Terminal<B> = ratatui::Terminal<B>;

/// Application UI State
pub struct UIState {
    pub selected_tab: usize,
    pub selected_connection_key: Option<String>,
    pub selected_service_key: Option<String>,
    pub selected_device_mac: Option<String>,
    pub selected_interface: Option<String>,
    pub show_interface_modal: bool,
    pub show_connection_modal: bool,
    pub selected_route_index: Option<usize>,
    pub show_route_modal: bool,
    pub show_device_modal: bool,
    pub show_service_modal: bool,
    pub selected_group: Option<String>,
    pub service_selected_group: Option<String>,
    pub scroll_offset: usize,
    pub grouped_scroll_offset: usize,
    pub services_scroll_offset: usize,
    pub service_grouped_scroll_offset: usize,
    pub devices_scroll_offset: usize,
    pub interfaces_scroll_offset: usize,
    pub routes_scroll_offset: usize,
    pub visible_rows: usize,
    pub show_help: bool,
    pub show_port_numbers: bool,
    pub show_hostnames: bool,
    pub show_historic: bool,
    pub sort_column: SortColumn,
    pub service_sort_column: ServiceSortColumn,
    pub device_sort_column: DeviceSortColumn,
    pub sort_ascending: bool,
    pub grouping_enabled: bool,
    pub service_grouping_enabled: bool,
    pub expanded_groups: HashSet<String>,
    pub service_expanded_groups: HashSet<String>,
    pub filter_mode: bool,
    pub filter_query: String,
    pub filter_cursor_position: usize,
    pub quit_confirmation: bool,
    pub clear_confirmation: bool,
    pub clipboard_message: Option<(String, Instant)>,
    pub has_geoip: bool,
    pub last_click: Option<(u16, u16, Instant)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServiceSortColumn {
    Protocol,
    LocalAddress,
    Service,
    Process,
    #[default]
    Connections,
}

impl ServiceSortColumn {
    pub fn next(self) -> Self {
        match self {
            Self::Protocol => Self::LocalAddress,
            Self::LocalAddress => Self::Service,
            Self::Service => Self::Process,
            Self::Process => Self::Connections,
            Self::Connections => Self::Protocol,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceSortColumn {
    Status,
    IpAddress,
    Hostname,
    MacAddress,
    Vendor,
    #[default]
    LastSeen,
    BytesReceived,
    BytesSent,
}

impl DeviceSortColumn {
    pub fn next(self) -> Self {
        match self {
            Self::Status => Self::IpAddress,
            Self::IpAddress => Self::Hostname,
            Self::Hostname => Self::MacAddress,
            Self::MacAddress => Self::Vendor,
            Self::Vendor => Self::LastSeen,
            Self::LastSeen => Self::BytesReceived,
            Self::BytesReceived => Self::BytesSent,
            Self::BytesSent => Self::Status,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortColumn {
    #[default]
    CreatedAt,
    BandwidthTotal,
    Process,
    LocalAddress,
    RemoteAddress,
    Location,
    Application,
    Service,
    State,
    Protocol,
}

impl SortColumn {
    pub fn next(self, has_location: bool) -> Self {
        match self {
            Self::CreatedAt => Self::Protocol,
            Self::Protocol => Self::LocalAddress,
            Self::LocalAddress => Self::RemoteAddress,
            Self::RemoteAddress => {
                if has_location {
                    Self::Location
                } else {
                    Self::State
                }
            }
            Self::Location => Self::State,
            Self::State => Self::Service,
            Self::Service => Self::Application,
            Self::Application => Self::BandwidthTotal,
            Self::BandwidthTotal => Self::Process,
            Self::Process => Self::CreatedAt,
        }
    }

    pub fn default_direction(self) -> bool {
        match self {
            Self::BandwidthTotal => false,
            _ => true,
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::CreatedAt => "Time",
            Self::BandwidthTotal => "Bandwidth Total",
            Self::Process => "Process",
            Self::LocalAddress => "Local Addr",
            Self::RemoteAddress => "Remote Addr",
            Self::Location => "Location",
            Self::Application => "Application",
            Self::Service => "Service",
            Self::State => "State",
            Self::Protocol => "Protocol",
        }
    }
}

/// Aggregated stats for a process group
#[derive(Debug, Clone, Default)]
pub struct ProcessGroupStats {
    pub connection_count: usize,
    pub historic_count: usize,
    pub tcp_count: usize,
    pub udp_count: usize,
    pub total_incoming_rate_bps: f64,
    pub total_outgoing_rate_bps: f64,
}

/// A row in the grouped display
#[derive(Debug, Clone)]
pub enum GroupedRow<'a> {
    Group {
        process_name: String,
        stats: ProcessGroupStats,
        expanded: bool,
    },
    Connection {
        process_name: String,
        connection: &'a crate::network::types::Connection,
        is_last_in_group: bool,
    },
}

/// Aggregated stats for a service process group
#[derive(Debug, Clone, Default)]
pub struct ServiceProcessGroupStats {
    pub listener_count: usize,
    pub total_active_connections: usize,
}

/// A row in the grouped services display
#[derive(Debug, Clone)]
pub enum ServiceGroupedRow<'a> {
    Group {
        process_name: String,
        stats: ServiceProcessGroupStats,
        expanded: bool,
    },
    Service {
        process_name: String,
        listener: &'a crate::network::types::Listener,
        is_last_in_group: bool,
    },
}

impl Default for UIState {
    fn default() -> Self {
        Self {
            selected_tab: 0,
            selected_connection_key: None,
            selected_service_key: None,
            selected_device_mac: None,
            selected_interface: None,
            show_interface_modal: false,
            show_connection_modal: false,
            selected_route_index: None,
            show_route_modal: false,
            show_device_modal: false,
            show_service_modal: false,
            selected_group: None,
            service_selected_group: None,
            scroll_offset: 0,
            grouped_scroll_offset: 0,
            services_scroll_offset: 0,
            service_grouped_scroll_offset: 0,
            devices_scroll_offset: 0,
            interfaces_scroll_offset: 0,
            routes_scroll_offset: 0,
            visible_rows: 20,
            show_help: false,
            show_port_numbers: false,
            show_hostnames: true,
            show_historic: false,
            sort_column: SortColumn::CreatedAt,
            service_sort_column: ServiceSortColumn::default(),
            device_sort_column: DeviceSortColumn::default(),
            sort_ascending: true,
            grouping_enabled: false,
            service_grouping_enabled: false,
            expanded_groups: HashSet::new(),
            service_expanded_groups: HashSet::new(),
            filter_mode: false,
            filter_query: String::new(),
            filter_cursor_position: 0,
            quit_confirmation: false,
            clear_confirmation: false,
            clipboard_message: None,
            has_geoip: false,
            last_click: None,
        }
    }
}

// Registry of clickable screen regions
#[derive(Debug, Default)]
pub struct ClickableRegions {
    pub regions: Vec<(Rect, ClickAction)>,
    pub scroll_area: Option<Rect>,
}

#[derive(Debug, Clone)]
pub enum ClickAction {
    SwitchTab(usize),
    SelectConnection(usize),
    SelectService(usize),
    SelectDevice(usize),
    SelectInterface(usize),
    SelectRoute(usize),
    CopyField { label: String, value: String },
}

impl ClickableRegions {
    pub fn clear(&mut self) {
        self.regions.clear();
        self.scroll_area = None;
    }
    pub fn register(&mut self, area: Rect, action: ClickAction) {
        self.regions.push((area, action));
    }
    pub fn hit_test(&self, column: u16, row: u16) -> Option<&ClickAction> {
        self.regions
            .iter()
            .rev()
            .find(|(rect, _)| {
                column >= rect.x
                    && column < rect.x + rect.width
                    && row >= rect.y
                    && row < rect.y + rect.height
            })
            .map(|(_, action)| action)
    }
}

/// Compute a stable scroll offset
pub fn compute_scroll_offset(
    selected_index: usize,
    current_offset: usize,
    visible_rows: usize,
    total_rows: usize,
) -> usize {
    if total_rows == 0 || visible_rows == 0 {
        return 0;
    }
    let max_offset = total_rows.saturating_sub(visible_rows);
    let mut offset = current_offset.min(max_offset);
    if selected_index < offset {
        offset = selected_index;
    }
    if selected_index >= offset + visible_rows {
        offset = selected_index - visible_rows + 1;
    }
    offset.min(max_offset)
}

/// Orchestrate UI rendering
pub fn draw(
    f: &mut Frame,
    app: &crate::app::App,
    ui_state: &UIState,
    connections: &[crate::network::types::Connection],
    grouped_rows: Option<&[GroupedRow]>,
    service_grouped_rows: Option<&[ServiceGroupedRow]>,
    devices: &[crate::network::types::Device],
    stats: &crate::app::AppStats,
    click_regions: &mut ClickableRegions,
) -> Result<()> {
    click_regions.clear();
    let area = f.area();

    if app.is_loading() && connections.is_empty() {
        draw_loading_screen(f);
        return Ok(());
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Content
            Constraint::Length(1), // Status bar
        ])
        .split(area);

    draw_tabs(f, ui_state, chunks[0], click_regions);

    let mut content_area = chunks[1];
    if ui_state.filter_mode || !ui_state.filter_query.is_empty() {
        let content_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(content_area);
        draw_filter_input(f, ui_state, content_chunks[0]);
        content_area = content_chunks[1];
    }

    match ui_state.selected_tab {
        0 => draw_overview(
            f,
            app,
            ui_state,
            connections,
            grouped_rows,
            stats,
            content_area,
            click_regions,
        )?,
        1 => draw_devices(f, app, ui_state, devices, content_area, click_regions)?,
        2 => draw_services(
            f,
            app,
            ui_state,
            service_grouped_rows,
            connections,
            content_area,
            click_regions,
        )?,
        3 => draw_interface_stats(f, app, ui_state, content_area, click_regions)?,
        4 => draw_routes_tab(f, app, ui_state, content_area, click_regions)?,
        5 => draw_graph_tab(f, app, connections, content_area)?,
        6 => draw_help(f, content_area)?,
        _ => {}
    }

    draw_status_bar(f, ui_state, connections.len(), chunks[2]);

    if ui_state.show_connection_modal {
        draw_connection_modal(
            f,
            ui_state,
            connections,
            app.get_dns_resolver().as_deref(),
            click_regions,
        )?;
    }

    Ok(())
}

fn draw_tabs(f: &mut Frame, ui_state: &UIState, area: Rect, click_regions: &mut ClickableRegions) {
    let titles = [
        "Overview",
        "Devices",
        "Services",
        "Interfaces",
        "Routes",
        "Graph",
        "Help",
    ];
    let tabs = Tabs::new(titles.to_vec())
        .divider("")
        .padding(" ", " ")
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(fg(muted())),
        )
        .select(ui_state.selected_tab)
        .style(fg(muted()))
        .highlight_style(fg(primary()).add_modifier(Modifier::REVERSED));

    f.render_widget(tabs, area);

    // Register click regions based on actual label widths (title + padding)
    let mut current_x = area.x + 1; // +1 for left border
    for (i, title) in titles.iter().enumerate() {
        let width = (title.len() + 2) as u16; // title + 2 spaces padding
        click_regions.register(
            Rect::new(current_x, area.y, width, 3),
            ClickAction::SwitchTab(i),
        );
        current_x += width;
    }
}

fn draw_loading_screen(f: &mut Frame) {
    let para = Paragraph::new("Loading network connections...").alignment(Alignment::Center);
    f.render_widget(para, f.area());
}

fn draw_filter_input(f: &mut Frame, ui_state: &UIState, area: Rect) {
    let block = panel_block(" Filter ").border_style(if ui_state.filter_mode {
        fg(warn())
    } else {
        fg(ok())
    });
    let mut query = ui_state.filter_query.clone();
    if ui_state.filter_mode {
        query.insert(ui_state.filter_cursor_position, '|');
    }
    f.render_widget(Paragraph::new(query).block(block), area);
}

fn draw_status_bar(f: &mut Frame, ui_state: &UIState, count: usize, area: Rect) {
    let status = if ui_state.quit_confirmation {
        " Press 'q' again to quit or any other key to cancel ".to_string()
    } else if ui_state.clear_confirmation {
        " Press 'x' again to clear all connections or any other key to cancel ".to_string()
    } else if let Some((ref msg, ref time)) = ui_state.clipboard_message {
        if time.elapsed().as_secs() < 3 {
            format!(" {} ", msg)
        } else {
            " 'h' help | Tab switch tabs | '/' filter | 'a' group | 't' history | 'c' copy "
                .to_string()
        }
    } else if !ui_state.filter_query.is_empty() {
        format!(
            " 'h' help | Tab switch tabs | Showing {} filtered connections (Esc to clear) ",
            count
        )
    } else {
        " 'h' help | Tab switch tabs | '/' filter | 'a' group | 't' history | 'c' copy ".to_string()
    };

    let style = if ui_state.quit_confirmation || ui_state.clear_confirmation {
        status_bar_confirm()
    } else {
        status_bar_default()
    };
    f.render_widget(Paragraph::new(status).style(style), area);
}

pub fn setup_terminal<B: ratatui::backend::Backend>(backend: B) -> Result<Terminal<B>>
where
    <B as ratatui::backend::Backend>::Error: Send + Sync + 'static,
{
    let terminal = ratatui::Terminal::new(backend)?;
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    Ok(terminal)
}

pub fn restore_terminal<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>) -> Result<()>
where
    <B as ratatui::backend::Backend>::Error: Send + Sync + 'static,
{
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

impl UIState {
    pub fn get_selected_index(
        &self,
        connections: &[crate::network::types::Connection],
    ) -> Option<usize> {
        self.selected_connection_key
            .as_ref()
            .and_then(|k| connections.iter().position(|c| c.key() == *k))
            .or(if connections.is_empty() {
                None
            } else {
                Some(0)
            })
    }
    pub fn set_selected_by_index(
        &mut self,
        connections: &[crate::network::types::Connection],
        index: usize,
    ) {
        if let Some(c) = connections.get(index) {
            self.selected_connection_key = Some(c.key());
        }
    }
    pub fn get_selected_service_index(
        &self,
        listeners: &[crate::network::types::Listener],
    ) -> Option<usize> {
        self.selected_service_key
            .as_ref()
            .and_then(|k| {
                listeners
                    .iter()
                    .position(|l| format!("{}:{}", l.protocol, l.local_addr) == *k)
            })
            .or(if listeners.is_empty() { None } else { Some(0) })
    }
    pub fn set_selected_service_by_index(
        &mut self,
        listeners: &[crate::network::types::Listener],
        index: usize,
    ) {
        if let Some(l) = listeners.get(index) {
            self.selected_service_key = Some(format!("{}:{}", l.protocol, l.local_addr));
        }
    }
    pub fn move_service_selection_up(&mut self, listeners: &[crate::network::types::Listener]) {
        let idx = self.get_selected_service_index(listeners).unwrap_or(0);
        self.set_selected_service_by_index(
            listeners,
            if idx > 0 {
                idx - 1
            } else {
                listeners.len().saturating_sub(1)
            },
        );
    }
    pub fn move_service_selection_down(&mut self, listeners: &[crate::network::types::Listener]) {
        let idx = self.get_selected_service_index(listeners).unwrap_or(0);
        self.set_selected_service_by_index(
            listeners,
            if idx < listeners.len().saturating_sub(1) {
                idx + 1
            } else {
                0
            },
        );
    }
    pub fn get_selected_device_index(
        &self,
        devices: &[crate::network::types::Device],
    ) -> Option<usize> {
        self.selected_device_mac
            .as_ref()
            .and_then(|m| devices.iter().position(|d| d.mac == *m))
            .or(if devices.is_empty() { None } else { Some(0) })
    }
    pub fn set_selected_device_by_index(
        &mut self,
        devices: &[crate::network::types::Device],
        index: usize,
    ) {
        if let Some(d) = devices.get(index) {
            self.selected_device_mac = Some(d.mac.clone());
        }
    }

    pub fn get_selected_interface_index(
        &self,
        stats: &[crate::network::interface_stats::InterfaceStats],
    ) -> Option<usize> {
        self.selected_interface
            .as_ref()
            .and_then(|name| stats.iter().position(|s| s.interface_name == *name))
            .or(if stats.is_empty() { None } else { Some(0) })
    }

    pub fn set_selected_interface_by_index(
        &mut self,
        stats: &[crate::network::interface_stats::InterfaceStats],
        index: usize,
    ) {
        if let Some(s) = stats.get(index) {
            self.selected_interface = Some(s.interface_name.clone());
        }
    }

    pub fn move_interface_selection_up(
        &mut self,
        stats: &[crate::network::interface_stats::InterfaceStats],
    ) {
        let idx = self.get_selected_interface_index(stats).unwrap_or(0);
        self.set_selected_interface_by_index(
            stats,
            if idx > 0 {
                idx - 1
            } else {
                stats.len().saturating_sub(1)
            },
        );
    }

    pub fn move_interface_selection_down(
        &mut self,
        stats: &[crate::network::interface_stats::InterfaceStats],
    ) {
        let idx = self.get_selected_interface_index(stats).unwrap_or(0);
        self.set_selected_interface_by_index(
            stats,
            if idx < stats.len().saturating_sub(1) {
                idx + 1
            } else {
                0
            },
        );
    }

    pub fn move_route_selection_up(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        let idx = self.selected_route_index.unwrap_or(0);
        self.selected_route_index = Some(if idx > 0 {
            idx - 1
        } else {
            count.saturating_sub(1)
        });
    }

    pub fn move_route_selection_down(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        let idx = self.selected_route_index.unwrap_or(0);
        self.selected_route_index = Some(if idx < count.saturating_sub(1) {
            idx + 1
        } else {
            0
        });
    }
    pub fn move_device_selection_up(&mut self, devices: &[crate::network::types::Device]) {
        let idx = self.get_selected_device_index(devices).unwrap_or(0);
        self.set_selected_device_by_index(
            devices,
            if idx > 0 {
                idx - 1
            } else {
                devices.len().saturating_sub(1)
            },
        );
    }
    pub fn move_device_selection_down(&mut self, devices: &[crate::network::types::Device]) {
        let idx = self.get_selected_device_index(devices).unwrap_or(0);
        self.set_selected_device_by_index(
            devices,
            if idx < devices.len().saturating_sub(1) {
                idx + 1
            } else {
                0
            },
        );
    }
    pub fn move_selection_up(&mut self, connections: &[crate::network::types::Connection]) {
        let idx = self.get_selected_index(connections).unwrap_or(0);
        self.set_selected_by_index(
            connections,
            if idx > 0 {
                idx - 1
            } else {
                connections.len().saturating_sub(1)
            },
        );
    }
    pub fn move_selection_down(&mut self, connections: &[crate::network::types::Connection]) {
        let idx = self.get_selected_index(connections).unwrap_or(0);
        self.set_selected_by_index(
            connections,
            if idx < connections.len().saturating_sub(1) {
                idx + 1
            } else {
                0
            },
        );
    }
    pub fn move_selection_page_up(
        &mut self,
        connections: &[crate::network::types::Connection],
        size: usize,
    ) {
        let idx = self.get_selected_index(connections).unwrap_or(0);
        self.set_selected_by_index(connections, idx.saturating_sub(size));
    }
    pub fn move_selection_page_down(
        &mut self,
        connections: &[crate::network::types::Connection],
        size: usize,
    ) {
        let idx = self.get_selected_index(connections).unwrap_or(0);
        self.set_selected_by_index(
            connections,
            (idx + size).min(connections.len().saturating_sub(1)),
        );
    }
    pub fn move_selection_to_first(&mut self, connections: &[crate::network::types::Connection]) {
        self.set_selected_by_index(connections, 0);
    }
    pub fn move_selection_to_last(&mut self, connections: &[crate::network::types::Connection]) {
        self.set_selected_by_index(connections, connections.len().saturating_sub(1));
    }
    pub fn ensure_valid_selection(&mut self, connections: &[crate::network::types::Connection]) {
        if (self.selected_connection_key.is_none()
            || self.get_selected_index(connections).is_none())
            && !connections.is_empty()
        {
            self.set_selected_by_index(connections, 0);
        }
    }
    pub fn enter_filter_mode(&mut self) {
        self.filter_mode = true;
        self.filter_cursor_position = self.filter_query.len();
    }
    pub fn exit_filter_mode(&mut self) {
        self.filter_mode = false;
    }
    pub fn clear_filter(&mut self) {
        self.filter_query.clear();
        self.exit_filter_mode();
    }
    pub fn filter_add_char(&mut self, c: char) {
        self.filter_query.insert(self.filter_cursor_position, c);
        self.filter_cursor_position += 1;
    }
    pub fn filter_backspace(&mut self) {
        if self.filter_cursor_position > 0 {
            self.filter_cursor_position -= 1;
            self.filter_query.remove(self.filter_cursor_position);
        }
    }
    pub fn filter_cursor_left(&mut self) {
        self.filter_cursor_position = self.filter_cursor_position.saturating_sub(1);
    }
    pub fn filter_cursor_right(&mut self) {
        if self.filter_cursor_position < self.filter_query.len() {
            self.filter_cursor_position += 1;
        }
    }
    pub fn cycle_sort_column(&mut self) {
        if self.selected_tab == 2 {
            self.service_sort_column = self.service_sort_column.next();
        } else if self.selected_tab == 1 {
            self.device_sort_column = self.device_sort_column.next();
        } else {
            self.sort_column = self.sort_column.next(self.has_geoip);
            self.sort_ascending = self.sort_column.default_direction();
        }
    }
    pub fn toggle_sort_direction(&mut self) {
        self.sort_ascending = !self.sort_ascending;
    }
    pub fn reset_view(&mut self) {
        self.grouping_enabled = false;
        self.service_grouping_enabled = false;
        self.expanded_groups.clear();
        self.service_expanded_groups.clear();
        self.selected_group = None;
        self.service_selected_group = None;
        self.sort_column = SortColumn::default();
        self.service_sort_column = ServiceSortColumn::default();
        self.device_sort_column = DeviceSortColumn::default();
        self.sort_ascending = true;
        self.filter_query.clear();
        self.filter_mode = false;
        self.show_historic = false;
    }
    pub fn toggle_grouping(&mut self) {
        if self.selected_tab == 2 {
            self.service_grouping_enabled = !self.service_grouping_enabled;
            if self.service_grouping_enabled {
                self.service_selected_group = None;
            }
        } else {
            self.grouping_enabled = !self.grouping_enabled;
            if self.grouping_enabled {
                self.selected_group = None;
            }
        }
    }
    pub fn toggle_group_expansion(&mut self) {
        if self.selected_tab == 2 {
            if let Some(ref g) = self.service_selected_group {
                if self.service_expanded_groups.contains(g) {
                    self.service_expanded_groups.remove(g);
                } else {
                    self.service_expanded_groups.insert(g.clone());
                }
            }
        } else {
            if let Some(ref g) = self.selected_group {
                if self.expanded_groups.contains(g) {
                    self.expanded_groups.remove(g);
                } else {
                    self.expanded_groups.insert(g.clone());
                }
            }
        }
    }
    pub fn expand_selected_group(&mut self) {
        if self.selected_tab == 2 {
            if let Some(ref g) = self.service_selected_group {
                self.service_expanded_groups.insert(g.clone());
            }
        } else {
            if let Some(ref g) = self.selected_group {
                self.expanded_groups.insert(g.clone());
            }
        }
    }
    pub fn collapse_selected_group(&mut self) {
        if self.selected_tab == 2 {
            if let Some(ref g) = self.service_selected_group {
                self.service_expanded_groups.remove(g);
            }
        } else {
            if let Some(ref g) = self.selected_group {
                self.expanded_groups.remove(g);
            }
        }
    }
    pub fn get_selected_grouped_index(&self, rows: &[GroupedRow]) -> Option<usize> {
        if rows.is_empty() {
            return None;
        }
        if let Some(ref k) = self.selected_connection_key
            && let Some(p) = rows.iter().position(|r| {
                if let GroupedRow::Connection { connection, .. } = r {
                    connection.key() == *k
                } else {
                    false
                }
            })
        {
            return Some(p);
        }
        if let Some(ref g) = self.selected_group
            && let Some(p) = rows.iter().position(|r| {
                if let GroupedRow::Group { process_name, .. } = r {
                    process_name == g
                } else {
                    false
                }
            })
        {
            return Some(p);
        }
        Some(0)
    }

    pub fn get_selected_service_grouped_index(&self, rows: &[ServiceGroupedRow]) -> Option<usize> {
        if rows.is_empty() {
            return None;
        }
        if let Some(ref k) = self.selected_service_key
            && let Some(p) = rows.iter().position(|r| {
                if let ServiceGroupedRow::Service { listener, .. } = r {
                    format!("{}:{}", listener.protocol, listener.local_addr) == *k
                } else {
                    false
                }
            })
        {
            return Some(p);
        }
        if let Some(ref g) = self.service_selected_group
            && let Some(p) = rows.iter().position(|r| {
                if let ServiceGroupedRow::Group { process_name, .. } = r {
                    process_name == g
                } else {
                    false
                }
            })
        {
            return Some(p);
        }
        Some(0)
    }

    pub fn set_selected_grouped_by_index(&mut self, rows: &[GroupedRow], index: usize) {
        if let Some(row) = rows.get(index) {
            match row {
                GroupedRow::Group { process_name, .. } => {
                    self.selected_group = Some(process_name.clone());
                    self.selected_connection_key = None;
                }
                GroupedRow::Connection {
                    process_name,
                    connection,
                    ..
                } => {
                    self.selected_connection_key = Some(connection.key());
                    self.selected_group = Some(process_name.clone());
                }
            }
        }
    }

    pub fn set_selected_service_grouped_by_index(&mut self, rows: &[ServiceGroupedRow], index: usize) {
        if let Some(row) = rows.get(index) {
            match row {
                ServiceGroupedRow::Group { process_name, .. } => {
                    self.service_selected_group = Some(process_name.clone());
                    self.selected_service_key = None;
                }
                ServiceGroupedRow::Service {
                    process_name,
                    listener,
                    ..
                } => {
                    self.selected_service_key = Some(format!("{}:{}", listener.protocol, listener.local_addr));
                    self.service_selected_group = Some(process_name.clone());
                }
            }
        }
    }

    pub fn move_selection_up_grouped(&mut self, rows: &[GroupedRow]) {
        let idx = self.get_selected_grouped_index(rows).unwrap_or(0);
        self.set_selected_grouped_by_index(
            rows,
            if idx > 0 {
                idx - 1
            } else {
                rows.len().saturating_sub(1)
            },
        );
    }

    pub fn move_service_selection_up_grouped(&mut self, rows: &[ServiceGroupedRow]) {
        let idx = self.get_selected_service_grouped_index(rows).unwrap_or(0);
        self.set_selected_service_grouped_by_index(
            rows,
            if idx > 0 {
                idx - 1
            } else {
                rows.len().saturating_sub(1)
            },
        );
    }

    pub fn move_selection_down_grouped(&mut self, rows: &[GroupedRow]) {
        let idx = self.get_selected_grouped_index(rows).unwrap_or(0);
        self.set_selected_grouped_by_index(
            rows,
            if idx < rows.len().saturating_sub(1) {
                idx + 1
            } else {
                0
            },
        );
    }

    pub fn move_service_selection_down_grouped(&mut self, rows: &[ServiceGroupedRow]) {
        let idx = self.get_selected_service_grouped_index(rows).unwrap_or(0);
        self.set_selected_service_grouped_by_index(
            rows,
            if idx < rows.len().saturating_sub(1) {
                idx + 1
            } else {
                0
            },
        );
    }

    pub fn move_selection_page_up_grouped(&mut self, rows: &[GroupedRow], size: usize) {
        let idx = self.get_selected_grouped_index(rows).unwrap_or(0);
        self.set_selected_grouped_by_index(rows, idx.saturating_sub(size));
    }

    pub fn move_selection_page_down_grouped(&mut self, rows: &[GroupedRow], size: usize) {
        let idx = self.get_selected_grouped_index(rows).unwrap_or(0);
        self.set_selected_grouped_by_index(rows, (idx + size).min(rows.len().saturating_sub(1)));
    }

    pub fn ensure_valid_grouped_selection(&mut self, rows: &[GroupedRow]) {
        if (self.selected_group.is_none() || self.get_selected_grouped_index(rows).is_none())
            && !rows.is_empty()
        {
            self.set_selected_grouped_by_index(rows, 0);
        }
    }

    pub fn ensure_valid_service_selection(&mut self, listeners: &[crate::network::types::Listener]) {
        if (self.selected_service_key.is_none() || self.get_selected_service_index(listeners).is_none())
            && !listeners.is_empty()
        {
            self.set_selected_service_by_index(listeners, 0);
        }
    }

    pub fn ensure_valid_service_grouped_selection(&mut self, rows: &[ServiceGroupedRow]) {
        if (self.service_selected_group.is_none() || self.get_selected_service_grouped_index(rows).is_none())
            && !rows.is_empty()
        {
            self.set_selected_service_grouped_by_index(rows, 0);
        }
    }

    pub fn ensure_valid_device_selection(&mut self, devices: &[crate::network::types::Device]) {
        if (self.selected_device_mac.is_none() || self.get_selected_device_index(devices).is_none())
            && !devices.is_empty()
        {
            self.set_selected_device_by_index(devices, 0);
        }
    }

    pub fn is_group_selected(&self) -> bool {
        self.selected_group.is_some() && self.selected_connection_key.is_none()
    }

    pub fn is_service_group_selected(&self) -> bool {
        self.service_selected_group.is_some() && self.selected_service_key.is_none()
    }
}

pub fn compute_grouped_rows<'a>(
    connections: &'a [crate::network::types::Connection],
    expanded: &HashSet<String>,
) -> Vec<GroupedRow<'a>> {
    use std::collections::HashMap;
    let mut groups: HashMap<String, Vec<&crate::network::types::Connection>> = HashMap::new();
    for c in connections {
        let k = c
            .process_name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());
        groups.entry(k).or_default().push(c);
    }
    let mut stats: Vec<(
        String,
        ProcessGroupStats,
        Vec<&crate::network::types::Connection>,
    )> = groups
        .into_iter()
        .map(|(name, conns)| {
            let mut s = ProcessGroupStats::default();
            for c in &conns {
                if c.is_historic {
                    s.historic_count += 1;
                } else {
                    s.connection_count += 1;
                    if c.protocol == crate::network::types::Protocol::Tcp {
                        s.tcp_count += 1;
                    } else if c.protocol == crate::network::types::Protocol::Udp {
                        s.udp_count += 1;
                    }
                    s.total_incoming_rate_bps += c.current_incoming_rate_bps;
                    s.total_outgoing_rate_bps += c.current_outgoing_rate_bps;
                }
            }
            (name, s, conns)
        })
        .collect();
    stats.sort_by_key(|a| a.0.to_lowercase());
    let mut rows = Vec::new();
    for (name, s, conns) in stats {
        let exp = expanded.contains(&name);
        rows.push(GroupedRow::Group {
            process_name: name.clone(),
            stats: s,
            expanded: exp,
        });
        if exp {
            let count = conns.len();
            for (i, c) in conns.into_iter().enumerate() {
                rows.push(GroupedRow::Connection {
                    process_name: name.clone(),
                    connection: c,
                    is_last_in_group: i == count - 1,
                });
            }
        }
    }
    rows
}

pub fn compute_service_grouped_rows<'a>(
    listeners: &'a [crate::network::types::Listener],
    expanded: &HashSet<String>,
) -> Vec<ServiceGroupedRow<'a>> {
    use std::collections::HashMap;
    let mut groups: HashMap<String, Vec<&crate::network::types::Listener>> = HashMap::new();
    for l in listeners {
        let k = l
            .process_name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());
        groups.entry(k).or_default().push(l);
    }
    let mut stats: Vec<(
        String,
        ServiceProcessGroupStats,
        Vec<&crate::network::types::Listener>,
    )> = groups
        .into_iter()
        .map(|(name, listeners)| {
            let mut s = ServiceProcessGroupStats::default();
            s.listener_count = listeners.len();
            for l in &listeners {
                s.total_active_connections += l.active_connections;
            }
            (name, s, listeners)
        })
        .collect();
    stats.sort_by_key(|a| a.0.to_lowercase());
    let mut rows = Vec::new();
    for (name, s, listeners) in stats {
        let exp = expanded.contains(&name);
        rows.push(ServiceGroupedRow::Group {
            process_name: name.clone(),
            stats: s,
            expanded: exp,
        });
        if exp {
            let count = listeners.len();
            for (i, l) in listeners.into_iter().enumerate() {
                rows.push(ServiceGroupedRow::Service {
                    process_name: name.clone(),
                    listener: l,
                    is_last_in_group: i == count - 1,
                });
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::interface_stats::InterfaceStats;
    use std::time::SystemTime;

    fn mock_stats(names: Vec<&str>) -> Vec<InterfaceStats> {
        names
            .into_iter()
            .map(|name| InterfaceStats {
                interface_name: name.to_string(),
                description: None,
                mac_address: None,
                ipv4: Vec::new(),
                ipv6: Vec::new(),
                mtu: None,
                operstate: None,
                flags: None,
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_errors: 0,
                tx_errors: 0,
                rx_dropped: 0,
                tx_dropped: 0,
                collisions: 0,
                timestamp: SystemTime::now(),
            })
            .collect()
    }

    #[test]
    fn test_interface_selection_by_name() {
        let mut ui_state = UIState::default();
        let stats = mock_stats(vec!["eth0", "lo", "wlan0"]);

        // Select "lo" by index 1
        ui_state.set_selected_interface_by_index(&stats, 1);
        assert_eq!(ui_state.selected_interface.as_deref(), Some("lo"));
        assert_eq!(ui_state.get_selected_interface_index(&stats), Some(1));

        // Now if the list is re-ordered (e.g. "lo" comes first)
        let reordered_stats = mock_stats(vec!["lo", "eth0", "wlan0"]);
        // It should still correctly find "lo" at index 0
        assert_eq!(
            ui_state.get_selected_interface_index(&reordered_stats),
            Some(0)
        );
    }

    #[test]
    fn test_interface_selection_movement() {
        let mut ui_state = UIState::default();
        let stats = mock_stats(vec!["eth0", "lo", "wlan0"]);

        // Default selection is index 0 ("eth0")
        assert_eq!(ui_state.get_selected_interface_index(&stats), Some(0));

        // Move down to "lo"
        ui_state.move_interface_selection_down(&stats);
        assert_eq!(ui_state.selected_interface.as_deref(), Some("lo"));
        assert_eq!(ui_state.get_selected_interface_index(&stats), Some(1));

        // Move down to "wlan0"
        ui_state.move_interface_selection_down(&stats);
        assert_eq!(ui_state.selected_interface.as_deref(), Some("wlan0"));

        // Wrap around to "eth0"
        ui_state.move_interface_selection_down(&stats);
        assert_eq!(ui_state.selected_interface.as_deref(), Some("eth0"));

        // Move up to "wlan0"
        ui_state.move_interface_selection_up(&stats);
        assert_eq!(ui_state.selected_interface.as_deref(), Some("wlan0"));
    }
}
