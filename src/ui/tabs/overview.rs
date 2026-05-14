use ratatui::prelude::*;
use ratatui::widgets::{Cell, Row, Table};
use crate::app::App;
use crate::app::state::sort_connections;
use crate::network::types::{Connection, Protocol, ProtocolState, TcpState};
use crate::ui::{UIState, ClickableRegions, GroupedRow, SortColumn, ClickAction};
use crate::ui::theme::{theme, style_if_colored};
use crate::ui::components::panel_block;
use crate::ui::utils::format_rate;

pub fn draw_overview(
    f: &mut Frame,
    app: &App,
    ui_state: &UIState,
    connections: &[Connection],
    grouped_rows: Option<&[GroupedRow]>,
    area: Rect,
    click_regions: &mut ClickableRegions,
) -> anyhow::Result<()> {
    if let Some(grouped) = grouped_rows {
        draw_grouped_connections_list(f, ui_state, grouped, area, click_regions);
    } else {
        draw_connections_list(f, ui_state, connections, area, click_regions);
    }
    Ok(())
}

fn status_indicator_cell(conn: &Connection) -> Cell {
    let staleness = conn.staleness_ratio();
    let (icon, color) = if conn.is_historic {
        ("●", theme::muted())
    } else if staleness >= 0.90 {
        ("●", theme::err())
    } else if staleness >= 0.75 {
        ("●", theme::warn())
    } else {
        ("●", theme::ok())
    };

    Cell::from(Span::styled(icon, style_if_colored(theme::fg(color))))
}

fn dpi_color(app_proto: &crate::network::types::ApplicationProtocol) -> Color {
    use crate::network::types::ApplicationProtocol;
    match app_proto {
        ApplicationProtocol::Https(_) => theme::proto_https(),
        ApplicationProtocol::Quic(_) => theme::proto_quic(),
        ApplicationProtocol::Http(_) => theme::proto_http(),
        ApplicationProtocol::Dns(_) => theme::proto_dns(),
        ApplicationProtocol::Ssh(_) => theme::proto_ssh(),
        _ => theme::proto_other(),
    }
}

fn state_color(conn: &Connection) -> Color {
    match conn.protocol {
        Protocol::Tcp => {
            if let ProtocolState::Tcp(state) = &conn.protocol_state {
                match state {
                    TcpState::Established => theme::tcp_established(),
                    TcpState::SynSent | TcpState::SynReceived => theme::tcp_opening(),
                    TcpState::FinWait1 | TcpState::FinWait2 | TcpState::TimeWait => {
                        theme::tcp_closing()
                    }
                    TcpState::CloseWait | TcpState::LastAck | TcpState::Closing => {
                        theme::tcp_waiting()
                    }
                    TcpState::Closed => theme::tcp_closed(),
                    TcpState::Unknown => Color::Reset,
                }
            } else {
                Color::Reset
            }
        }
        Protocol::Udp => Color::Cyan,
        Protocol::Icmp | Protocol::Icmpv6 => Color::Magenta,
        Protocol::Arp => Color::Yellow,
        _ => Color::Reset,
    }
}

fn draw_connections_list(
    f: &mut Frame,
    ui_state: &UIState,
    connections: &[Connection],
    area: Rect,
    click_regions: &mut ClickableRegions,
) {
    let show_location = ui_state.has_geoip;

    let header_cells = vec![
        Cell::from(""),
        Cell::from(" Proto"),
        Cell::from(" Local Address"),
        Cell::from(" Remote Address"),
    ];
    let mut header_cells = if show_location {
        let mut v = header_cells;
        v.push(Cell::from(" Location"));
        v
    } else {
        header_cells
    };
    header_cells.extend([
        Cell::from(" State"),
        Cell::from(" Service"),
        Cell::from(" Application"),
        Cell::from(Line::from("Bandwidth Total").right_aligned()),
        Cell::from(" Process"),
    ]);

    let header = Row::new(header_cells)
        .style(theme::fg(theme::heading()))
        .height(1);

    let mut widths = vec![
        Constraint::Length(1),  // Status dot
        Constraint::Length(7),  // Proto
        Constraint::Length(25), // Local
        Constraint::Length(25), // Remote
    ];
    if show_location {
        widths.push(Constraint::Length(15));
    }
    widths.extend([
        Constraint::Length(12), // State
        Constraint::Length(15), // Service
        Constraint::Length(15), // App
        Constraint::Length(18), // BW
        Constraint::Min(20),    // Process
    ]);

    // Virtualization: only build Row objects for the visible window
    let scroll_offset = ui_state.scroll_offset;
    let visible_rows = ui_state.visible_rows.max(1);
    let window_end = (scroll_offset + visible_rows + 1).min(connections.len());
    let visible_connections = &connections[scroll_offset.min(connections.len())..window_end];

    let rows: Vec<Row> = visible_connections
        .iter()
        .map(|conn| {
            let local_addr_display = if ui_state.show_hostnames && let Some(hostname) = app_get_hostname(conn.local_addr.ip()) {
                if ui_state.show_port_numbers { format!("{}:{}", hostname, conn.local_addr.port()) } else { hostname }
            } else if ui_state.show_port_numbers { conn.local_addr.to_string() } else { conn.local_addr.ip().to_string() };

            let remote_addr_display = if ui_state.show_hostnames && let Some(hostname) = app_get_hostname(conn.remote_addr.ip()) {
                if ui_state.show_port_numbers { format!("{}:{}", hostname, conn.remote_addr.port()) } else { hostname }
            } else if ui_state.show_port_numbers { conn.remote_addr.to_string() } else { conn.remote_addr.ip().to_string() };

            let state = conn.state();
            let service_display = conn.service_name.as_deref().unwrap_or("-");
            let (dpi_display, dpi_cell_color) = if let Some(dpi) = &conn.dpi_info {
                (dpi.application.to_string(), dpi_color(&dpi.application))
            } else {
                ("-".to_string(), Color::Reset)
            };

            let location_display = if let Some(ref geo) = conn.geoip_info {
                geo.country_code.as_deref().unwrap_or("-")
            } else {
                "-"
            };

            let incoming_rate = format_rate(conn.current_incoming_rate_bps);
            let outgoing_rate = format_rate(conn.current_outgoing_rate_bps);

            let bandwidth_cell = Cell::from(
                Line::from(format!("{}↓/{}↑", incoming_rate, outgoing_rate))
                    .right_aligned(),
            );

            let mut cells = vec![
                status_indicator_cell(conn),
                Cell::from(conn.protocol.to_string()),
                Cell::from(local_addr_display).style(style_if_colored(theme::field_local_addr())),
                Cell::from(remote_addr_display).style(style_if_colored(theme::field_remote_addr())),
            ];
            if show_location {
                cells.push(Cell::from(location_display).style(style_if_colored(theme::field_location())));
            }
            cells.extend([
                Cell::from(state).style(style_if_colored(state_color(conn))),
                Cell::from(service_display).style(style_if_colored(theme::field_service())),
                Cell::from(dpi_display).style(style_if_colored(dpi_cell_color)),
                bandwidth_cell,
                Cell::from(conn.process_name.as_deref().unwrap_or("-")).style(style_if_colored(theme::field_process())),
            ]);

            Row::new(cells)
        })
        .collect();

    let mut state = ratatui::widgets::TableState::default();
    if let Some(selected_index) = ui_state.get_selected_index(connections) {
        state.select(Some(selected_index.saturating_sub(scroll_offset)));
    }

    let history_suffix = if ui_state.show_historic { " + Historic" } else { "" };
    let table_title = if ui_state.sort_column != SortColumn::CreatedAt {
        let direction = if ui_state.sort_ascending { "↑" } else { "↓" };
        format!(" Connections ({}){} │ Sorted by: {} {}", connections.len(), history_suffix, ui_state.sort_column.display_name(), direction)
    } else {
        format!(" Connections ({}){} │ Sorted by: Time ↑", connections.len(), history_suffix)
    };

    let table = Table::new(rows, &widths)
        .header(header)
        .block(panel_block(table_title))
        .row_highlight_style(theme::row_highlight())
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut state);

    click_regions.scroll_area = Some(area);
    let inner = area.inner(Margin { horizontal: 1, vertical: 1 });
    let header_height = 2_u16;
    let visible_start_y = inner.y + header_height;
    let max_visible_rows = inner.height.saturating_sub(header_height) as usize;

    for i in 0..max_visible_rows {
        let conn_idx = scroll_offset + i;
        if conn_idx >= connections.len() { break; }
        let row_y = visible_start_y + i as u16;
        let row_rect = Rect::new(inner.x, row_y, inner.width, 1);
        click_regions.register(row_rect, ClickAction::SelectConnection(conn_idx));
    }
}

fn draw_grouped_connections_list(
    f: &mut Frame,
    ui_state: &UIState,
    grouped_rows: &[GroupedRow],
    area: Rect,
    click_regions: &mut ClickableRegions,
) {
    let show_location = ui_state.has_geoip;
    let header_cells = vec![
        Cell::from(""),
        Cell::from(" Proto"),
        Cell::from(" Local Address"),
        Cell::from(" Remote Address"),
    ];
    let mut header_cells = if show_location {
        let mut v = header_cells;
        v.push(Cell::from(" Location"));
        v
    } else {
        header_cells
    };
    header_cells.extend([
        Cell::from(" State"),
        Cell::from(" Service"),
        Cell::from(" Application"),
        Cell::from(Line::from("Bandwidth Total").right_aligned()),
    ]);

    let header = Row::new(header_cells).style(theme::fg(theme::heading())).height(1);

    let mut widths = vec![
        Constraint::Length(1),
        Constraint::Length(7),
        Constraint::Length(25),
        Constraint::Length(25),
    ];
    if show_location { widths.push(Constraint::Length(15)); }
    widths.extend([
        Constraint::Length(12),
        Constraint::Length(15),
        Constraint::Length(15),
        Constraint::Min(18),
    ]);

    let scroll_offset = ui_state.grouped_scroll_offset;
    let visible_rows = ui_state.visible_rows.max(1);
    let window_end = (scroll_offset + visible_rows + 1).min(grouped_rows.len());
    let visible_rows_slice = &grouped_rows[scroll_offset.min(grouped_rows.len())..window_end];

    let rows: Vec<Row> = visible_rows_slice
        .iter()
        .map(|row| {
            match row {
                GroupedRow::Group { name, count, total_rx, total_tx, expanded, .. } => {
                    let icon = if *expanded { "▼" } else { "▶" };
                    let cells = vec![
                        Cell::from(Span::styled(icon, theme::fg(theme::heading()))),
                        Cell::from(Span::styled(format!("Process: {}", name), theme::bold_fg(theme::field_process()))),
                        Cell::from(""),
                        Cell::from(""),
                    ];
                    let mut cells = if show_location {
                        let mut v = cells; v.push(Cell::from("")); v
                    } else {
                        cells
                    };
                    cells.extend([
                        Cell::from(""),
                        Cell::from(""),
                        Cell::from(Span::styled(format!("{} connections", count), theme::fg(theme::muted()))),
                        Cell::from(Line::from(format!("{}↓/{}↑", format_rate(*total_rx), format_rate(*total_tx))).right_aligned().style(theme::fg(theme::accent()))),
                    ]);
                    Row::new(cells).style(Style::default().bg(Color::Rgb(30, 34, 42)))
                }
                GroupedRow::Connection { connection, .. } => {
                    let local_addr_display = if ui_state.show_port_numbers { connection.local_addr.to_string() } else { connection.local_addr.ip().to_string() };
                    let remote_addr_display = if ui_state.show_port_numbers { connection.remote_addr.to_string() } else { connection.remote_addr.ip().to_string() };
                    let state = connection.state();
                    let service_display = connection.service_name.as_deref().unwrap_or("-");
                    let (dpi_display, dpi_cell_color) = if let Some(dpi) = &connection.dpi_info {
                        (dpi.application.to_string(), dpi_color(&dpi.application))
                    } else {
                        ("-".to_string(), Color::Reset)
                    };
                    let location_display = if let Some(ref geo) = connection.geoip_info {
                        geo.country_code.as_deref().unwrap_or("-")
                    } else {
                        "-"
                    };
                    let incoming_rate = format_rate(connection.current_incoming_rate_bps);
                    let outgoing_rate = format_rate(connection.current_outgoing_rate_bps);

                    let mut cells = vec![
                        status_indicator_cell(connection),
                        Cell::from(connection.protocol.to_string()),
                        Cell::from(local_addr_display).style(style_if_colored(theme::field_local_addr())),
                        Cell::from(remote_addr_display).style(style_if_colored(theme::field_remote_addr())),
                    ];
                    if show_location {
                        cells.push(Cell::from(location_display).style(style_if_colored(theme::field_location())));
                    }
                    cells.extend([
                        Cell::from(state).style(style_if_colored(state_color(connection))),
                        Cell::from(service_display).style(style_if_colored(theme::field_service())),
                        Cell::from(dpi_display).style(style_if_colored(dpi_cell_color)),
                        Cell::from(Line::from(format!("{}↓/{}↑", incoming_rate, outgoing_rate)).right_aligned()),
                    ]);
                    Row::new(cells)
                }
            }
        })
        .collect();

    let mut state = ratatui::widgets::TableState::default();
    if let Some(selected_index) = ui_state.get_selected_grouped_index(grouped_rows) {
        state.select(Some(selected_index.saturating_sub(scroll_offset)));
    }

    let history_suffix = if ui_state.show_historic { " + Historic" } else { "" };
    let table_title = format!("Grouped by Process (A-Z){} │ Connections: {}", history_suffix, ui_state.sort_column.display_name());

    let connections_table = Table::new(rows, &widths)
        .header(header)
        .block(panel_block(table_title))
        .row_highlight_style(theme::row_highlight())
        .highlight_symbol("> ");

    f.render_stateful_widget(connections_table, area, &mut state);

    click_regions.scroll_area = Some(area);
    let inner = area.inner(Margin { horizontal: 1, vertical: 1 });
    let header_height = 2_u16;
    let visible_start_y = inner.y + header_height;
    let max_visible_rows = inner.height.saturating_sub(header_height) as usize;

    for i in 0..max_visible_rows {
        let row_idx = scroll_offset + i;
        if row_idx >= grouped_rows.len() { break; }
        let row_y = visible_start_y + i as u16;
        let row_rect = Rect::new(inner.x, row_y, inner.width, 1);
        click_regions.register(row_rect, ClickAction::SelectConnection(row_idx));
    }
}

// Dummy helper - will be properly linked
fn app_get_hostname(_ip: std::net::IpAddr) -> Option<String> { None }
