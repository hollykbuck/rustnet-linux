use crate::app::{App, AppStats};
use crate::network::types::{
    ApplicationProtocol, Connection, Device, Protocol, ProtocolState, TcpState,
};
use crate::ui::*;
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

pub fn draw_overview(
    f: &mut Frame,
    app: &App,
    ui_state: &UIState,
    connections: &[Connection],
    grouped_rows: Option<&[GroupedRow]>,
    devices: &[Device],
    stats: &AppStats,
    area: Rect,
    click_regions: &mut ClickableRegions,
) -> anyhow::Result<()> {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(75), Constraint::Percentage(25)])
        .split(area);

    let (has_country_db, _, _) = app.get_geoip_status();
    let dns_resolver = app.get_dns_resolver();

    if let Some(grouped) = grouped_rows {
        draw_grouped_connections_list(
            f,
            ui_state,
            grouped,
            devices,
            chunks[0],
            dns_resolver.as_deref(),
            has_country_db,
            click_regions,
        );
    } else {
        draw_connections_list(
            f,
            ui_state,
            connections,
            devices,
            chunks[0],
            dns_resolver.as_deref(),
            has_country_db,
            click_regions,
        );
    }

    draw_stats_panel(f, connections, stats, app, chunks[1])?;

    Ok(())
}

fn status_indicator_cell(conn: &Connection) -> Cell<'_> {
    let staleness = conn.staleness_ratio();
    let (icon, color) = if conn.is_historic {
        ("●", muted())
    } else if staleness >= 0.90 {
        ("●", err())
    } else if staleness >= 0.75 {
        ("●", warn())
    } else {
        ("●", ok())
    };

    Cell::from(Span::styled(icon, style_if_colored(fg(color))))
}

fn dpi_color(app_proto: &ApplicationProtocol) -> Color {
    match app_proto {
        ApplicationProtocol::Https(_) => proto_https(),
        ApplicationProtocol::Quic(_) => proto_quic(),
        ApplicationProtocol::Http(_) => proto_http(),
        ApplicationProtocol::Dns(_) => proto_dns(),
        ApplicationProtocol::Ssh(_) => proto_ssh(),
        _ => proto_other(),
    }
}

fn state_color(conn: &Connection) -> Color {
    match conn.protocol {
        Protocol::Tcp => {
            if let ProtocolState::Tcp(state) = &conn.protocol_state {
                match state {
                    TcpState::Established => tcp_established(),
                    TcpState::SynSent | TcpState::SynReceived => tcp_opening(),
                    TcpState::FinWait1 | TcpState::FinWait2 | TcpState::TimeWait => tcp_closing(),
                    TcpState::CloseWait | TcpState::LastAck | TcpState::Closing => tcp_waiting(),
                    TcpState::Closed => tcp_closed(),
                    TcpState::Unknown => Color::Reset,
                }
            } else {
                Color::Reset
            }
        }
        Protocol::Udp => Color::Cyan,
        Protocol::Icmp => Color::Magenta,
        Protocol::Arp => Color::Yellow,
        _ => Color::Reset,
    }
}

fn bandwidth_line<'a>(incoming: String, outgoing: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(incoming, fg(rx())),
        Span::styled("↓", fg(rx())),
        Span::raw("/"),
        Span::styled(outgoing, fg(tx())),
        Span::styled("↑", fg(tx())),
    ])
    .right_aligned()
}

fn draw_connections_list(
    f: &mut Frame,
    ui_state: &UIState,
    connections: &[Connection],
    devices: &[Device],
    area: Rect,
    dns_resolver: Option<&crate::network::dns::DnsResolver>,
    show_location: bool,
    click_regions: &mut ClickableRegions,
) {
    let mut widths = vec![
        Constraint::Length(1),
        Constraint::Length(6),
        Constraint::Length(22),
        Constraint::Length(22),
    ];
    if show_location {
        widths.push(Constraint::Length(5));
    }
    widths.extend([
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(20),
        Constraint::Length(16),
        Constraint::Min(20),
    ]);

    let header_style = fg(heading());
    let mut header_cells = vec![
        Cell::from(""),
        Cell::from("Proto"),
        Cell::from("Local Address"),
        Cell::from("Remote Address"),
    ];
    if show_location {
        header_cells.push(Cell::from("Loc"));
    }
    header_cells.extend([
        Cell::from("State"),
        Cell::from("Service"),
        Cell::from("Application"),
        Cell::from(Line::from("Bandwidth").right_aligned()),
        Cell::from("Process"),
    ]);

    let header = Row::new(header_cells)
        .style(header_style)
        .height(1)
        .bottom_margin(1);

    let scroll_offset = ui_state.scroll_offset;
    let visible_rows = ui_state.visible_rows.max(1);
    let window_end = (scroll_offset + visible_rows + 1).min(connections.len());
    let visible_connections = &connections[scroll_offset.min(connections.len())..window_end];

    let rows: Vec<Row> = visible_connections
        .iter()
        .map(|conn| {
            let local_name = if ui_state.show_hostnames {
                devices
                    .iter()
                    .find(|d| d.ips.contains(&conn.local_addr.ip()))
                    .and_then(|d| d.hostname.clone())
                    .or_else(|| dns_resolver.and_then(|r| r.get_hostname(&conn.local_addr.ip())))
            } else {
                None
            };

            let local_addr = if let Some(h) = local_name {
                if ui_state.show_port_numbers {
                    format!("{}:{}", h, conn.local_addr.port())
                } else {
                    h
                }
            } else if ui_state.show_port_numbers {
                conn.local_addr.to_string()
            } else {
                conn.local_addr.ip().to_string()
            };

            let remote_name = if ui_state.show_hostnames {
                devices
                    .iter()
                    .find(|d| d.ips.contains(&conn.remote_addr.ip()))
                    .and_then(|d| d.hostname.clone())
                    .or_else(|| dns_resolver.and_then(|r| r.get_hostname(&conn.remote_addr.ip())))
            } else {
                None
            };

            let remote_addr = if let Some(h) = remote_name {
                if ui_state.show_port_numbers {
                    format!("{}:{}", h, conn.remote_addr.port())
                } else {
                    h
                }
            } else if ui_state.show_port_numbers {
                conn.remote_addr.to_string()
            } else {
                conn.remote_addr.ip().to_string()
            };

            let incoming_rate = format_rate_compact(conn.current_incoming_rate_bps);
            let outgoing_rate = format_rate_compact(conn.current_outgoing_rate_bps);

            let mut cells = vec![
                status_indicator_cell(conn),
                Cell::from(conn.protocol.to_string()).style(fg(muted())),
                Cell::from(local_addr).style(style_if_colored(field_local_addr())),
                Cell::from(remote_addr).style(style_if_colored(field_remote_addr())),
            ];
            if show_location {
                let loc = conn
                    .geoip_info
                    .as_ref()
                    .and_then(|g| g.country_code.as_deref())
                    .unwrap_or("-");
                cells.push(Cell::from(loc).style(style_if_colored(field_location())));
            }
            cells.extend([
                Cell::from(conn.state()).style(style_if_colored(fg(state_color(conn)))),
                Cell::from(conn.service_name.as_deref().unwrap_or(NONE_PLACEHOLDER))
                    .style(style_if_colored(field_service())),
                Cell::from(
                    conn.dpi_info
                        .as_ref()
                        .map(|d| d.application.to_string())
                        .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
                )
                .style(style_if_colored(fg(conn
                    .dpi_info
                    .as_ref()
                    .map(|d| dpi_color(&d.application))
                    .unwrap_or(Color::Reset)))),
                Cell::from(bandwidth_line(incoming_rate, outgoing_rate)),
                Cell::from(conn.process_name.as_deref().unwrap_or(NONE_PLACEHOLDER))
                    .style(style_if_colored(field_process())),
            ]);

            Row::new(cells)
        })
        .collect();

    let mut state = ratatui::widgets::TableState::default();
    if let Some(idx) = ui_state.get_selected_index(connections) {
        state.select(Some(idx.saturating_sub(scroll_offset)));
    }

    let title = format!(" Connections ({}) ", connections.len());
    let table = Table::new(rows, [Constraint::Min(0); 10]) // Simplified widths for now
        .header(header)
        .block(panel_block(title))
        .row_highlight_style(row_highlight())
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut state);

    let inner = area.inner(Margin {
        horizontal: 1,
        vertical: 1,
    });
    let header_height = 2_u16;
    for i in 0..(inner.height.saturating_sub(header_height) as usize) {
        let idx = scroll_offset + i;
        if idx >= connections.len() {
            break;
        }
        click_regions.register(
            Rect::new(inner.x, inner.y + header_height + i as u16, inner.width, 1),
            ClickAction::SelectConnection(idx),
        );
    }
}

fn draw_grouped_connections_list(
    f: &mut Frame,
    ui_state: &UIState,
    grouped_rows: &[GroupedRow],
    devices: &[Device],
    area: Rect,
    dns_resolver: Option<&crate::network::dns::DnsResolver>,
    show_location: bool,
    _click_regions: &mut ClickableRegions,
) {
    let widths = [Constraint::Min(0); 10]; // Simplified widths for now
    let rows: Vec<Row> = grouped_rows
        .iter()
        .map(|row| match row {
            GroupedRow::Group {
                process_name,
                stats,
                expanded,
            } => {
                let indicator = if *expanded { "▼" } else { "▶" };
                let mut cells = vec![
                    Cell::from(""),
                    Cell::from(Line::from(vec![
                        Span::styled(format!("{} {}", indicator, process_name), bold_fg(accent())),
                        Span::raw(format!(" ({})", stats.connection_count)),
                    ])),
                    Cell::from(""),
                    Cell::from(""),
                ];
                if show_location {
                    cells.push(Cell::from(""));
                }
                cells.extend([
                    Cell::from(format!("TCP:{} UDP:{}", stats.tcp_count, stats.udp_count))
                        .style(fg(muted())),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(bandwidth_line(
                        format_rate_compact(stats.total_incoming_rate_bps),
                        format_rate_compact(stats.total_outgoing_rate_bps),
                    )),
                ]);
                Row::new(cells).style(Style::default().bg(Color::Rgb(30, 34, 42)))
            }
            GroupedRow::Connection {
                connection,
                is_last_in_group,
                ..
            } => {
                let prefix = if *is_last_in_group {
                    "  └── "
                } else {
                    "  ├── "
                };

                let local_name = if ui_state.show_hostnames {
                    devices
                        .iter()
                        .find(|d| d.ips.contains(&connection.local_addr.ip()))
                        .and_then(|d| d.hostname.clone())
                        .or_else(|| {
                            dns_resolver.and_then(|r| r.get_hostname(&connection.local_addr.ip()))
                        })
                } else {
                    None
                };

                let local_addr = if let Some(h) = local_name {
                    if ui_state.show_port_numbers {
                        format!("{}:{}", h, connection.local_addr.port())
                    } else {
                        h
                    }
                } else if ui_state.show_port_numbers {
                    connection.local_addr.to_string()
                } else {
                    connection.local_addr.ip().to_string()
                };

                let remote_name = if ui_state.show_hostnames {
                    devices
                        .iter()
                        .find(|d| d.ips.contains(&connection.remote_addr.ip()))
                        .and_then(|d| d.hostname.clone())
                        .or_else(|| {
                            dns_resolver.and_then(|r| r.get_hostname(&connection.remote_addr.ip()))
                        })
                } else {
                    None
                };

                let remote_addr = if let Some(h) = remote_name {
                    if ui_state.show_port_numbers {
                        format!("{}:{}", h, connection.remote_addr.port())
                    } else {
                        h
                    }
                } else if ui_state.show_port_numbers {
                    connection.remote_addr.to_string()
                } else {
                    connection.remote_addr.ip().to_string()
                };

                let mut cells = vec![
                    status_indicator_cell(connection),
                    Cell::from(Line::from(vec![
                        Span::styled(prefix, fg(muted())),
                        Span::raw(connection.protocol.to_string()),
                    ])),
                    Cell::from(local_addr).style(style_if_colored(field_local_addr())),
                    Cell::from(remote_addr).style(style_if_colored(field_remote_addr())),
                ];
                if show_location {
                    cells.push(Cell::from("-"));
                }
                cells.extend([
                    Cell::from(connection.state())
                        .style(style_if_colored(fg(state_color(connection)))),
                    Cell::from("-"),
                    Cell::from("-"),
                    Cell::from(bandwidth_line(
                        format_rate_compact(connection.current_incoming_rate_bps),
                        format_rate_compact(connection.current_outgoing_rate_bps),
                    )),
                ]);
                Row::new(cells)
            }
        })
        .collect();

    let mut state = ratatui::widgets::TableState::default();
    if let Some(idx) = ui_state.get_selected_grouped_index(grouped_rows) {
        state.select(Some(idx.saturating_sub(ui_state.grouped_scroll_offset)));
    }

    let table = Table::new(rows, &widths)
        .block(panel_block(" Grouped Connections "))
        .row_highlight_style(row_highlight())
        .highlight_symbol("> ");
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_stats_panel(
    f: &mut Frame,
    connections: &[Connection],
    stats: &AppStats,
    app: &App,
    area: Rect,
) -> anyhow::Result<()> {
    let block = panel_block(" System ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let active_count = connections.iter().filter(|c| !c.is_historic).count();
    let packets = stats
        .packets_processed
        .load(std::sync::atomic::Ordering::Relaxed);

    let mut lines = vec![
        Line::from(Span::styled("Statistics", bold_fg(heading()))),
        Line::from(format!(
            "Interface: {}",
            app.get_current_interface()
                .unwrap_or_else(|| "-".to_string())
        )),
        Line::from(format!("Connections: {}", active_count)),
        Line::from(format!("Packets: {}", packets)),
        Line::from(""),
        Line::from(Span::styled("Network Health", bold_fg(heading()))),
    ];

    let history = app.get_traffic_history();
    let rx = format_rate(history.get_latest_packets_per_sec() as f64);
    lines.push(Line::from(format!("Traffic: {}", rx)));

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
    Ok(())
}
