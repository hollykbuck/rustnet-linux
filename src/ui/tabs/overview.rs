use crate::app::{App, AppStats};
use crate::network::types::{
    ApplicationProtocol, Connection, Device, Protocol, ProtocolState, TcpState,
};
use crate::ui::*;
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};
use std::sync::atomic::Ordering;

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

fn connection_widths(show_location: bool) -> Vec<Constraint> {
    let mut widths = vec![
        Constraint::Length(1),
        Constraint::Length(24),
        Constraint::Length(20),
        Constraint::Length(24),
    ];
    if show_location {
        widths.push(Constraint::Length(5));
    }
    widths.extend([
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(18),
        Constraint::Length(15),
    ]);
    widths
}

fn sort_indicator(sort_ascending: bool) -> &'static str {
    if sort_ascending { " ▲" } else { " ▼" }
}

fn sort_header_index(sort_column: SortColumn, show_location: bool) -> Option<usize> {
    match sort_column {
        SortColumn::CreatedAt => None,
        SortColumn::Protocol | SortColumn::Process => Some(1),
        SortColumn::LocalAddress => Some(2),
        SortColumn::RemoteAddress => Some(3),
        SortColumn::Location => show_location.then_some(4),
        SortColumn::State => Some(if show_location { 5 } else { 4 }),
        SortColumn::Service => Some(if show_location { 6 } else { 5 }),
        SortColumn::Application => Some(if show_location { 7 } else { 6 }),
        SortColumn::BandwidthTotal => Some(if show_location { 8 } else { 7 }),
    }
}

fn sort_title(ui_state: &UIState) -> String {
    format!(
        "Sort: {} {}",
        ui_state.sort_column.display_name(),
        if ui_state.sort_ascending {
            "↑"
        } else {
            "↓"
        }
    )
}

fn header_cell(
    title: &'static str,
    index: usize,
    active_index: Option<usize>,
    asc: bool,
) -> Cell<'static> {
    if active_index == Some(index) {
        Cell::from(Line::from(vec![
            Span::raw(title),
            Span::raw(sort_indicator(asc)),
        ]))
        .style(bold_underline_fg(accent()))
    } else {
        Cell::from(title)
    }
}

fn connection_header(show_location: bool, ui_state: &UIState) -> Row<'static> {
    let active_index = sort_header_index(ui_state.sort_column, show_location);
    let mut cells = vec![
        Cell::from(""),
        header_cell(
            "Process / Protocol",
            1,
            active_index,
            ui_state.sort_ascending,
        ),
        header_cell("Local Address", 2, active_index, ui_state.sort_ascending),
        header_cell("Remote Address", 3, active_index, ui_state.sort_ascending),
    ];
    if show_location {
        cells.push(header_cell("Loc", 4, active_index, ui_state.sort_ascending));
    }
    let state_idx = if show_location { 5 } else { 4 };
    cells.extend([
        header_cell("State", state_idx, active_index, ui_state.sort_ascending),
        header_cell(
            "Service",
            state_idx + 1,
            active_index,
            ui_state.sort_ascending,
        ),
        header_cell(
            "Application",
            state_idx + 2,
            active_index,
            ui_state.sort_ascending,
        ),
    ]);
    let bandwidth_idx = state_idx + 3;
    if active_index == Some(bandwidth_idx) {
        cells.push(
            Cell::from(
                Line::from(vec![
                    Span::raw("Down/Up"),
                    Span::raw(sort_indicator(ui_state.sort_ascending)),
                ])
                .right_aligned(),
            )
            .style(bold_underline_fg(accent())),
        );
    } else {
        cells.push(Cell::from(Line::from("Down/Up").right_aligned()));
    }

    Row::new(cells)
        .style(fg(heading()))
        .height(1)
        .bottom_margin(1)
}

fn display_addr(
    conn: &Connection,
    is_local: bool,
    ui_state: &UIState,
    devices: &[Device],
    dns_resolver: Option<&crate::network::dns::DnsResolver>,
) -> String {
    let addr = if is_local {
        conn.local_addr
    } else {
        conn.remote_addr
    };
    let name = if ui_state.show_hostnames {
        devices
            .iter()
            .find(|d| d.ips.contains(&addr.ip()))
            .and_then(|d| d.hostname.clone())
            .or_else(|| dns_resolver.and_then(|r| r.get_hostname(&addr.ip())))
    } else {
        None
    };

    if let Some(host) = name {
        if ui_state.show_port_numbers {
            format!("{}:{}", host, addr.port())
        } else {
            host
        }
    } else if ui_state.show_port_numbers {
        addr.to_string()
    } else {
        addr.ip().to_string()
    }
}

fn application_label(conn: &Connection) -> String {
    conn.dpi_info
        .as_ref()
        .map(|d| d.application.to_string())
        .unwrap_or_else(|| NONE_PLACEHOLDER.to_string())
}

fn application_style(conn: &Connection) -> Style {
    style_if_colored(fg(conn
        .dpi_info
        .as_ref()
        .map(|d| dpi_color(&d.application))
        .unwrap_or(Color::Reset)))
}

fn location_label(conn: &Connection) -> &str {
    conn.geoip_info
        .as_ref()
        .map_or("-", |geoip| geoip.country_display())
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
    let widths = connection_widths(show_location);
    let header = connection_header(show_location, ui_state);

    let scroll_offset = ui_state.scroll_offset;
    let visible_rows = ui_state.visible_rows.max(1);
    let window_end = (scroll_offset + visible_rows + 1).min(connections.len());
    let visible_connections = &connections[scroll_offset.min(connections.len())..window_end];

    let rows: Vec<Row> = visible_connections
        .iter()
        .map(|conn| {
            let local_addr = display_addr(conn, true, ui_state, devices, dns_resolver);
            let remote_addr = display_addr(conn, false, ui_state, devices, dns_resolver);

            let incoming_rate = format_rate_compact(conn.current_incoming_rate_bps);
            let outgoing_rate = format_rate_compact(conn.current_outgoing_rate_bps);

            let mut cells = vec![
                status_indicator_cell(conn),
                Cell::from(format!(
                    "{} {}",
                    conn.protocol,
                    conn.process_name.as_deref().unwrap_or(NONE_PLACEHOLDER)
                ))
                .style(style_if_colored(field_process())),
                Cell::from(local_addr).style(style_if_colored(field_local_addr())),
                Cell::from(remote_addr).style(style_if_colored(field_remote_addr())),
            ];
            if show_location {
                cells.push(
                    Cell::from(location_label(conn)).style(style_if_colored(field_location())),
                );
            }
            cells.extend([
                Cell::from(conn.state()).style(style_if_colored(fg(state_color(conn)))),
                Cell::from(conn.service_name.as_deref().unwrap_or(NONE_PLACEHOLDER))
                    .style(style_if_colored(field_service())),
                Cell::from(application_label(conn)).style(application_style(conn)),
                Cell::from(bandwidth_line(incoming_rate, outgoing_rate)),
            ]);

            Row::new(cells)
        })
        .collect();

    let mut state = ratatui::widgets::TableState::default();
    if let Some(idx) = ui_state.get_selected_index(connections) {
        state.select(Some(idx.saturating_sub(scroll_offset)));
    }

    let title = format!(
        " Connections ({}) | {} ",
        connections.len(),
        sort_title(ui_state)
    );
    let table = Table::new(rows, widths)
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
    click_regions: &mut ClickableRegions,
) {
    let widths = connection_widths(show_location);
    let scroll_offset = ui_state.grouped_scroll_offset.min(grouped_rows.len());
    let visible_rows = ui_state.visible_rows.max(1);
    let window_end = (scroll_offset + visible_rows).min(grouped_rows.len());
    let visible_grouped_rows = &grouped_rows[scroll_offset..window_end];

    let rows: Vec<Row> = visible_grouped_rows
        .iter()
        .map(|row| match row {
            GroupedRow::Group {
                process_name,
                stats,
                expanded,
            } => {
                let indicator = if *expanded { "[-]" } else { "[+]" };
                let connection_count = stats.connection_count + stats.historic_count;
                let mut cells = vec![
                    Cell::from(""),
                    Cell::from(Line::from(vec![
                        Span::styled(format!("{} ", indicator), fg(accent())),
                        Span::styled(process_name.clone(), bold_fg(accent())),
                        Span::raw(format!(" ({})", connection_count)),
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

                let local_addr = display_addr(connection, true, ui_state, devices, dns_resolver);
                let remote_addr = display_addr(connection, false, ui_state, devices, dns_resolver);

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
                    cells.push(
                        Cell::from(location_label(connection))
                            .style(style_if_colored(field_location())),
                    );
                }
                cells.extend([
                    Cell::from(connection.state())
                        .style(style_if_colored(fg(state_color(connection)))),
                    Cell::from(
                        connection
                            .service_name
                            .as_deref()
                            .unwrap_or(NONE_PLACEHOLDER),
                    )
                    .style(style_if_colored(field_service())),
                    Cell::from(application_label(connection)).style(application_style(connection)),
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
        state.select(Some(idx.saturating_sub(scroll_offset)));
    }

    let table = Table::new(rows, &widths)
        .header(connection_header(show_location, ui_state))
        .block(panel_block(format!(
            " Grouped by Process (A-Z) | {} ",
            sort_title(ui_state)
        )))
        .row_highlight_style(row_highlight())
        .highlight_symbol("> ");
    f.render_stateful_widget(table, area, &mut state);

    let inner = area.inner(Margin {
        horizontal: 1,
        vertical: 1,
    });
    let header_height = 2_u16;
    for (i, row_idx) in (scroll_offset..window_end).enumerate() {
        click_regions.register(
            Rect::new(inner.x, inner.y + header_height + i as u16, inner.width, 1),
            ClickAction::SelectConnection(row_idx),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::geoip::GeoIpInfo;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_connection() -> Connection {
        Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 50000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    #[test]
    fn location_label_uses_geoip_country_code() {
        let mut conn = test_connection();
        conn.geoip_info = Some(GeoIpInfo {
            country_code: Some("US".to_string()),
            ..GeoIpInfo::default()
        });

        assert_eq!(location_label(&conn), "US");
    }

    #[test]
    fn location_label_falls_back_when_country_missing() {
        let mut conn = test_connection();
        assert_eq!(location_label(&conn), "-");

        conn.geoip_info = Some(GeoIpInfo {
            city: Some("Mountain View".to_string()),
            ..GeoIpInfo::default()
        });
        assert_eq!(location_label(&conn), "-");
    }

    #[test]
    fn sort_header_index_tracks_optional_location_column() {
        assert_eq!(sort_header_index(SortColumn::CreatedAt, true), None);
        assert_eq!(sort_header_index(SortColumn::Process, true), Some(1));
        assert_eq!(sort_header_index(SortColumn::Protocol, true), Some(1));
        assert_eq!(sort_header_index(SortColumn::Location, true), Some(4));
        assert_eq!(sort_header_index(SortColumn::Location, false), None);
        assert_eq!(sort_header_index(SortColumn::State, true), Some(5));
        assert_eq!(sort_header_index(SortColumn::State, false), Some(4));
        assert_eq!(sort_header_index(SortColumn::BandwidthTotal, true), Some(8));
        assert_eq!(
            sort_header_index(SortColumn::BandwidthTotal, false),
            Some(7)
        );
    }
}

fn push_line(lines: &mut Vec<Line<'static>>, label_text: &str, value: impl Into<String>) {
    lines.push(Line::from(vec![
        Span::styled(format!("{}: ", label_text), fg(label())),
        Span::raw(value.into()),
    ]));
}

fn push_section(lines: &mut Vec<Line<'static>>, title: &str) {
    if !lines.is_empty() {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        title.to_string(),
        bold_fg(heading()),
    )));
}

fn sparkline(data: &[u64], width: usize) -> String {
    const BARS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if width == 0 {
        return String::new();
    }
    if data.is_empty() {
        return "·".repeat(width.min(8));
    }

    let start = data.len().saturating_sub(width);
    let sample = &data[start..];
    let max = sample.iter().copied().max().unwrap_or(0);
    if max == 0 {
        return "▁".repeat(sample.len());
    }

    sample
        .iter()
        .map(|value| {
            let idx = ((*value as usize) * (BARS.len() - 1) / max as usize).min(BARS.len() - 1);
            BARS[idx]
        })
        .collect()
}

#[cfg(any(
    target_os = "linux",
    target_os = "windows",
    all(target_os = "macos", feature = "macos-sandbox")
))]
fn sandbox_lines(lines: &mut Vec<Line<'static>>, app: &App) {
    let sandbox = app.get_sandbox_info();
    push_line(
        lines,
        "Sandbox",
        if sandbox.status.is_empty() {
            "Unknown".to_string()
        } else {
            sandbox.status
        },
    );

    #[cfg(target_os = "linux")]
    {
        lines.push(Line::from(vec![
            Span::styled("• ", fg(muted())),
            Span::raw(format!(
                "CAP_NET_RAW {}",
                if sandbox.cap_dropped {
                    "dropped"
                } else {
                    "available"
                }
            )),
        ]));
        lines.push(Line::from(vec![
            Span::styled("• ", fg(muted())),
            Span::raw(format!(
                "eBPF caps {}",
                if sandbox.ebpf_caps_dropped {
                    "dropped"
                } else {
                    "available"
                }
            )),
        ]));
        lines.push(Line::from(vec![
            Span::styled("• ", fg(muted())),
            Span::raw(format!(
                "FS {}",
                if sandbox.fs_restricted {
                    "restricted"
                } else {
                    "unrestricted"
                }
            )),
        ]));
        lines.push(Line::from(vec![
            Span::styled("• ", fg(muted())),
            Span::raw(format!(
                "Net {}",
                if sandbox.net_restricted {
                    "blocked"
                } else {
                    "allowed"
                }
            )),
        ]));
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "windows",
    all(target_os = "macos", feature = "macos-sandbox")
)))]
fn sandbox_lines(lines: &mut Vec<Line<'static>>, _app: &App) {
    push_line(lines, "Sandbox", "Unavailable");
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
    let tcp_count = connections
        .iter()
        .filter(|c| c.protocol == Protocol::Tcp && !c.is_historic)
        .count();
    let udp_count = connections
        .iter()
        .filter(|c| c.protocol == Protocol::Udp && !c.is_historic)
        .count();
    let active_tcp_flows = connections
        .iter()
        .filter(|c| {
            c.protocol == Protocol::Tcp
                && !c.is_historic
                && !matches!(
                    c.protocol_state,
                    ProtocolState::Tcp(TcpState::Closed | TcpState::TimeWait)
                )
        })
        .count();
    let packets = stats.packets_processed.load(Ordering::Relaxed);
    let dropped = stats.packets_dropped.load(Ordering::Relaxed);
    let retransmits = stats.total_tcp_retransmits.load(Ordering::Relaxed);
    let out_of_order = stats.total_tcp_out_of_order.load(Ordering::Relaxed);
    let fast_retransmits = stats.total_tcp_fast_retransmits.load(Ordering::Relaxed);
    let process_status = app.get_process_detection_status();
    let (link_layer, is_tunnel) = app.get_link_layer_info();
    let history = app.get_traffic_history();
    let interface = app
        .get_current_interface()
        .unwrap_or_else(|| "-".to_string());
    let sorted_interfaces = app.get_sorted_interface_stats();
    let current_interface_stats = sorted_interfaces
        .iter()
        .find(|stat| stat.interface_name == interface)
        .or_else(|| sorted_interfaces.first());
    let interface_rates = app.get_interface_rates();
    let current_rates = interface_rates.get(&interface);
    let rx_rate = current_rates
        .map(|rates| rates.rx_bytes_per_sec as f64)
        .unwrap_or_else(|| {
            history
                .get_rx_sparkline_data(1)
                .last()
                .copied()
                .unwrap_or(0) as f64
        });
    let tx_rate = current_rates
        .map(|rates| rates.tx_bytes_per_sec as f64)
        .unwrap_or_else(|| {
            history
                .get_tx_sparkline_data(1)
                .last()
                .copied()
                .unwrap_or(0) as f64
        });

    let mut lines = Vec::new();
    push_section(&mut lines, "Statistics");
    push_line(&mut lines, "Interface", interface.clone());
    push_line(
        &mut lines,
        "Link Layer",
        if is_tunnel {
            format!("{} tunnel", link_layer)
        } else {
            link_layer
        },
    );
    push_line(
        &mut lines,
        "Process Detection",
        if process_status.is_degraded {
            format!(
                "{} degraded ({})",
                process_status.method,
                process_status
                    .unavailable_feature
                    .as_deref()
                    .unwrap_or("feature unavailable")
            )
        } else {
            process_status.method
        },
    );
    if let Some(reason) = process_status.degradation_reason {
        lines.push(Line::from(Span::styled(reason, fg(warn()))));
    }

    push_section(&mut lines, "Connections");
    push_line(&mut lines, "TCP", tcp_count.to_string());
    push_line(&mut lines, "UDP", udp_count.to_string());
    push_line(&mut lines, "Total", active_count.to_string());
    push_line(&mut lines, "Packets", packets.to_string());
    push_line(
        &mut lines,
        "Packets/sec",
        history.get_latest_packets_per_sec().to_string(),
    );
    push_line(&mut lines, "Dropped", dropped.to_string());

    push_section(&mut lines, "Network Stats");
    push_line(&mut lines, "TCP Retransmits", retransmits.to_string());
    push_line(&mut lines, "Out-of-Order", out_of_order.to_string());
    push_line(&mut lines, "Fast Retransmits", fast_retransmits.to_string());
    push_line(&mut lines, "Active TCP Flows", active_tcp_flows.to_string());

    push_section(&mut lines, "Security");
    sandbox_lines(&mut lines, app);

    push_section(&mut lines, "Traffic");
    let spark_width = inner.width.saturating_sub(3).clamp(8, 48) as usize;
    lines.push(Line::from(vec![
        Span::styled("RX ", fg(rx())),
        Span::raw(sparkline(
            &history.get_rx_sparkline_data(spark_width),
            spark_width,
        )),
    ]));
    lines.push(Line::from(vec![
        Span::styled("TX ", fg(tx())),
        Span::raw(sparkline(
            &history.get_tx_sparkline_data(spark_width),
            spark_width,
        )),
    ]));
    lines.push(Line::from(vec![
        Span::styled("↓", fg(rx())),
        Span::raw(format_rate(rx_rate)),
        Span::raw(" "),
        Span::styled("↑", fg(tx())),
        Span::raw(format_rate(tx_rate)),
    ]));
    if let Some(stat) = current_interface_stats {
        lines.push(Line::from(format!(
            "{}: Err {} Drop {}",
            stat.interface_name,
            stat.rx_errors + stat.tx_errors,
            stat.rx_dropped + stat.tx_dropped
        )));
    }

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
    Ok(())
}
