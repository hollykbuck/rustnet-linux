use crate::app::App;
use crate::network::types::{Connection, Listener, Protocol};
use crate::ui::*;
use ratatui::widgets::{Cell, Paragraph, Row, Table};

pub fn draw_services(
    f: &mut Frame,
    app: &App,
    ui_state: &UIState,
    service_grouped_rows: Option<&[ServiceGroupedRow]>,
    connections: &[Connection],
    area: Rect,
    click_regions: &mut ClickableRegions,
) -> anyhow::Result<()> {
    let listeners = if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
        app.get_listeners()
    } else {
        app.get_filtered_listeners(&ui_state.filter_query)
    };

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // Summary panels
            Constraint::Min(0),    // Listeners table
        ])
        .split(area);

    draw_services_summary(f, &listeners, main_chunks[0]);
    draw_listeners_table(
        f,
        ui_state,
        &listeners,
        service_grouped_rows,
        main_chunks[1],
        click_regions,
    );

    if ui_state.show_service_modal {
        let mut listeners_sorted = listeners.clone();
        // (Sorting logic same as run_ui_loop)
        listeners_sorted.sort_by(|a, b| {
            let (ord, default_asc) = match ui_state.service_sort_column {
                ServiceSortColumn::Protocol => (a.protocol.cmp(&b.protocol), true),
                ServiceSortColumn::LocalAddress => (a.local_addr.cmp(&b.local_addr), true),
                ServiceSortColumn::Service => (a.service_name.cmp(&b.service_name), true),
                ServiceSortColumn::Process => (a.process_name.cmp(&b.process_name), true),
                ServiceSortColumn::Connections => {
                    (a.active_connections.cmp(&b.active_connections), false)
                }
            };
            if ui_state.sort_ascending == default_asc {
                ord
            } else {
                ord.reverse()
            }
        });

        if let Some(idx) = ui_state.get_selected_service_index(&listeners_sorted)
            && let Some(listener) = listeners_sorted.get(idx)
        {
            draw_service_modal(f, listener, connections);
        }
    }

    Ok(())
}

fn draw_service_modal(f: &mut Frame, listener: &Listener, connections: &[Connection]) {
    use crate::ui::components::{Clear, centered_rect};
    let area = centered_rect(80, 70, f.area());
    f.render_widget(Clear, area);

    let block = panel_block(format!(" Service Details: {} ", listener.local_addr));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let modal_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8), // Info table
            Constraint::Min(0),    // Active connections table
            Constraint::Length(1), // Help text
        ])
        .split(inner);

    let mut info_rows = Vec::new();
    let label_style = fg(label());
    let value_style = fg(primary());

    let mut add_info_row = |label: &str, value: String, style: Style| {
        info_rows.push(Row::new(vec![
            Cell::from(Span::styled(format!("{}:", label), label_style)),
            Cell::from(Span::styled(value, style)),
        ]));
    };

    add_info_row("Protocol", listener.protocol.to_string(), value_style);
    add_info_row(
        "Local Address",
        listener.local_addr.to_string(),
        value_style,
    );
    add_info_row(
        "Service Name",
        listener
            .service_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        fg(accent()),
    );
    add_info_row(
        "Process Name",
        listener
            .process_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        fg(ok()),
    );
    add_info_row(
        "PID",
        listener
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        fg(muted()),
    );
    add_info_row(
        "Active Conns",
        listener.active_connections.to_string(),
        if listener.active_connections > 0 {
            fg(ok())
        } else {
            fg(muted())
        },
    );

    let info_table =
        Table::new(info_rows, [Constraint::Length(15), Constraint::Min(0)]).style(Style::default());
    f.render_widget(info_table, modal_chunks[0]);

    // Active connections for this service
    let service_conns: Vec<&Connection> = connections
        .iter()
        .filter(|c| {
            c.protocol == listener.protocol
                && (c.local_addr == listener.local_addr
                    || c.local_addr.port() == listener.local_addr.port())
        })
        .collect();

    let conn_header = Row::new(vec![
        Cell::from(" Remote Address"),
        Cell::from(" Process"),
        Cell::from(" Status"),
        Cell::from(" Bytes Sent"),
        Cell::from(" Bytes Recv"),
    ])
    .style(fg(heading()))
    .height(1);

    let conn_rows: Vec<Row> = service_conns
        .iter()
        .map(|c| {
            Row::new(vec![
                Cell::from(c.remote_addr.to_string()),
                Cell::from(c.process_name.as_deref().unwrap_or("unknown")),
                Cell::from(c.state().into_owned()),
                Cell::from(format_bytes(c.bytes_sent)),
                Cell::from(format_bytes(c.bytes_received)),
            ])
        })
        .collect();

    let conn_table = Table::new(
        conn_rows,
        [
            Constraint::Percentage(30),
            Constraint::Percentage(25),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
        ],
    )
    .header(conn_header)
    .block(panel_block(format!(
        " ACTIVE CONNECTIONS ({}) ",
        service_conns.len()
    )))
    .row_highlight_style(row_highlight());

    f.render_widget(conn_table, modal_chunks[1]);

    let help = Paragraph::new(" Press Esc or Enter to close ")
        .alignment(Alignment::Center)
        .style(fg(muted()));
    f.render_widget(help, modal_chunks[2]);
}

fn draw_services_summary(f: &mut Frame, listeners: &[Listener], area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(area);

    // 1. TCP BIND Panel
    let tcp_listeners = listeners
        .iter()
        .filter(|l| l.protocol == Protocol::Tcp)
        .count();
    let bind_block = panel_block(" TCP BIND ");
    let bind_inner = bind_block.inner(chunks[0]);
    f.render_widget(bind_block, chunks[0]);

    let mut addr_counts = std::collections::HashMap::new();
    for l in listeners.iter().filter(|l| l.protocol == Protocol::Tcp) {
        let ip = l.local_addr.ip().to_string();
        *addr_counts.entry(ip).or_insert(0) += 1;
    }
    let mut addr_vec: Vec<_> = addr_counts.into_iter().collect();
    addr_vec.sort_by_key(|&(_, count)| std::cmp::Reverse(count));

    let mut bind_lines = vec![Line::from(vec![
        Span::styled(format!(" {} ", tcp_listeners), fg(primary())),
        Span::raw("listeners"),
    ])];

    for (addr, count) in addr_vec.iter().take(3) {
        let bar_len = (bind_inner.width as usize)
            .saturating_sub(15)
            .min(*count * 2);
        bind_lines.push(Line::from(vec![
            Span::styled(format!("{:<10} ", addr), fg(muted())),
            Span::styled("█".repeat(bar_len), fg(primary())),
            Span::raw(format!(" {}", count)),
        ]));
    }
    f.render_widget(Paragraph::new(bind_lines), bind_inner);

    // 2. TCP EXPOSURE Panel
    let exposure_block = panel_block(" TCP EXPOSURE ");
    let exposure_inner = exposure_block.inner(chunks[1]);
    f.render_widget(exposure_block, chunks[1]);

    let network_facing = listeners
        .iter()
        .filter(|l| l.protocol == Protocol::Tcp && !l.local_addr.ip().is_loopback())
        .count();
    let localhost_only = tcp_listeners.saturating_sub(network_facing);
    let exposure_pct = if tcp_listeners > 0 {
        (network_facing as f64 / tcp_listeners as f64) * 100.0
    } else {
        0.0
    };

    let exposure_lines = vec![
        Line::from(vec![
            Span::styled(" Exposure ", fg(muted())),
            if exposure_pct > 50.0 {
                Span::styled("High", fg(err()))
            } else if exposure_pct > 20.0 {
                Span::styled("Medium", fg(warn()))
            } else {
                Span::styled("Low", fg(ok()))
            },
            Span::raw(format!(" ({:.0}%)", exposure_pct)),
        ]),
        Line::from(vec![
            Span::styled(" ● ", fg(err())),
            Span::raw(format!("{} network-facing", network_facing)),
        ]),
        Line::from(vec![
            Span::styled(" ● ", fg(ok())),
            Span::raw(format!("{} localhost only", localhost_only)),
        ]),
    ];
    f.render_widget(Paragraph::new(exposure_lines), exposure_inner);

    // 3. SERVICES Panel
    let services_block = panel_block(" SERVICES ");
    let services_inner = services_block.inner(chunks[2]);
    f.render_widget(services_block, chunks[2]);

    let active_services = listeners
        .iter()
        .filter(|l| l.active_connections > 0)
        .count();
    let total_conn: usize = listeners.iter().map(|l| l.active_connections).sum();

    let services_lines = vec![
        Line::from(vec![
            Span::styled(format!(" {} ", listeners.len()), fg(primary())),
            Span::raw("total services"),
        ]),
        Line::from(vec![
            Span::styled(" ● ", fg(ok())),
            Span::raw(format!("{} active", active_services)),
            Span::raw(format!(
                "  ○ {} silent",
                listeners.len().saturating_sub(active_services)
            )),
        ]),
        Line::from(vec![
            Span::styled(" ⇄ ", fg(primary())),
            Span::raw(format!("{} total connections", total_conn)),
        ]),
    ];
    f.render_widget(Paragraph::new(services_lines), services_inner);
}

fn draw_listeners_table(
    f: &mut Frame,
    ui_state: &UIState,
    listeners: &[Listener],
    service_grouped_rows: Option<&[ServiceGroupedRow]>,
    area: Rect,
    click_regions: &mut ClickableRegions,
) {
    let titles = [
        " Protocol",
        " Local Address",
        " Service",
        " Process",
        " Conns",
    ];

    let header_cells: Vec<Cell> = titles
        .iter()
        .enumerate()
        .map(|(i, title)| {
            let sort_idx = match ui_state.service_sort_column {
                ServiceSortColumn::Protocol => 0,
                ServiceSortColumn::LocalAddress => 1,
                ServiceSortColumn::Service => 2,
                ServiceSortColumn::Process => 3,
                ServiceSortColumn::Connections => 4,
            };

            if i == sort_idx {
                let indicator = if ui_state.sort_ascending {
                    " ▲"
                } else {
                    " ▼"
                };
                Cell::from(Line::from(vec![Span::raw(*title), Span::raw(indicator)]))
            } else {
                Cell::from(*title)
            }
        })
        .collect();

    let header = Row::new(header_cells).style(fg(heading())).height(1);

    let mut listeners_sorted = listeners.to_vec();
    // (Sorting logic)
    listeners_sorted.sort_by(|a, b| {
        let (ord, default_asc) = match ui_state.service_sort_column {
            ServiceSortColumn::Protocol => (a.protocol.cmp(&b.protocol), true),
            ServiceSortColumn::LocalAddress => (a.local_addr.cmp(&b.local_addr), true),
            ServiceSortColumn::Service => (a.service_name.cmp(&b.service_name), true),
            ServiceSortColumn::Process => (a.process_name.cmp(&b.process_name), true),
            ServiceSortColumn::Connections => {
                (a.active_connections.cmp(&b.active_connections), false)
            }
        };
        if ui_state.sort_ascending == default_asc {
            ord
        } else {
            ord.reverse()
        }
    });

    let scroll_offset = if ui_state.service_grouping_enabled {
        ui_state.service_grouped_scroll_offset
    } else {
        ui_state.services_scroll_offset
    };

    let visible_rows = ui_state.visible_rows.max(1);

    let rows: Vec<Row> = if let Some(grouped) = service_grouped_rows {
        let window_end = (scroll_offset + visible_rows + 1).min(grouped.len());
        grouped[scroll_offset.min(grouped.len())..window_end]
            .iter()
            .map(|r| match r {
                ServiceGroupedRow::Group {
                    process_name,
                    stats,
                    expanded,
                } => {
                    let style = if ui_state.service_selected_group.as_deref() == Some(process_name)
                        && ui_state.is_service_group_selected()
                    {
                        row_highlight()
                    } else {
                        group_header()
                    };

                    Row::new(vec![
                        Cell::from(Line::from(vec![
                            Span::styled(if *expanded { "▼ " } else { "▶ " }, fg(primary())),
                            Span::styled(process_name.clone(), fg(heading())),
                        ])),
                        Cell::from(""),
                        Cell::from(""),
                        Cell::from(format!("{} listeners", stats.listener_count)),
                        Cell::from(Line::from(vec![
                            Span::styled(" ● ", fg(ok())),
                            Span::raw(stats.total_active_connections.to_string()),
                        ])),
                    ])
                    .style(style)
                }
                ServiceGroupedRow::Service {
                    listener,
                    is_last_in_group,
                    ..
                } => {
                    let tree_sym = if *is_last_in_group {
                        "└─"
                    } else {
                        "├─"
                    };
                    let (proto_icon, icon_color) = match listener.protocol {
                        Protocol::Tcp => ("🔑 ", fg(Color::Yellow)),
                        Protocol::Udp => ("🔗 ", fg(Color::Cyan)),
                        _ => ("  ", fg(Color::Reset)),
                    };
                    let proto_color = match listener.protocol {
                        Protocol::Tcp => tcp_established(),
                        Protocol::Udp => Color::Cyan,
                        _ => Color::Reset,
                    };
                    let active_style = if listener.active_connections > 0 {
                        fg(ok())
                    } else {
                        fg(muted())
                    };

                    Row::new(vec![
                        Cell::from(Line::from(vec![
                            Span::styled(format!("  {} ", tree_sym), fg(muted())),
                            Span::styled(proto_icon, icon_color),
                            Span::styled(listener.protocol.to_string(), fg(proto_color)),
                        ])),
                        Cell::from(listener.local_addr.to_string()),
                        Cell::from(listener.service_name.as_deref().unwrap_or("unknown")),
                        Cell::from(format!(
                            "{} ({})",
                            listener.process_name.as_deref().unwrap_or("unknown"),
                            listener.pid.unwrap_or(0)
                        )),
                        Cell::from(Line::from(vec![
                            Span::styled(" ● ", active_style),
                            Span::raw(listener.active_connections.to_string()),
                        ])),
                    ])
                }
            })
            .collect()
    } else {
        let window_end = (scroll_offset + visible_rows + 1).min(listeners_sorted.len());
        let visible_listeners =
            &listeners_sorted[scroll_offset.min(listeners_sorted.len())..window_end];
        visible_listeners
            .iter()
            .map(|l| {
                let (proto_icon, icon_color) = match l.protocol {
                    Protocol::Tcp => ("🔑 ", fg(Color::Yellow)),
                    Protocol::Udp => ("🔗 ", fg(Color::Cyan)),
                    _ => ("  ", fg(Color::Reset)),
                };
                let proto_color = match l.protocol {
                    Protocol::Tcp => tcp_established(),
                    Protocol::Udp => Color::Cyan,
                    _ => Color::Reset,
                };
                let active_style = if l.active_connections > 0 {
                    fg(ok())
                } else {
                    fg(muted())
                };

                Row::new(vec![
                    Cell::from(Line::from(vec![
                        Span::styled(proto_icon, icon_color),
                        Span::styled(l.protocol.to_string(), fg(proto_color)),
                    ])),
                    Cell::from(l.local_addr.to_string()),
                    Cell::from(l.service_name.as_deref().unwrap_or("unknown")),
                    Cell::from(format!(
                        "{} ({})",
                        l.process_name.as_deref().unwrap_or("unknown"),
                        l.pid.unwrap_or(0)
                    )),
                    Cell::from(Line::from(vec![
                        Span::styled(" ● ", active_style),
                        Span::raw(l.active_connections.to_string()),
                    ])),
                ])
            })
            .collect()
    };

    let mut state = ratatui::widgets::TableState::default();
    if ui_state.service_grouping_enabled {
        if let Some(grouped) = service_grouped_rows {
            if let Some(selected_index) = ui_state.get_selected_service_grouped_index(grouped) {
                state.select(Some(selected_index.saturating_sub(scroll_offset)));
            }
        }
    } else if let Some(selected_index) = ui_state.get_selected_service_index(&listeners_sorted) {
        state.select(Some(selected_index.saturating_sub(scroll_offset)));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(25),
            Constraint::Length(15),
            Constraint::Min(20),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(panel_block(format!(
        " TCP/UDP SERVICES ({}) ",
        listeners.len()
    )))
    .row_highlight_style(row_highlight())
    .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut state);

    let inner = area.inner(Margin {
        horizontal: 1,
        vertical: 1,
    });
    let header_height = 1_u16;
    let total_rows = if ui_state.service_grouping_enabled {
        service_grouped_rows.map(|g| g.len()).unwrap_or(0)
    } else {
        listeners_sorted.len()
    };

    for i in 0..(inner.height.saturating_sub(header_height) as usize) {
        let idx = scroll_offset + i;
        if idx >= total_rows {
            break;
        }
        click_regions.register(
            Rect::new(inner.x, inner.y + header_height + i as u16, inner.width, 1),
            ClickAction::SelectService(idx),
        );
    }
}
