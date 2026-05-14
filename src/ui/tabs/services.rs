use crate::app::App;
use crate::network::types::{Listener, Protocol};
use crate::ui::*;
use ratatui::prelude::*;
use ratatui::widgets::{Cell, Paragraph, Row, Table};

pub fn draw_services(
    f: &mut Frame,
    app: &App,
    ui_state: &UIState,
    area: Rect,
    click_regions: &mut ClickableRegions,
) -> anyhow::Result<()> {
    let listeners = app.get_listeners();

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // Summary panels
            Constraint::Min(0),    // Listeners table
        ])
        .split(area);

    draw_services_summary(f, &listeners, main_chunks[0]);
    draw_listeners_table(f, ui_state, &listeners, main_chunks[1], click_regions);

    Ok(())
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
        .filter(|l| !l.local_addr.ip().is_loopback())
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
    area: Rect,
    click_regions: &mut ClickableRegions,
) {
    let header_style = fg(heading());
    let header = Row::new(vec![
        Cell::from(" Protocol"),
        Cell::from(" Local Address"),
        Cell::from(" Service"),
        Cell::from(" Process"),
        Cell::from(" Conns"),
    ])
    .style(header_style)
    .height(1);

    let mut listeners_sorted = listeners.to_vec();
    listeners_sorted.sort_by(|a, b| b.active_connections.cmp(&a.active_connections));

    let scroll_offset = ui_state.services_scroll_offset;
    let visible_rows = ui_state.visible_rows.max(1);
    let window_end = (scroll_offset + visible_rows + 1).min(listeners_sorted.len());
    let visible_listeners =
        &listeners_sorted[scroll_offset.min(listeners_sorted.len())..window_end];

    let rows: Vec<Row> = visible_listeners
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
        .collect();

    let mut state = ratatui::widgets::TableState::default();
    if let Some(selected_index) = ui_state.get_selected_service_index(&listeners_sorted) {
        state.select(Some(selected_index.saturating_sub(scroll_offset)));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
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
    for i in 0..(inner.height.saturating_sub(header_height) as usize) {
        let service_idx = scroll_offset + i;
        if service_idx >= listeners_sorted.len() {
            break;
        }
        click_regions.register(
            Rect::new(inner.x, inner.y + header_height + i as u16, inner.width, 1),
            ClickAction::SelectService(service_idx),
        );
    }
}
