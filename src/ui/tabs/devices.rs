use crate::app::App;
use crate::network::types::Device;
use crate::ui::*;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

pub fn draw_devices(
    f: &mut Frame,
    app: &App,
    ui_state: &UIState,
    area: Rect,
    click_regions: &mut ClickableRegions,
) -> anyhow::Result<()> {
    let devices = app.get_devices();

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Summary bar
            Constraint::Min(0),    // Devices table
        ])
        .split(area);

    draw_devices_summary(f, app, &devices, main_chunks[0]);
    draw_devices_table(f, app, ui_state, &devices, main_chunks[1], click_regions);

    if ui_state.show_device_modal {
        if let Some(idx) = ui_state.get_selected_device_index(&devices) {
            if let Some(device) = devices.get(idx) {
                draw_device_modal(f, device);
            }
        }
    }

    Ok(())
}

fn draw_device_modal(f: &mut Frame, device: &Device) {
    use crate::ui::components::{centered_rect, Clear};
    let area = centered_rect(60, 50, f.area());
    f.render_widget(Clear, area);

    let block = panel_block(format!(" Device Details: {} ", device.ip));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut rows = Vec::new();
    let label_style = fg(label());
    let value_style = fg(primary());

    let mut add_row = |label: &str, value: String, style: Style| {
        rows.push(Row::new(vec![
            Cell::from(Span::styled(format!("{}:", label), label_style)),
            Cell::from(Span::styled(value, style)),
        ]));
    };

    add_row("IP Address", device.ip.to_string(), value_style);
    add_row("MAC Address", device.mac.clone(), value_style);
    add_row(
        "Vendor",
        device.vendor.clone().unwrap_or_else(|| "—".to_string()),
        fg(accent()),
    );
    add_row(
        "Hostname",
        device.hostname.clone().unwrap_or_else(|| "—".to_string()),
        fg(ok()),
    );
    add_row("Status", if device.is_online { "ONLINE".to_string() } else { "OFFLINE".to_string() }, if device.is_online { fg(ok()) } else { fg(muted()) });
    add_row("First Seen", format_system_time(device.first_seen), fg(muted()));
    add_row("Last Seen", format_system_time(device.last_seen), fg(muted()));
    add_row("Total Recv", format_bytes(device.bytes_received), fg(rx()));
    add_row("Total Sent", format_bytes(device.bytes_sent), fg(tx()));

    if !device.open_ports.is_empty() {
        let ports: Vec<String> = device.open_ports.iter()
            .map(|(p, s)| if s.is_empty() { p.to_string() } else { format!("{}:{}", p, s) })
            .collect();
        add_row("Open Ports", ports.join(", "), value_style);
    }

    if !device.discovery_details.is_empty() {
        let details: Vec<String> = device.discovery_details.iter().cloned().collect();
        add_row("Discovery", details.join(", "), fg(muted()));
    }

    let table = Table::new(rows, [Constraint::Length(15), Constraint::Min(0)]).style(Style::default());
    f.render_widget(table, inner);

    let help = Paragraph::new(" Press Esc or Enter to close ")
        .alignment(Alignment::Center)
        .style(fg(muted()));
    let help_area = Rect::new(inner.x, inner.y + inner.height - 1, inner.width, 1);
    f.render_widget(help, help_area);
}

fn draw_devices_summary(f: &mut Frame, app: &App, devices: &[Device], area: Rect) {
    let online_count = devices.iter().filter(|d| d.is_online).count();
    let total_count = devices.len();
    let hidden_count = 0; // Placeholder for future filtering logic

    let (dns_pending, dns_resolved) = app
        .get_dns_resolver()
        .map(|r| r.get_stats())
        .unwrap_or((0, 0));

    let local_ip = app
        .get_local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let summary_text = Line::from(vec![
        Span::styled(" Devices ", fg(heading())),
        Span::styled(
            format!(" {}/{} online ", online_count, total_count),
            fg(primary()),
        ),
        if hidden_count > 0 {
            Span::styled(format!(" ({} hidden) ", hidden_count), fg(muted()))
        } else {
            Span::raw(" ")
        },
        Span::raw(" ▏ "),
        Span::styled(" 🔍 DNS ", fg(ok())),
        Span::styled(
            format!("{}/{} hosts ", dns_pending, dns_pending + dns_resolved),
            fg(primary()),
        ),
        Span::raw(" ▏ "),
        Span::styled(" Local: ", fg(muted())),
        Span::styled(local_ip, fg(accent())),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(fg(muted()))
        .title(summary_text);

    f.render_widget(block, area);
}

fn draw_devices_table(
    f: &mut Frame,
    _app: &App,
    ui_state: &UIState,
    devices: &[Device],
    area: Rect,
    click_regions: &mut ClickableRegions,
) {
    let header_style = fg(heading());
    let header = Row::new(vec![
        Cell::from("Status ▼"),
        Cell::from("IP Address"),
        Cell::from("Hostname"),
        Cell::from("MAC"),
        Cell::from("Vendor"),
        Cell::from("Ports"),
        Cell::from("First"),
        Cell::from("Last"),
        Cell::from("↓ Recv"),
        Cell::from("↑ Sent"),
        Cell::from("Details"),
    ])
    .style(header_style)
    .height(1);

    let mut devices_sorted = devices.to_vec();
    devices_sorted.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

    let scroll_offset = ui_state.devices_scroll_offset;
    let visible_rows = ui_state.visible_rows.max(1);
    let window_end = (scroll_offset + visible_rows + 1).min(devices_sorted.len());
    let visible_devices = &devices_sorted[scroll_offset.min(devices_sorted.len())..window_end];

    let rows: Vec<Row> = visible_devices
        .iter()
        .map(|d| {
            let status_style = if d.is_online { fg(ok()) } else { fg(muted()) };

            let ip_str = if d.is_gateway {
                format!("{} (gateway)", d.ip)
            } else {
                d.ip.to_string()
            };

            let last_seen_str = format_system_time(d.last_seen);
            let first_seen_str = format_system_time(d.first_seen);
            
            let mut ports: Vec<String> = d.open_ports.iter()
                .map(|(p, s)| if s.is_empty() { p.to_string() } else { format!("{}:{}", p, s) })
                .collect();
            if ports.is_empty() {
                ports.push("—".to_string());
            }
            let ports_str = ports.join(" ");

            let mut details: Vec<String> = d.protocols.iter().cloned().collect();
            details.extend(d.discovery_details.iter().cloned());
            let details_str = details.join("  ");

            Row::new(vec![
                Cell::from(Line::from(vec![
                    Span::styled(" ● ", status_style),
                    Span::raw(if d.is_online { "ONLINE" } else { "OFFLINE" }),
                ])),
                Cell::from(ip_str),
                Cell::from(d.hostname.as_deref().unwrap_or("—")),
                Cell::from(d.mac.clone()),
                Cell::from(d.vendor.as_deref().unwrap_or("—")),
                Cell::from(ports_str),
                Cell::from(first_seen_str),
                Cell::from(last_seen_str),
                Cell::from(format_bytes(d.bytes_received)),
                Cell::from(format_bytes(d.bytes_sent)),
                Cell::from(details_str),
            ])
        })
        .collect();

    let mut state = ratatui::widgets::TableState::default();
    if let Some(selected_index) = ui_state.get_selected_device_index(&devices_sorted) {
        state.select(Some(selected_index.saturating_sub(scroll_offset)));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(22), // IP Address + (gateway)
            Constraint::Length(15),
            Constraint::Length(18),
            Constraint::Length(20),
            Constraint::Length(20), // Ports
            Constraint::Length(10), // First
            Constraint::Length(10), // Last
            Constraint::Length(12), // Recv
            Constraint::Length(12), // Sent
            Constraint::Min(20),    // Details
        ],
    )
    .header(header)
    .block(panel_block(format!(
        " DISCOVERED DEVICES ({}) ",
        devices.len()
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
        let device_idx = scroll_offset + i;
        if device_idx >= devices_sorted.len() {
            break;
        }
        click_regions.register(
            Rect::new(inner.x, inner.y + header_height + i as u16, inner.width, 1),
            ClickAction::SelectDevice(device_idx),
        );
    }
}
