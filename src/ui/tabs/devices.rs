use ratatui::prelude::*;
use ratatui::widgets::{Cell, Row, Table, Block, Borders};
use crate::app::App;
use crate::network::types::Device;
use crate::ui::{UIState, ClickableRegions, ClickAction};
use crate::ui::theme::theme;
use crate::ui::components::panel_block;
use crate::ui::utils::{format_bytes, format_system_time};

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
    draw_devices_table(f, ui_state, &devices, main_chunks[1], click_regions);

    Ok(())
}

fn draw_devices_summary(f: &mut Frame, _app: &App, devices: &[Device], area: Rect) {
    let online_count = devices.iter().filter(|d| d.is_online).count();

    let summary_text = Line::from(vec![
        Span::styled(" Devices ", theme::fg(theme::heading())),
        Span::styled(
            format!(" {}/{} online ", online_count, devices.len()),
            theme::primary(),
        ),
        Span::raw(" ▏ "),
        Span::styled(" 🔍 Discovery Active ", theme::fg(theme::ok())),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::fg(theme::muted()))
        .title(summary_text);

    f.render_widget(block, area);
}

fn draw_devices_table(
    f: &mut Frame,
    ui_state: &UIState,
    devices: &[Device],
    area: Rect,
    click_regions: &mut ClickableRegions,
) {
    let header_style = theme::fg(theme::heading());
    let header = Row::new(vec![
        Cell::from(" Status"),
        Cell::from(" IP Address"),
        Cell::from(" Hostname"),
        Cell::from(" MAC"),
        Cell::from(" Vendor"),
        Cell::from(" First Seen"),
        Cell::from(" Last Seen"),
        Cell::from(" ↓ Recv"),
        Cell::from(" ↑ Sent"),
        Cell::from(" Details"),
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
            let status_style = if d.is_online {
                theme::fg(theme::ok())
            } else {
                theme::fg(theme::muted())
            };

            let last_seen_str = format_system_time(d.last_seen);
            let first_seen_str = format_system_time(d.first_seen);
            let details = d.protocols.iter().cloned().collect::<Vec<_>>().join(" ");

            Row::new(vec![
                Cell::from(Line::from(vec![
                    Span::styled(" ● ", status_style),
                    Span::raw(if d.is_online { "ONLINE" } else { "OFFLINE" }),
                ])),
                Cell::from(d.ip.to_string()),
                Cell::from(d.hostname.as_deref().unwrap_or("—")),
                Cell::from(d.mac.clone()),
                Cell::from(d.vendor.as_deref().unwrap_or("—")),
                Cell::from(first_seen_str),
                Cell::from(last_seen_str),
                Cell::from(format_bytes(d.bytes_received)),
                Cell::from(format_bytes(d.bytes_sent)),
                Cell::from(details),
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
            Constraint::Length(16),
            Constraint::Length(15),
            Constraint::Length(18),
            Constraint::Length(20),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(panel_block(format!(
        " DISCOVERED DEVICES ({}) ",
        devices.len()
    )))
    .row_highlight_style(theme::row_highlight())
    .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut state);

    click_regions.scroll_area = Some(area);
    let inner = area.inner(Margin { horizontal: 1, vertical: 1 });
    let header_height = 1_u16;
    let visible_start_y = inner.y + header_height;
    let max_visible_rows = inner.height.saturating_sub(header_height) as usize;

    for i in 0..max_visible_rows {
        let device_idx = scroll_offset + i;
        if device_idx >= devices_sorted.len() { break; }
        let row_y = visible_start_y + i as u16;
        let row_rect = Rect::new(inner.x, row_y, inner.width, 1);
        click_regions.register(row_rect, ClickAction::SelectDevice(device_idx));
    }
}
