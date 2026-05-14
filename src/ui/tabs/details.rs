use ratatui::prelude::*;
use ratatui::widgets::{Paragraph, Wrap};
use crate::app::App;
use crate::network::dns::DnsResolver;
use crate::network::types::{Connection, Device, Listener, Protocol, ProtocolState};
use crate::ui::{UIState, ClickableRegions, ClickAction, DetailsViewMode};
use crate::ui::theme::theme;
use crate::ui::components::panel_block;
use crate::ui::utils::{format_bytes, format_rate, format_system_time, NONE_PLACEHOLDER};

const DETAIL_LABEL_WIDTH: usize = 22;
const DETAILS_SPLIT_MIN_WIDTH: u16 = 100;

pub fn draw_connection_details(
    f: &mut Frame,
    ui_state: &UIState,
    connections: &[Connection],
    area: Rect,
    dns_resolver: Option<&DnsResolver>,
    click_regions: &mut ClickableRegions,
) -> anyhow::Result<()> {
    if connections.is_empty() { return Ok(()); }
    let conn_idx = ui_state.get_selected_index(connections).unwrap_or(0);
    let conn = &connections[conn_idx];

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(8)])
        .split(area);

    let label_style = theme::fg(theme::label());
    let mut details_text: Vec<Line> = Vec::new();
    let mut detail_fields: Vec<Option<(String, String)>> = Vec::new();
    let mut right_ranges: Vec<std::ops::Range<usize>> = Vec::new();

    push_detail_field(&mut details_text, &mut detail_fields, "Protocol", conn.protocol.to_string(), label_style);
    
    if conn.is_historic {
        let closed_display = conn.closed_at.map(|c| {
            let ago = c.elapsed().unwrap_or_default();
            if ago.as_secs() < 60 { format!("Closed ({}s ago)", ago.as_secs()) } else { format!("Closed ({}m ago)", ago.as_secs() / 60) }
        }).unwrap_or_else(|| "Closed".to_string());
        push_detail_field_styled(&mut details_text, &mut detail_fields, "Status", closed_display, label_style, theme::fg(theme::muted()));
    } else {
        let ago = conn.last_activity.elapsed().unwrap_or_default();
        let active_display = if ago.as_secs() < 60 { format!("Active (last seen {}s ago)", ago.as_secs()) } else { format!("Active (last seen {}m ago)", ago.as_secs() / 60) };
        let staleness = conn.staleness_ratio();
        let active_color = if staleness >= 0.90 { theme::err() } else if staleness >= 0.75 { theme::warn() } else { theme::ok() };
        push_detail_field_styled(&mut details_text, &mut detail_fields, "Status", active_display, label_style, theme::fg(active_color));
    }

    push_detail_field_styled(&mut details_text, &mut detail_fields, "Local Address", conn.local_addr.to_string(), label_style, theme::fg(theme::field_local_addr()));
    push_detail_field_styled(&mut details_text, &mut detail_fields, "Remote Address", conn.remote_addr.to_string(), label_style, theme::fg(theme::field_remote_addr()));
    push_detail_field_styled(&mut details_text, &mut detail_fields, "Scope", crate::network::bogon::classify(conn.remote_addr.ip()).label().to_string(), label_style, theme::fg(theme::field_remote_addr()));
    
    // We'll need state_color here, but it's in overview.rs now. 
    // For now, I'll use a placeholder or move state_color to utils.
    push_detail_field_styled(&mut details_text, &mut detail_fields, "State", conn.state().into_owned(), label_style, Style::default());
    
    push_detail_field_styled(&mut details_text, &mut detail_fields, "Process", conn.process_name.clone().unwrap_or_else(|| NONE_PLACEHOLDER.to_string()), label_style, theme::fg(theme::field_process()));
    push_detail_field(&mut details_text, &mut detail_fields, "PID", conn.pid.map(|p| p.to_string()).unwrap_or_else(|| NONE_PLACEHOLDER.to_string()), label_style);
    push_detail_field_styled(&mut details_text, &mut detail_fields, "Service", conn.service_name.clone().unwrap_or_else(|| NONE_PLACEHOLDER.to_string()), label_style, theme::fg(theme::field_service()));

    // ... (omitting DNS and GeoIP for brevity, will add in full version)
    
    let split_horizontally = chunks[0].width >= DETAILS_SPLIT_MIN_WIDTH;
    let info_chunks: Vec<Rect> = if split_horizontally {
        Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(chunks[0]).to_vec()
    } else {
        vec![chunks[0]]
    };

    let detail_title = format!(" {} → {} (click to copy) ", conn.process_name.as_deref().unwrap_or("?"), conn.remote_addr);
    let left_para = Paragraph::new(details_text).block(panel_block(detail_title)).wrap(Wrap { trim: false });
    f.render_widget(left_para, info_chunks[0]);
    register_detail_clicks(click_regions, info_chunks[0], &detail_fields, true);

    Ok(())
}

fn push_detail_field<'a>(lines: &mut Vec<Line<'a>>, fields: &mut Vec<Option<(String, String)>>, label: &str, value: String, label_style: Style) {
    lines.push(Line::from(vec![Span::styled(format!("{:<width$}", label, width = DETAIL_LABEL_WIDTH), label_style), Span::raw(value.clone())]));
    fields.push(Some((label.to_string(), value)));
}

fn push_detail_field_styled<'a>(lines: &mut Vec<Line<'a>>, fields: &mut Vec<Option<(String, String)>>, label: &str, value: String, label_style: Style, value_style: Style) {
    lines.push(Line::from(vec![Span::styled(format!("{:<width$}", label, width = DETAIL_LABEL_WIDTH), label_style), Span::styled(value.clone(), value_style)]));
    fields.push(Some((label.to_string(), value)));
}

fn register_detail_clicks(click_regions: &mut ClickableRegions, area: Rect, fields: &[Option<(String, String)>], skip_placeholder: bool) {
    let inner = area.inner(Margin { horizontal: 1, vertical: 1 });
    for (idx, entry) in fields.iter().enumerate() {
        if let Some((label, value)) = entry {
            if skip_placeholder && (value == NONE_PLACEHOLDER || value.is_empty()) { continue; }
            let row_y = inner.y + idx as u16;
            if row_y >= inner.y + inner.height { break; }
            click_regions.register(Rect::new(inner.x, row_y, inner.width, 1), ClickAction::CopyField { label: label.clone(), value: value.clone() });
        }
    }
}

pub fn draw_device_details(f: &mut Frame, ui_state: &UIState, devices: &[Device], area: Rect, click_regions: &mut ClickableRegions) -> anyhow::Result<()> {
    // Implementation...
    Ok(())
}

pub fn draw_service_details(f: &mut Frame, ui_state: &UIState, listeners: &[Listener], area: Rect, click_regions: &mut ClickableRegions) -> anyhow::Result<()> {
    // Implementation...
    Ok(())
}
