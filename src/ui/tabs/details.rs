use crate::network::dns::DnsResolver;
use crate::network::types::Connection;
use crate::ui::*;
use ratatui::widgets::{Paragraph, Wrap};

const DETAIL_LABEL_WIDTH: usize = 22;

pub fn draw_connection_modal(
    f: &mut Frame,
    ui_state: &UIState,
    connections: &[Connection],
    dns_resolver: Option<&DnsResolver>,
    click_regions: &mut ClickableRegions,
) -> anyhow::Result<()> {
    use crate::ui::components::{centered_rect, Clear};
    let area = centered_rect(60, 60, f.area());
    f.render_widget(Clear, area);
    draw_connection_details(f, ui_state, connections, area, dns_resolver, click_regions)
}

pub fn draw_connection_details(
    f: &mut Frame,
    ui_state: &UIState,
    connections: &[Connection],
    area: Rect,
    dns_resolver: Option<&DnsResolver>,
    click_regions: &mut ClickableRegions,
) -> anyhow::Result<()> {
    if connections.is_empty() {
        return Ok(());
    }
    let conn_idx = ui_state.get_selected_index(connections).unwrap_or(0);
    let conn = &connections[conn_idx];

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(8)])
        .split(area);

    let label_style = fg(label());
    let mut details_text: Vec<Line> = Vec::new();
    let mut detail_fields: Vec<Option<(String, String)>> = Vec::new();

    push_detail_field(
        &mut details_text,
        &mut detail_fields,
        "Protocol",
        conn.protocol.to_string(),
        label_style,
    );

    if conn.is_historic {
        push_detail_field_styled(
            &mut details_text,
            &mut detail_fields,
            "Status",
            "Closed".to_string(),
            label_style,
            fg(muted()),
        );
    } else {
        push_detail_field_styled(
            &mut details_text,
            &mut detail_fields,
            "Status",
            "Active".to_string(),
            label_style,
            fg(ok()),
        );
    }

    push_detail_field_styled(
        &mut details_text,
        &mut detail_fields,
        "Local Address",
        conn.local_addr.to_string(),
        label_style,
        field_local_addr(),
    );
    push_detail_field_styled(
        &mut details_text,
        &mut detail_fields,
        "Remote Address",
        conn.remote_addr.to_string(),
        label_style,
        field_remote_addr(),
    );

    push_detail_field_styled(
        &mut details_text,
        &mut detail_fields,
        "Process",
        conn.process_name
            .clone()
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        label_style,
        field_process(),
    );
    push_detail_field(
        &mut details_text,
        &mut detail_fields,
        "PID",
        conn.pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        label_style,
    );
    push_detail_field_styled(
        &mut details_text,
        &mut detail_fields,
        "Service",
        conn.service_name
            .clone()
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        label_style,
        field_service(),
    );

    if let Some(resolver) = dns_resolver
        && let Some(h) = resolver.get_hostname(&conn.remote_addr.ip())
    {
        push_detail_field_styled(
            &mut details_text,
            &mut detail_fields,
            "Hostname",
            h,
            label_style,
            fg(accent()),
        );
    }

    let detail_title = format!(
        " {} → {} ",
        conn.process_name.as_deref().unwrap_or("?"),
        conn.remote_addr
    );
    let left_para = Paragraph::new(details_text)
        .block(panel_block(detail_title))
        .wrap(Wrap { trim: false });
    f.render_widget(left_para, chunks[0]);
    register_detail_clicks(click_regions, chunks[0], &detail_fields, true);

    let mut traffic_text = Vec::new();
    push_detail_field_styled(
        &mut traffic_text,
        &mut Vec::new(),
        "Bytes Sent",
        format_bytes(conn.bytes_sent),
        label_style,
        fg(tx()),
    );
    push_detail_field_styled(
        &mut traffic_text,
        &mut Vec::new(),
        "Bytes Received",
        format_bytes(conn.bytes_received),
        label_style,
        fg(rx()),
    );

    let traffic_block = panel_block(" Traffic Statistics ");
    f.render_widget(Paragraph::new(traffic_text).block(traffic_block), chunks[1]);

    Ok(())
}

fn push_detail_field<'a>(
    lines: &mut Vec<Line<'a>>,
    fields: &mut Vec<Option<(String, String)>>,
    label: &str,
    value: String,
    label_style: Style,
) {
    lines.push(Line::from(vec![
        Span::styled(
            format!("{:<width$}", label, width = DETAIL_LABEL_WIDTH),
            label_style,
        ),
        Span::raw(value.clone()),
    ]));
    fields.push(Some((label.to_string(), value)));
}

fn push_detail_field_styled<'a>(
    lines: &mut Vec<Line<'a>>,
    fields: &mut Vec<Option<(String, String)>>,
    label: &str,
    value: String,
    label_style: Style,
    value_style: Style,
) {
    lines.push(Line::from(vec![
        Span::styled(
            format!("{:<width$}", label, width = DETAIL_LABEL_WIDTH),
            label_style,
        ),
        Span::styled(value.clone(), value_style),
    ]));
    fields.push(Some((label.to_string(), value)));
}

fn register_detail_clicks(
    click_regions: &mut ClickableRegions,
    area: Rect,
    fields: &[Option<(String, String)>],
    skip_placeholder: bool,
) {
    let inner = area.inner(Margin {
        horizontal: 1,
        vertical: 1,
    });
    for (idx, entry) in fields.iter().enumerate() {
        if let Some((label, value)) = entry {
            if skip_placeholder && (value == NONE_PLACEHOLDER || value.is_empty()) {
                continue;
            }
            let row_y = inner.y + idx as u16;
            if row_y >= inner.y + inner.height {
                break;
            }
            click_regions.register(
                Rect::new(inner.x, row_y, inner.width, 1),
                ClickAction::CopyField {
                    label: label.clone(),
                    value: value.clone(),
                },
            );
        }
    }
}
