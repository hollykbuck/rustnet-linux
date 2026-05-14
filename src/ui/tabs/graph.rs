use ratatui::prelude::*;
use ratatui::widgets::{Chart, Dataset, GraphType, Sparkline, Paragraph, Table, Row, Cell, Axis};
use crate::app::App;
use crate::network::types::{Connection, Protocol, ProtocolState, TcpState, AppProtocolDistribution, TrafficHistory};
use crate::ui::*;

pub fn draw_graph_tab(f: &mut Frame, app: &App, connections: &[Connection], area: Rect) -> anyhow::Result<()> {
    let active_connections: Vec<Connection> = connections
        .iter()
        .filter(|c| !c.is_historic)
        .cloned()
        .collect();
    let connections = &active_connections;

    let traffic_history = app.get_traffic_history();

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Percentage(20),
            Constraint::Min(0),
        ])
        .split(area);

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(main_chunks[0]);

    let health_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Percentage(35),
            Constraint::Percentage(30),
        ])
        .split(main_chunks[1]);

    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[2]);

    draw_traffic_chart(f, &traffic_history, top_chunks[0]);
    draw_connections_sparkline(f, &traffic_history, top_chunks[1]);
    draw_health_chart(f, &traffic_history, health_chunks[0]);
    draw_tcp_counters(f, app, health_chunks[1]);
    draw_tcp_states(f, connections, health_chunks[2]);
    draw_app_distribution(f, connections, bottom_chunks[0]);
    draw_top_processes(f, connections, bottom_chunks[1]);

    Ok(())
}

fn draw_traffic_chart(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let block = panel_block(" Traffic Over Time (60s) ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if !history.has_enough_data() {
        let placeholder = Paragraph::new("Collecting data...").style(fg(muted()));
        f.render_widget(placeholder, inner);
        return;
    }

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);
    let chart_area = layout[0];
    let legend_area = layout[1];

    let legend = Paragraph::new(Line::from(vec![
        Span::styled("▬ RX (incoming) ↓", fg(rx())),
        Span::raw("   "),
        Span::styled("▬ TX (outgoing) ↑", fg(tx())),
    ]));
    f.render_widget(legend, legend_area);

    let (rx_data, tx_data) = history.get_chart_data();
    let max_rate = rx_data.iter().chain(tx_data.iter()).map(|(_, y)| *y).fold(0.0f64, |a, b| a.max(b)).max(1024.0);

    let datasets = vec![
        Dataset::default().marker(symbols::Marker::Braille).graph_type(GraphType::Line).style(fg(rx())).data(&rx_data),
        Dataset::default().marker(symbols::Marker::Braille).graph_type(GraphType::Line).style(fg(tx())).data(&tx_data),
    ];

    let chart = Chart::new(datasets)
        .x_axis(Axis::default().title("Time").style(fg(muted())).bounds([-60.0, 0.0]).labels(vec![Line::from("-60s"), Line::from("-30s"), Line::from("now")]))
        .y_axis(Axis::default().title("Rate").style(fg(muted())).bounds([0.0, max_rate]).labels(vec![Line::from("0"), Line::from(format_rate_compact(max_rate / 2.0)), Line::from(format_rate_compact(max_rate))]));

    f.render_widget(chart, chart_area);
}

fn draw_connections_sparkline(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let block = panel_block(" Connections ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if !history.has_enough_data() {
        let placeholder = Paragraph::new("Collecting...").style(fg(muted()));
        f.render_widget(placeholder, inner);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let width = inner.width as usize;
    let conn_data = history.get_connection_sparkline_data(width);
    let sparkline = Sparkline::default().data(&conn_data).style(fg(accent()));
    f.render_widget(sparkline, chunks[0]);

    let current_count = conn_data.last().copied().unwrap_or(0);
    let label = Paragraph::new(format!("{} active connections", current_count));
    f.render_widget(label, chunks[1]);
}

fn draw_app_distribution(f: &mut Frame, connections: &[Connection], area: Rect) {
    let block = panel_block(" Application Distribution ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let dist = AppProtocolDistribution::from_connections(connections);
    let percentages = dist.as_percentages();

    const LABEL_WIDTH: usize = 6;
    const PCT_WIDTH: usize = 6;
    const SPACERS_AND_PAD: usize = 3;
    let bar_width = (inner.width as usize).saturating_sub(LABEL_WIDTH + PCT_WIDTH + SPACERS_AND_PAD).max(1);
    let mut lines: Vec<Line> = Vec::new();

    for (label, count, pct) in percentages {
        if count == 0 { continue; }
        let filled = ((pct / 100.0) * bar_width as f64) as usize;
        let bar: String = "█".repeat(filled) + &"░".repeat(bar_width.saturating_sub(filled));
        let color = match label {
            "HTTPS" => proto_https(),
            "QUIC" => proto_quic(),
            "HTTP" => proto_http(),
            "DNS" => proto_dns(),
            "SSH" => proto_ssh(),
            _ => proto_other(),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{:<width$}", label, width = LABEL_WIDTH), fg(color)),
            Span::raw(" "),
            Span::styled(bar, fg(color)),
            Span::raw(format!(" {:>5.1}%", pct)),
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled("No connections", fg(muted()))));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_top_processes(f: &mut Frame, connections: &[Connection], area: Rect) {
    let block = panel_block(" Top Processes ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut process_traffic: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    for conn in connections {
        let name = conn.process_name.clone().unwrap_or_else(|| "Unknown".to_string());
        let traffic = conn.current_incoming_rate_bps + conn.current_outgoing_rate_bps;
        *process_traffic.entry(name).or_insert(0.0) += traffic;
    }

    let mut sorted: Vec<_> = process_traffic.into_iter().filter(|(_, rate)| *rate > 0.0).collect();
    sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let rows: Vec<Row> = sorted.into_iter().take(5).map(|(name, rate)| {
        let display_name = if name.len() > 20 { format!("{}...", &name[..17]) } else { name };
        Row::new(vec![Cell::from(display_name), Cell::from(Line::from(format_rate(rate)).right_aligned()).style(fg(accent()))])
    }).collect();

    if rows.is_empty() {
        f.render_widget(Paragraph::new("No active processes").style(fg(muted())), inner);
        return;
    }

    let table = Table::new(rows, [Constraint::Min(0), Constraint::Length(12)]).header(Row::new(vec![Cell::from("Process"), Cell::from(Line::from("Rate").right_aligned())]).style(fg(heading())));
    f.render_widget(table, inner);
}

fn draw_health_chart(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let block = panel_block(" Network Health ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if !history.has_enough_data() {
        f.render_widget(Paragraph::new("Collecting data...").style(fg(muted())), inner);
        return;
    }

    let (loss_data, rtt_data) = history.get_health_chart_data();
    let current_loss = loss_data.last().map(|(_, v)| *v).unwrap_or(0.0);
    let current_rtt = rtt_data.last().map(|(_, v)| *v);

    let avg_loss = if !loss_data.is_empty() { loss_data.iter().map(|(_, v)| v).sum::<f64>() / loss_data.len() as f64 } else { 0.0 };
    let avg_rtt = if !rtt_data.is_empty() { Some(rtt_data.iter().map(|(_, v)| v).sum::<f64>() / rtt_data.len() as f64) } else { None };

    const RTT_MAX: f64 = 200.0;
    const LOSS_MAX: f64 = 10.0;
    let bar_width = (inner.width as usize).saturating_sub(18).max(1);

    let rtt_line = if let Some(rtt) = current_rtt {
        let rtt_pct = (rtt / RTT_MAX).min(1.0);
        let filled = (rtt_pct * bar_width as f64) as usize;
        let empty = bar_width.saturating_sub(filled);
        let color = if rtt < 50.0 { ok() } else if rtt < 150.0 { warn() } else { err() };
        Line::from(vec![Span::styled("  RTT  ", Style::default().add_modifier(Modifier::BOLD)), Span::styled("█".repeat(filled), fg(color)), Span::styled("░".repeat(empty), fg(muted())), Span::styled(format!(" {:>6.1}ms", rtt), fg(color))])
    } else {
        Line::from(vec![Span::styled("  RTT  ", Style::default().add_modifier(Modifier::BOLD)), Span::styled("░".repeat(bar_width), fg(muted())), Span::styled("    --  ", fg(muted()))])
    };

    let loss_pct = (current_loss / LOSS_MAX).min(1.0);
    let filled = (loss_pct * bar_width as f64) as usize;
    let empty = bar_width.saturating_sub(filled);
    let loss_color = if current_loss < 1.0 { ok() } else if current_loss < 5.0 { warn() } else { err() };
    let loss_line = Line::from(vec![Span::styled("  Loss ", Style::default().add_modifier(Modifier::BOLD)), Span::styled("█".repeat(filled.max(if current_loss > 0.0 { 1 } else { 0 })), fg(loss_color)), Span::styled("░".repeat(empty.min(bar_width)), fg(muted())), Span::styled(format!(" {:>6.2}%", current_loss), fg(loss_color))]);

    let avg_line = Line::from(vec![Span::styled("  avg: ", fg(muted())), Span::styled(avg_rtt.map(|r| format!("{:.0}ms", r)).unwrap_or_else(|| "--".to_string()), fg(muted())), Span::styled(" / ", fg(muted())), Span::styled(format!("{:.2}%", avg_loss), fg(muted()))]);

    f.render_widget(Paragraph::new(vec![rtt_line, loss_line, avg_line]), inner);
}

fn draw_tcp_counters(f: &mut Frame, app: &App, area: Rect) {
    use std::sync::atomic::Ordering;
    let stats = app.get_stats();
    let retransmits = stats.total_tcp_retransmits.load(Ordering::Relaxed);
    let out_of_order = stats.total_tcp_out_of_order.load(Ordering::Relaxed);
    let fast_retransmits = stats.total_tcp_fast_retransmits.load(Ordering::Relaxed);
    let block = panel_block(" TCP Counters ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let retrans_color = if retransmits == 0 { ok() } else if retransmits < 100 { warn() } else { err() };
    let ooo_color = if out_of_order == 0 { ok() } else if out_of_order < 50 { warn() } else { err() };
    let fast_color = if fast_retransmits == 0 { ok() } else if fast_retransmits < 50 { warn() } else { err() };

    let lines = vec![
        Line::from(vec![Span::styled("  Retransmits  ", Style::default().add_modifier(Modifier::BOLD)), Span::styled(format!("{:>8}", retransmits), fg(retrans_color))]),
        Line::from(vec![Span::styled("  Out of Order ", Style::default().add_modifier(Modifier::BOLD)), Span::styled(format!("{:>8}", out_of_order), fg(ooo_color))]),
        Line::from(vec![Span::styled("  Fast Retrans ", Style::default().add_modifier(Modifier::BOLD)), Span::styled(format!("{:>8}", fast_retransmits), fg(fast_color))]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_tcp_states(f: &mut Frame, connections: &[Connection], area: Rect) {
    let mut state_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for conn in connections {
        if conn.protocol == Protocol::Tcp && let ProtocolState::Tcp(tcp_state) = &conn.protocol_state {
            let state_name = match tcp_state {
                TcpState::Established => "ESTAB",
                TcpState::SynSent => "SYN_SENT",
                TcpState::SynReceived => "SYN_RECV",
                TcpState::FinWait1 => "FIN_WAIT1",
                TcpState::FinWait2 => "FIN_WAIT2",
                TcpState::TimeWait => "TIME_WAIT",
                TcpState::CloseWait => "CLOSE_WAIT",
                TcpState::LastAck => "LAST_ACK",
                TcpState::Closing => "CLOSING",
                TcpState::Closed => "CLOSED",
                TcpState::Unknown => "UNKNOWN",
            };
            *state_counts.entry(state_name).or_insert(0) += 1;
        }
    }

    const STATE_ORDER: &[&str] = &["ESTAB", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE_WAIT", "LAST_ACK", "CLOSING", "CLOSED", "LISTEN", "UNKNOWN"];
    let states: Vec<_> = STATE_ORDER.iter().filter_map(|&name| state_counts.get(name).map(|&count| (name, count))).collect();

    let block = panel_block(" TCP States ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if states.is_empty() {
        f.render_widget(Paragraph::new("No TCP connections").style(fg(muted())), inner);
        return;
    }

    let max_count = states.iter().map(|(_, c)| *c).max().unwrap_or(1);
    let bar_width = (inner.width as usize).saturating_sub(17).max(1);
    let max_rows = inner.height as usize;
    let lines: Vec<Line> = states.iter().take(max_rows).map(|(name, count)| {
        let bar_len = (*count * bar_width).checked_div(max_count).unwrap_or(0);
        let bar = "█".repeat(bar_len.max(1).min(bar_width));
        let color = match *name {
            "ESTAB" => tcp_established(),
            "SYN_SENT" | "SYN_RECV" => tcp_opening(),
            "TIME_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" => tcp_closing(),
            "CLOSE_WAIT" | "LAST_ACK" | "CLOSING" => tcp_waiting(),
            "CLOSED" => tcp_closed(),
            _ => Color::Reset,
        };
        Line::from(vec![Span::styled(format!("{:>10} ", name), fg(color)), Span::styled(bar, fg(color)), Span::raw(format!(" {:>4}", count))])
    }).collect();

    f.render_widget(Paragraph::new(lines), inner);
}
