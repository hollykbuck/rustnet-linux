use crate::app::App;
use crate::ui::*;
use ratatui::widgets::{Cell, Row, Table};

pub fn draw_interface_stats(f: &mut Frame, app: &App, area: Rect) -> anyhow::Result<()> {
    let mut stats = app.get_interface_stats();
    let rates = app.get_interface_rates();

    let captured_interface = app.get_current_interface();
    if let Some(ref captured) = captured_interface {
        stats.sort_by(|a, b| {
            let a_is_captured = &a.interface_name == captured;
            let b_is_captured = &b.interface_name == captured;
            match (a_is_captured, b_is_captured) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.interface_name.cmp(&b.interface_name),
            }
        });
    }

    if stats.is_empty() {
        return Ok(());
    }

    let mut rows = Vec::new();
    for stat in &stats {
        let error_style = if stat.rx_errors > 0 || stat.tx_errors > 0 {
            fg(err())
        } else {
            fg(ok())
        };
        let drop_style = if stat.rx_dropped > 0 || stat.tx_dropped > 0 {
            fg(warn())
        } else {
            fg(ok())
        };

        let rx_rate_str = if let Some(rate) = rates.get(&stat.interface_name) {
            format!("{}/s", format_bytes(rate.rx_bytes_per_sec))
        } else {
            "---".to_string()
        };
        let tx_rate_str = if let Some(rate) = rates.get(&stat.interface_name) {
            format!("{}/s", format_bytes(rate.tx_bytes_per_sec))
        } else {
            "---".to_string()
        };

        let right = |s: String| Cell::from(Line::from(s).right_aligned());
        let right_styled = |s: String, style: Style| {
            Cell::from(Line::from(Span::styled(s, style)).right_aligned())
        };

        rows.push(Row::new(vec![
            Cell::from(stat.interface_name.clone()),
            right(rx_rate_str),
            right(tx_rate_str),
            right(format!("{}", stat.rx_packets)),
            right(format!("{}", stat.tx_packets)),
            right_styled(format!("{}", stat.rx_errors), error_style),
            right_styled(format!("{}", stat.tx_errors), error_style),
            right_styled(format!("{}", stat.rx_dropped), drop_style),
            right_styled(format!("{}", stat.tx_dropped), drop_style),
            right(format!("{}", stat.collisions)),
        ]));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header({
        let right = |s: &str| Cell::from(Line::from(s.to_string()).right_aligned());
        Row::new(vec![
            Cell::from("Interface"),
            right("RX Rate"),
            right("TX Rate"),
            right("RX Packets"),
            right("TX Packets"),
            right("RX Err"),
            right("TX Err"),
            right("RX Drop"),
            right("TX Drop"),
            right("Collisions"),
        ])
        .style(fg(heading()))
    })
    .block(panel_block(" Interface Statistics (Press 'i' to toggle) "))
    .style(Style::default());

    f.render_widget(table, area);

    Ok(())
}
