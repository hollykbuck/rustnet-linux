use crate::app::App;
use crate::ui::*;
use ratatui::widgets::{Cell, Row, Table, TableState};

pub fn draw_interface_stats(
    f: &mut Frame,
    app: &App,
    ui_state: &UIState,
    area: Rect,
    click_regions: &mut ClickableRegions,
) -> anyhow::Result<()> {
    let stats = app.get_sorted_interface_stats();
    let rates = app.get_interface_rates();

    if stats.is_empty() {
        return Ok(());
    }

    let mut rows = Vec::new();
    for (i, stat) in stats.iter().enumerate() {
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
            Cell::from(stat.description.clone().unwrap_or_else(|| "---".to_string())),
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

        // Register click region for each row
        click_regions.register(
            Rect::new(area.x, area.y + 3 + i as u16, area.width, 1),
            ClickAction::SelectInterface(i),
        );
    }

    let mut state = TableState::default();
    if let Some(selected_idx) = ui_state.get_selected_interface_index(&stats) {
        state.select(Some(selected_idx.saturating_sub(ui_state.interfaces_scroll_offset)));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Length(15),
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
            Cell::from("Type"),
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
    .block(panel_block(" Interface Statistics (Enter for details) "))
    .row_highlight_style(row_highlight())
    .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut state);

    if ui_state.show_interface_modal {
        if let Some(idx) = ui_state.get_selected_interface_index(&stats) {
            if let Some(stat) = stats.get(idx) {
                draw_interface_modal(f, stat, rates.get(&stat.interface_name));
            }
        }
    }

    Ok(())
}

fn draw_interface_modal(
    f: &mut Frame,
    stat: &crate::network::interface_stats::InterfaceStats,
    rates: Option<&crate::network::interface_stats::InterfaceRates>,
) {
    use crate::ui::components::{Clear, centered_rect};
    let area = centered_rect(60, 60, f.area());
    f.render_widget(Clear, area);

    let block = panel_block(format!(" Interface Details: {} ", stat.interface_name));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut rows = Vec::new();
    let label_style = fg(label());
    let value_style = fg(primary());

    rows.push(Row::new(vec![
        Cell::from(Span::styled("Name:", label_style)),
        Cell::from(Span::styled(stat.interface_name.clone(), value_style)),
    ]));
    rows.push(Row::new(vec![
        Cell::from(Span::styled("Type:", label_style)),
        Cell::from(Span::styled(
            stat.description.clone().unwrap_or_else(|| "Unknown".to_string()),
            value_style,
        )),
    ]));
    rows.push(Row::new(vec![
        Cell::from(Span::styled("RX Bytes:", label_style)),
        Cell::from(Span::styled(
            format!("{} ({})", stat.rx_bytes, format_bytes(stat.rx_bytes)),
            value_style,
        )),
    ]));
    rows.push(Row::new(vec![
        Cell::from(Span::styled("TX Bytes:", label_style)),
        Cell::from(Span::styled(
            format!("{} ({})", stat.tx_bytes, format_bytes(stat.tx_bytes)),
            value_style,
        )),
    ]));

    if let Some(r) = rates {
        rows.push(Row::new(vec![
            Cell::from(Span::styled("RX Rate:", label_style)),
            Cell::from(Span::styled(format!("{}/s", format_bytes(r.rx_bytes_per_sec)), value_style)),
        ]));
        rows.push(Row::new(vec![
            Cell::from(Span::styled("TX Rate:", label_style)),
            Cell::from(Span::styled(format!("{}/s", format_bytes(r.tx_bytes_per_sec)), value_style)),
        ]));
    }

    rows.push(Row::new(vec![
        Cell::from(Span::styled("RX Packets:", label_style)),
        Cell::from(Span::styled(stat.rx_packets.to_string(), value_style)),
    ]));
    rows.push(Row::new(vec![
        Cell::from(Span::styled("TX Packets:", label_style)),
        Cell::from(Span::styled(stat.tx_packets.to_string(), value_style)),
    ]));
    rows.push(Row::new(vec![
        Cell::from(Span::styled("RX Errors:", label_style)),
        Cell::from(Span::styled(stat.rx_errors.to_string(), value_style)),
    ]));
    rows.push(Row::new(vec![
        Cell::from(Span::styled("TX Errors:", label_style)),
        Cell::from(Span::styled(stat.tx_errors.to_string(), value_style)),
    ]));
    rows.push(Row::new(vec![
        Cell::from(Span::styled("RX Dropped:", label_style)),
        Cell::from(Span::styled(stat.rx_dropped.to_string(), value_style)),
    ]));
    rows.push(Row::new(vec![
        Cell::from(Span::styled("TX Dropped:", label_style)),
        Cell::from(Span::styled(stat.tx_dropped.to_string(), value_style)),
    ]));
    rows.push(Row::new(vec![
        Cell::from(Span::styled("Collisions:", label_style)),
        Cell::from(Span::styled(stat.collisions.to_string(), value_style)),
    ]));

    let table = Table::new(rows, [Constraint::Length(15), Constraint::Min(0)]).style(Style::default());

    f.render_widget(table, inner);

    // Help text at bottom of modal
    let help_text = " Press Esc or Enter to close ";
    let help = Paragraph::new(help_text)
        .alignment(Alignment::Center)
        .style(fg(muted()));
    let help_area = Rect::new(inner.x, inner.y + inner.height - 1, inner.width, 1);
    f.render_widget(help, help_area);
}
