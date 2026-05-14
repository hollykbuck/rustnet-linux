use crate::app::App;
use crate::ui::*;
use ratatui::prelude::*;
use ratatui::widgets::{Cell, Row, Table};

pub fn draw_routes_tab(f: &mut Frame, app: &App, area: Rect) -> anyhow::Result<()> {
    let mut routes = app.get_routes();

    // Sort routes: IPv4 first, then by destination
    routes.sort_by(
        |a, b| match (a.destination.is_ipv4(), b.destination.is_ipv4()) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.destination.cmp(&b.destination),
        },
    );

    if routes.is_empty() {
        let para = Paragraph::new("No routing information available.")
            .block(panel_block(" Routes "))
            .alignment(Alignment::Center);
        f.render_widget(para, area);
        return Ok(());
    }

    let mut rows = Vec::new();
    for route in &routes {
        let destination = format!("{}", route.destination);
        let gateway = route
            .gateway
            .map(|g| g.to_string())
            .unwrap_or_else(|| "*".to_string());
        let mask = if route.destination.is_ipv4() {
            format!("{}", route.netmask)
        } else {
            "---".to_string() // IPv6 doesn't use the same mask field in /proc/net/ipv6_route
        };
        let flags = format!("0x{:X}", route.flags);
        let metric = format!("{}", route.metric);
        let iface = route.interface.clone();

        rows.push(Row::new(vec![
            Cell::from(destination),
            Cell::from(gateway),
            Cell::from(mask),
            Cell::from(iface),
            Cell::from(metric),
            Cell::from(flags),
        ]));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(15),
            Constraint::Percentage(10),
            Constraint::Percentage(10),
        ],
    )
    .header(
        Row::new(vec![
            Cell::from("Destination"),
            Cell::from("Gateway"),
            Cell::from("Netmask"),
            Cell::from("Interface"),
            Cell::from("Metric"),
            Cell::from("Flags"),
        ])
        .style(fg(heading())),
    )
    .block(panel_block(" System Routing Table "))
    .style(Style::default())
    .row_highlight_style(row_highlight());

    f.render_widget(table, area);

    Ok(())
}
