use crate::app::App;
use crate::network::types::RouteEntry;
use crate::ui::*;
use ratatui::widgets::{Cell, Row, Table, TableState};

pub fn draw_routes_tab(
    f: &mut Frame,
    app: &App,
    ui_state: &UIState,
    area: Rect,
    click_regions: &mut ClickableRegions,
) -> anyhow::Result<()> {
    let mut routes = app.get_routes();

    // Filter routes if a query is active
    if !ui_state.filter_query.is_empty() {
        let query = ui_state.filter_query.to_lowercase();
        routes.retain(|r| {
            r.destination.to_string().contains(&query)
                || r.gateway
                    .map(|g| g.to_string())
                    .unwrap_or_default()
                    .contains(&query)
                || r.interface.to_lowercase().contains(&query)
                || interpret_flags(r.flags).to_lowercase().contains(&query)
        });
    }

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
    let mut row_actions = Vec::new();
    let mut display_routes = Vec::new();

    if ui_state.grouping_enabled {
        use std::collections::HashMap;
        let mut groups: HashMap<String, Vec<RouteEntry>> = HashMap::new();
        for r in routes {
            groups.entry(r.interface.clone()).or_default().push(r);
        }

        let mut group_names: Vec<String> = groups.keys().cloned().collect();
        group_names.sort_by_key(|n| n.to_lowercase());

        for name in group_names {
            let group_routes = groups.remove(&name).unwrap();
            let expanded = ui_state.expanded_groups.contains(&name);
            let symbol = if expanded { "▼" } else { "▶" };

            // Group header
            rows.push(
                Row::new(vec![
                    Cell::from(Span::styled(
                        format!("{} Interface: {}", symbol, name),
                        fg(primary()).add_modifier(Modifier::BOLD),
                    )),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(format!("{} routes", group_routes.len())),
                ])
                .style(Style::default()),
            );
            row_actions.push(ClickAction::SelectRoute(row_actions.len()));
            display_routes.push(None); // Header doesn't have a specific route for modal

            if expanded {
                for route in group_routes {
                    rows.push(format_route_row(&route, true));
                    row_actions.push(ClickAction::SelectRoute(row_actions.len()));
                    display_routes.push(Some(route));
                }
            }
        }
    } else {
        for route in routes {
            rows.push(format_route_row(&route, false));
            row_actions.push(ClickAction::SelectRoute(row_actions.len()));
            display_routes.push(Some(route));
        }
    }

    // Register click regions
    let header_height = 3; // Block title + Table header
    for (i, action) in row_actions.iter().enumerate() {
        click_regions.register(
            Rect::new(area.x, area.y + header_height + i as u16, area.width, 1),
            action.clone(),
        );
    }

    let mut state = TableState::default();
    if let Some(selected_idx) = ui_state.selected_route_index {
        state.select(Some(
            selected_idx.saturating_sub(ui_state.routes_scroll_offset),
        ));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(30),
            Constraint::Percentage(25),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
        ],
    )
    .header(
        Row::new(vec![
            Cell::from("Destination"),
            Cell::from("Gateway"),
            Cell::from("Flags"),
            Cell::from("Interface"),
            Cell::from("Metric"),
        ])
        .style(fg(heading())),
    )
    .block(panel_block(format!(
        " System Routing Table {} (Enter for details) ",
        if ui_state.grouping_enabled {
            "(Grouped by Interface)"
        } else {
            ""
        }
    )))
    .row_highlight_style(row_highlight())
    .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut state);

    if ui_state.show_route_modal
        && let Some(idx) = ui_state.selected_route_index
            && let Some(Some(route)) = display_routes.get(idx) {
                draw_route_modal(f, route);
            }

    Ok(())
}

fn format_route_row(route: &RouteEntry, indent: bool) -> Row<'static> {
    let is_unspecified = route.destination.is_unspecified() && route.prefix_len == 0;
    let has_gateway_flag = route.flags & 0x0002 != 0; // RTF_GATEWAY
    let is_default = is_unspecified && has_gateway_flag;

    let dest_style = if is_default {
        fg(ok()).add_modifier(Modifier::BOLD)
    } else if is_unspecified {
        fg(muted())
    } else {
        Style::default()
    };

    let destination = if is_default {
        "default".to_string()
    } else {
        format!("{}/{}", route.destination, route.prefix_len)
    };

    let display_dest = if indent {
        format!("  {}", destination)
    } else {
        destination
    };

    let gateway = route
        .gateway
        .map(|g| g.to_string())
        .unwrap_or_else(|| "*".to_string());

    let flags_str = interpret_flags(route.flags);
    let metric = format!("{}", route.metric);
    let iface = route.interface.clone();

    Row::new(vec![
        Cell::from(Span::styled(display_dest, dest_style)),
        Cell::from(gateway),
        Cell::from(flags_str),
        Cell::from(iface),
        Cell::from(metric),
    ])
}

fn interpret_flags(flags: u32) -> String {
    let mut s = String::new();
    if flags & 0x0001 != 0 {
        s.push('U');
    } // RTF_UP
    if flags & 0x0002 != 0 {
        s.push('G');
    } // RTF_GATEWAY
    if flags & 0x0004 != 0 {
        s.push('H');
    } // RTF_HOST
    if flags & 0x0010 != 0 {
        s.push('D');
    } // RTF_DYNAMIC
    if flags & 0x0020 != 0 {
        s.push('M');
    } // RTF_MODIFIED
    if flags & 0x0100 != 0 {
        s.push('!');
    } // RTF_REJECT
    s
}

fn draw_route_modal(f: &mut Frame, route: &RouteEntry) {
    use crate::ui::components::{Clear, centered_rect};
    let area = centered_rect(60, 50, f.area());
    f.render_widget(Clear, area);

    let block = panel_block(format!(
        " Route Details: {}/{} ",
        route.destination, route.prefix_len
    ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut rows = Vec::new();
    let label_style = fg(label());
    let value_style = fg(primary());

    rows.push(Row::new(vec![
        Cell::from(Span::styled("Destination:", label_style)),
        Cell::from(Span::styled(
            format!("{}/{}", route.destination, route.prefix_len),
            value_style,
        )),
    ]));

    rows.push(Row::new(vec![
        Cell::from(Span::styled("Gateway:", label_style)),
        Cell::from(Span::styled(
            route
                .gateway
                .map(|g| g.to_string())
                .unwrap_or_else(|| "None (Direct)".to_string()),
            value_style,
        )),
    ]));

    rows.push(Row::new(vec![
        Cell::from(Span::styled("Netmask:", label_style)),
        Cell::from(Span::styled(route.netmask.to_string(), value_style)),
    ]));

    rows.push(Row::new(vec![
        Cell::from(Span::styled("Interface:", label_style)),
        Cell::from(Span::styled(route.interface.clone(), value_style)),
    ]));

    rows.push(Row::new(vec![
        Cell::from(Span::styled("Metric:", label_style)),
        Cell::from(Span::styled(route.metric.to_string(), value_style)),
    ]));

    rows.push(Row::new(vec![
        Cell::from(Span::styled("Flags:", label_style)),
        Cell::from(Span::styled(
            format!("0x{:X} ({})", route.flags, interpret_flags(route.flags)),
            value_style,
        )),
    ]));

    if let Some(proto) = &route.protocol {
        rows.push(Row::new(vec![
            Cell::from(Span::styled("Protocol:", label_style)),
            Cell::from(Span::styled(proto.clone(), value_style)),
        ]));
    }

    if let Some(scope) = &route.scope {
        rows.push(Row::new(vec![
            Cell::from(Span::styled("Scope:", label_style)),
            Cell::from(Span::styled(scope.clone(), value_style)),
        ]));
    }

    if let Some(src) = &route.pref_src {
        rows.push(Row::new(vec![
            Cell::from(Span::styled("Preferred Src:", label_style)),
            Cell::from(Span::styled(src.to_string(), value_style)),
        ]));
    }

    let table =
        Table::new(rows, [Constraint::Length(15), Constraint::Min(0)]).style(Style::default());

    f.render_widget(table, inner);

    // Help text at bottom of modal
    let help_text = " Press Esc or Enter to close ";
    let help = Paragraph::new(help_text)
        .alignment(Alignment::Center)
        .style(fg(muted()));
    let help_area = Rect::new(inner.x, inner.y + inner.height - 1, inner.width, 1);
    f.render_widget(help, help_area);
}
