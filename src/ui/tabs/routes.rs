use crate::app::App;
use crate::network::types::RouteEntry;
use crate::ui::*;
use ratatui::widgets::{Cell, Row, Table, TableState};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum RouteRow {
    Group {
        table_id: u32,
        group_name: String,
        route_count: usize,
        expanded: bool,
    },
    Route {
        route: RouteEntry,
        indented: bool,
    },
}

pub fn route_table_name(table_id: u32) -> String {
    match table_id {
        254 => "Main".to_string(),
        255 => "Local".to_string(),
        253 => "Default".to_string(),
        _ => format!("Table {}", table_id),
    }
}

pub fn filtered_sorted_routes(app: &App, ui_state: &UIState) -> Vec<RouteEntry> {
    let mut routes = app.get_routes();

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

    routes.sort_by(
        |a, b| match (a.destination.is_ipv4(), b.destination.is_ipv4()) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.destination.cmp(&b.destination),
        },
    );

    routes
}

pub fn visible_route_rows(app: &App, ui_state: &UIState) -> Vec<RouteRow> {
    let routes = filtered_sorted_routes(app, ui_state);
    let mut rows = Vec::new();

    if ui_state.route_grouping_enabled {
        let mut groups: HashMap<u32, Vec<RouteEntry>> = HashMap::new();
        for route in routes {
            groups.entry(route.table_id).or_default().push(route);
        }

        let mut table_ids: Vec<u32> = groups.keys().cloned().collect();
        table_ids.sort();

        for table_id in table_ids {
            let group_routes = groups.remove(&table_id).unwrap_or_default();
            let group_name = route_table_name(table_id);
            let expanded = ui_state.route_expanded_groups.contains(&group_name);
            rows.push(RouteRow::Group {
                table_id,
                group_name,
                route_count: group_routes.len(),
                expanded,
            });

            if expanded {
                rows.extend(group_routes.into_iter().map(|route| RouteRow::Route {
                    route,
                    indented: true,
                }));
            }
        }
    } else {
        rows.extend(routes.into_iter().map(|route| RouteRow::Route {
            route,
            indented: false,
        }));
    }

    rows
}

pub fn selected_route(ui_state: &UIState, rows: &[RouteRow]) -> Option<RouteEntry> {
    match ui_state.selected_route_index.and_then(|idx| rows.get(idx)) {
        Some(RouteRow::Route { route, .. }) => Some(route.clone()),
        _ => None,
    }
}

pub fn selected_route_group_name(ui_state: &UIState, rows: &[RouteRow]) -> Option<String> {
    match ui_state.selected_route_index.and_then(|idx| rows.get(idx)) {
        Some(RouteRow::Group { group_name, .. }) => Some(group_name.clone()),
        _ => None,
    }
}

pub fn draw_routes_tab(
    f: &mut Frame,
    app: &App,
    ui_state: &UIState,
    area: Rect,
    click_regions: &mut ClickableRegions,
) -> anyhow::Result<()> {
    let route_rows = visible_route_rows(app, ui_state);

    if route_rows.is_empty() {
        let para = Paragraph::new("No routing information available.")
            .block(panel_block(" Routes "))
            .alignment(Alignment::Center);
        f.render_widget(para, area);
        return Ok(());
    }

    let mut rows: Vec<Row<'static>> = Vec::new();
    let mut row_actions = Vec::new();

    for route_row in &route_rows {
        let row_idx = row_actions.len();
        match route_row {
            RouteRow::Group {
                table_id,
                group_name,
                route_count,
                expanded,
            } => {
                let symbol = if *expanded { "▼" } else { "▶" };
                rows.push(
                    Row::new(vec![
                        Cell::from(Span::styled(
                            format!("{} Routing Table: {}", symbol, group_name),
                            fg(primary()).add_modifier(Modifier::BOLD),
                        )),
                        Cell::from(""),
                        Cell::from(""),
                        Cell::from(format!("ID {}", table_id)),
                        Cell::from(format!("{} routes", route_count)),
                    ])
                    .style(Style::default()),
                );
            }
            RouteRow::Route { route, indented } => {
                rows.push(format_route_row(route, *indented));
            }
        }
        row_actions.push(ClickAction::SelectRoute(row_idx));
    }

    let scroll_offset = ui_state.routes_scroll_offset;
    let visible_rows = ui_state.visible_rows.max(1);
    let total_rows = rows.len();
    let window_end = (scroll_offset + visible_rows).min(total_rows);
    let visible_rows_subset = &rows[scroll_offset.min(total_rows)..window_end];

    // Register click regions
    let header_height = 2; // Block border + Table header
    for (i, row_idx) in (scroll_offset..window_end).enumerate() {
        if let Some(action) = row_actions.get(row_idx) {
            click_regions.register(
                Rect::new(area.x, area.y + header_height + i as u16, area.width, 1),
                action.clone(),
            );
        }
    }

    let mut state = TableState::default();
    if let Some(selected_idx) = ui_state.selected_route_index {
        state.select(Some(
            selected_idx.saturating_sub(ui_state.routes_scroll_offset),
        ));
    }

    let table = Table::new(
        visible_rows_subset.to_vec(),
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
        " System Routing Table {} (Enter for details, Space to toggle) ",
        if ui_state.route_grouping_enabled {
            "(Grouped by Table)"
        } else {
            ""
        }
    )))
    .row_highlight_style(row_highlight())
    .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut state);

    if ui_state.show_route_modal
        && let Some(route) = selected_route(ui_state, &route_rows)
    {
        draw_route_modal(f, &route);
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
