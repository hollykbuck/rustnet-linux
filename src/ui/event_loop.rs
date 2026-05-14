use crate::app::App;
use crate::ui::*;
use anyhow::Result;
use log::error;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Run the UI loop
pub fn run_ui_loop<B: ratatui::prelude::Backend>(
    terminal: &mut crate::ui::Terminal<B>,
    app: &App,
) -> Result<()>
where
    <B as ratatui::prelude::Backend>::Error: Send + Sync + 'static,
{
    let tick_rate = Duration::from_millis(200);
    let mut last_tick = Instant::now();
    let mut ui_state = UIState::default();
    let (has_country_db, _, _) = app.get_geoip_status();
    ui_state.has_geoip = has_country_db;
    let mut click_regions = ClickableRegions::default();

    // Data state persists across loop iterations — only refreshed on timer tick
    // or when an event changes the underlying data (filter, sort, historic toggle, etc.)
    let mut connections = Vec::new();
    let mut grouped_rows = Vec::new();
    let mut listeners = Vec::new();
    let mut devices = Vec::new();
    let mut stats = app.get_stats();
    let mut needs_data_refresh = true;
    let mut needs_regroup = false;

    loop {
        // Refresh connection data only when needed
        if needs_data_refresh || last_tick.elapsed() >= tick_rate {
            connections = if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
                app.get_connections()
            } else {
                app.get_filtered_connections(&ui_state.filter_query)
            };
            crate::app::state::sort_connections(
                &mut connections,
                ui_state.sort_column,
                ui_state.sort_ascending,
            );
            grouped_rows = if ui_state.grouping_enabled {
                compute_grouped_rows(&connections, &ui_state.expanded_groups)
            } else {
                Vec::new()
            };
            listeners = app.get_listeners();
            devices = app.get_devices();
            stats = app.get_stats();
            last_tick = Instant::now();
            needs_data_refresh = false;
            needs_regroup = false;
        } else if needs_regroup {
            grouped_rows = if ui_state.grouping_enabled {
                compute_grouped_rows(&connections, &ui_state.expanded_groups)
            } else {
                Vec::new()
            };
            needs_regroup = false;
        }

        // Ensure we have a valid selection
        if ui_state.grouping_enabled {
            ui_state.ensure_valid_grouped_selection(&grouped_rows);
            let selected_idx = ui_state
                .get_selected_grouped_index(&grouped_rows)
                .unwrap_or(0);
            ui_state.grouped_scroll_offset = compute_scroll_offset(
                selected_idx,
                ui_state.grouped_scroll_offset,
                ui_state.visible_rows,
                grouped_rows.len(),
            );
        } else if ui_state.selected_tab == 2 {
            let mut listeners_sorted = listeners.clone();
            listeners_sorted.sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
            let selected_idx = ui_state
                .get_selected_service_index(&listeners_sorted)
                .unwrap_or(0);
            ui_state.services_scroll_offset = compute_scroll_offset(
                selected_idx,
                ui_state.services_scroll_offset,
                ui_state.visible_rows,
                listeners_sorted.len(),
            );
        } else if ui_state.selected_tab == 1 {
            let mut devices_sorted = devices.clone();
            devices_sorted.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
            let selected_idx = ui_state
                .get_selected_device_index(&devices_sorted)
                .unwrap_or(0);
            ui_state.devices_scroll_offset = compute_scroll_offset(
                selected_idx,
                ui_state.devices_scroll_offset,
                ui_state.visible_rows,
                devices_sorted.len(),
            );
        } else if ui_state.selected_tab == 4 {
            let stats = app.get_sorted_interface_stats();
            let selected_idx = ui_state.get_selected_interface_index(&stats).unwrap_or(0);
            ui_state.interfaces_scroll_offset = compute_scroll_offset(
                selected_idx,
                ui_state.interfaces_scroll_offset,
                ui_state.visible_rows,
                stats.len(),
            );
        } else if ui_state.selected_tab == 5 {
            let routes = app.get_routes();
            let selected_idx = ui_state.selected_route_index.unwrap_or(0);
            ui_state.routes_scroll_offset = compute_scroll_offset(
                selected_idx,
                ui_state.routes_scroll_offset,
                ui_state.visible_rows,
                routes.len(),
            );
        } else {
            ui_state.ensure_valid_selection(&connections);
            let selected_idx = ui_state.get_selected_index(&connections).unwrap_or(0);
            ui_state.scroll_offset = compute_scroll_offset(
                selected_idx,
                ui_state.scroll_offset,
                ui_state.visible_rows,
                connections.len(),
            );
        }

        // Draw the UI
        terminal.draw(|f| {
            let grouped = if ui_state.grouping_enabled {
                Some(grouped_rows.as_slice())
            } else {
                None
            };
            if let Err(err) = draw(
                f,
                app,
                &ui_state,
                &connections,
                grouped,
                &stats,
                &mut click_regions,
            ) {
                error!("UI draw error: {}", err);
            }
        })?;

        // Update visible rows for page navigation based on terminal height
        if let Ok(size) = terminal.size() {
            let chrome = if ui_state.filter_mode || !ui_state.filter_query.is_empty() {
                11
            } else {
                8
            };
            ui_state.visible_rows = (size.height as usize).saturating_sub(chrome);
        }

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_secs(0));

        if let Some((_, time)) = &ui_state.clipboard_message
            && time.elapsed().as_secs() >= 3
        {
            ui_state.clipboard_message = None;
        }

        if crossterm::event::poll(timeout)? {
            let event = crossterm::event::read()?;
            match event {
                crossterm::event::Event::Mouse(mouse) => {
                    handle_mouse_event(
                        mouse,
                        &mut ui_state,
                        &click_regions,
                        app,
                        &connections,
                        &grouped_rows,
                        &listeners,
                        &devices,
                        &mut needs_regroup,
                    );
                }
                crossterm::event::Event::Key(key)
                    if handle_key_event(
                        key,
                        &mut ui_state,
                        app,
                        &connections,
                        &grouped_rows,
                        &listeners,
                        &devices,
                        &mut needs_data_refresh,
                        &mut needs_regroup,
                    )? =>
                {
                    break;
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn handle_mouse_event(
    mouse: crossterm::event::MouseEvent,
    ui_state: &mut UIState,
    click_regions: &ClickableRegions,
    app: &App,
    connections: &[crate::network::types::Connection],
    grouped_rows: &[GroupedRow],
    listeners: &[crate::network::types::Listener],
    devices: &[crate::network::types::Device],
    needs_regroup: &mut bool,
) {
    use crossterm::event::{MouseButton, MouseEventKind};

    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            ui_state.quit_confirmation = false;
            ui_state.clear_confirmation = false;
            ui_state.show_interface_modal = false;
            ui_state.show_route_modal = false;
            ui_state.show_device_modal = false;
            ui_state.show_service_modal = false;

            let is_double_click = if let Some((_, prev_row, prev_time)) = ui_state.last_click {
                prev_row == mouse.row && prev_time.elapsed().as_millis() < 400
            } else {
                false
            };
            ui_state.last_click = Some((mouse.column, mouse.row, Instant::now()));

            if let Some(action) = click_regions.hit_test(mouse.column, mouse.row) {
                match action.clone() {
                    ClickAction::SwitchTab(tab_idx) => {
                        ui_state.selected_tab = tab_idx;
                        if tab_idx == 0 {
                            ui_state.details_view_mode = DetailsViewMode::Connection;
                        } else if tab_idx == 1 {
                            ui_state.details_view_mode = DetailsViewMode::Device;
                        } else if tab_idx == 2 {
                            ui_state.details_view_mode = DetailsViewMode::Service;
                        }
                    }
                    ClickAction::SelectConnection(conn_idx) => {
                        ui_state.details_view_mode = DetailsViewMode::Connection;
                        if ui_state.grouping_enabled {
                            ui_state.set_selected_grouped_by_index(grouped_rows, conn_idx);
                            if is_double_click && let Some(row) = grouped_rows.get(conn_idx) {
                                match row {
                                    GroupedRow::Group { .. } => {
                                        ui_state.toggle_group_expansion();
                                        *needs_regroup = true;
                                    }
                                    GroupedRow::Connection { .. } => {
                                        ui_state.selected_tab = 3;
                                    }
                                }
                            }
                        } else {
                            ui_state.set_selected_by_index(connections, conn_idx);
                            if is_double_click {
                                ui_state.selected_tab = 3;
                            }
                        }
                    }
                    ClickAction::SelectService(service_idx) => {
                        ui_state.details_view_mode = DetailsViewMode::Service;
                        let mut listeners_sorted = listeners.to_vec();
                        listeners_sorted
                            .sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
                        ui_state.set_selected_service_by_index(&listeners_sorted, service_idx);
                        if is_double_click {
                            ui_state.show_service_modal = true;
                        }
                    }
                    ClickAction::SelectDevice(device_idx) => {
                        ui_state.details_view_mode = DetailsViewMode::Device;
                        let mut devices_sorted = devices.to_vec();
                        devices_sorted.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                        ui_state.set_selected_device_by_index(&devices_sorted, device_idx);
                        if is_double_click {
                            ui_state.show_device_modal = true;
                        }
                    }
                    ClickAction::SelectInterface(idx) => {
                        let stats = app.get_sorted_interface_stats();
                        ui_state.set_selected_interface_by_index(&stats, idx);
                        ui_state.show_interface_modal = true;
                    }
                    ClickAction::SelectRoute(idx) => {
                        ui_state.selected_route_index = Some(idx);
                        if ui_state.grouping_enabled && is_double_click {
                            // If double-clicking in grouped mode, try to toggle expansion or open modal
                            // We need to re-derive the routes and groupings to know what was clicked
                            let routes = app.get_routes();
                            let mut groups: HashMap<
                                String,
                                Vec<crate::network::types::RouteEntry>,
                            > = HashMap::new();
                            for r in routes {
                                groups.entry(r.interface.clone()).or_default().push(r);
                            }
                            let mut group_names: Vec<String> = groups.keys().cloned().collect();
                            group_names.sort_by_key(|n| n.to_lowercase());

                            let mut current_idx = 0;
                            for name in group_names {
                                if current_idx == idx {
                                    // Clicked on group header
                                    if ui_state.expanded_groups.contains(&name) {
                                        ui_state.expanded_groups.remove(&name);
                                    } else {
                                        ui_state.expanded_groups.insert(name);
                                    }
                                    *needs_regroup = true;
                                    return;
                                }
                                current_idx += 1;
                                if ui_state.expanded_groups.contains(&name) {
                                    let group_routes_len = groups.get(&name).unwrap().len();
                                    if idx > current_idx && idx < current_idx + group_routes_len {
                                        // Clicked on a route in this group
                                        ui_state.show_route_modal = true;
                                        return;
                                    }
                                    current_idx += group_routes_len;
                                }
                            }
                        } else if is_double_click {
                            ui_state.show_route_modal = true;
                        }
                    }
                    ClickAction::CopyField { label, value } => {
                        copy_to_clipboard(&value, &format!("{}: {}", label, value), ui_state, app);
                    }
                }
            }
        }
        MouseEventKind::ScrollUp => {
            if let Some(scroll_area) = click_regions.scroll_area
                && mouse.column >= scroll_area.x
                && mouse.column < scroll_area.x + scroll_area.width
                && mouse.row >= scroll_area.y
                && mouse.row < scroll_area.y + scroll_area.height
            {
                if ui_state.selected_tab == 0 {
                    if ui_state.grouping_enabled {
                        ui_state.move_selection_up_grouped(grouped_rows);
                    } else {
                        ui_state.move_selection_up(connections);
                    }
                } else if ui_state.selected_tab == 1 {
                    let mut devices_sorted = devices.to_vec();
                    devices_sorted.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                    ui_state.move_device_selection_up(&devices_sorted);
                } else if ui_state.selected_tab == 2 {
                    let mut listeners_sorted = listeners.to_vec();
                    listeners_sorted
                        .sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
                    ui_state.move_service_selection_up(&listeners_sorted);
                } else if ui_state.selected_tab == 5 {
                    ui_state.move_route_selection_up(app.get_routes().len());
                }
            }
        }
        MouseEventKind::ScrollDown => {
            if let Some(scroll_area) = click_regions.scroll_area
                && mouse.column >= scroll_area.x
                && mouse.column < scroll_area.x + scroll_area.width
                && mouse.row >= scroll_area.y
                && mouse.row < scroll_area.y + scroll_area.height
            {
                if ui_state.selected_tab == 0 {
                    if ui_state.grouping_enabled {
                        ui_state.move_selection_down_grouped(grouped_rows);
                    } else {
                        ui_state.move_selection_down(connections);
                    }
                } else if ui_state.selected_tab == 1 {
                    let mut devices_sorted = devices.to_vec();
                    devices_sorted.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                    ui_state.move_device_selection_down(&devices_sorted);
                } else if ui_state.selected_tab == 2 {
                    let mut listeners_sorted = listeners.to_vec();
                    listeners_sorted
                        .sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
                    ui_state.move_service_selection_down(&listeners_sorted);
                } else if ui_state.selected_tab == 5 {
                    ui_state.move_route_selection_down(app.get_routes().len());
                }
            }
        }
        _ => {}
    }
}

fn handle_key_event(
    key: crossterm::event::KeyEvent,
    ui_state: &mut UIState,
    app: &App,
    connections: &[crate::network::types::Connection],
    grouped_rows: &[GroupedRow],
    listeners: &[crate::network::types::Listener],
    devices: &[crate::network::types::Device],
    needs_data_refresh: &mut bool,
    needs_regroup: &mut bool,
) -> Result<bool> {
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

    if key.kind != KeyEventKind::Press {
        return Ok(false);
    }

    if ui_state.filter_mode {
        match key.code {
            KeyCode::Enter => {
                ui_state.exit_filter_mode();
                *needs_data_refresh = true;
            }
            KeyCode::Esc => {
                ui_state.clear_filter();
                *needs_data_refresh = true;
            }
            KeyCode::Backspace => {
                ui_state.filter_backspace();
                *needs_data_refresh = true;
            }
            KeyCode::Delete if ui_state.filter_cursor_position < ui_state.filter_query.len() => {
                ui_state
                    .filter_query
                    .remove(ui_state.filter_cursor_position);
                *needs_data_refresh = true;
            }
            KeyCode::Left => ui_state.filter_cursor_left(),
            KeyCode::Right => ui_state.filter_cursor_right(),
            KeyCode::Home => ui_state.filter_cursor_position = 0,
            KeyCode::End => ui_state.filter_cursor_position = ui_state.filter_query.len(),
            KeyCode::Up => ui_state.move_selection_up(connections),
            KeyCode::Down => ui_state.move_selection_down(connections),
            KeyCode::Char(c) => {
                if c == 'h' && key.modifiers.contains(KeyModifiers::CONTROL) {
                    ui_state.filter_backspace();
                } else {
                    ui_state.filter_add_char(c);
                    *needs_data_refresh = true;
                }
            }
            _ => {}
        }
    } else {
        match (key.code, key.modifiers) {
            (KeyCode::Char('/'), _) if ui_state.selected_tab == 0 || ui_state.selected_tab == 5 => {
                ui_state.enter_filter_mode();
            }
            (KeyCode::Char('q'), _) => {
                if ui_state.quit_confirmation {
                    return Ok(true);
                } else {
                    ui_state.quit_confirmation = true;
                }
            }
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(true),
            (KeyCode::Tab, KeyModifiers::NONE) => {
                ui_state.selected_tab = (ui_state.selected_tab + 1) % 8;
                update_details_mode(ui_state);
            }
            (KeyCode::BackTab, _) | (KeyCode::Tab, KeyModifiers::SHIFT) => {
                ui_state.selected_tab = if ui_state.selected_tab == 0 {
                    7
                } else {
                    ui_state.selected_tab - 1
                };
                update_details_mode(ui_state);
            }
            (KeyCode::Char('h'), _) => {
                ui_state.show_help = !ui_state.show_help;
                ui_state.selected_tab = if ui_state.show_help { 7 } else { 0 };
            }
            (KeyCode::Char('i'), _) | (KeyCode::Char('I'), _) => {
                ui_state.selected_tab = if ui_state.selected_tab == 4 { 0 } else { 4 };
            }
            (KeyCode::Char('r'), KeyModifiers::CONTROL) => {
                ui_state.selected_tab = if ui_state.selected_tab == 5 { 0 } else { 5 };
            }
            (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                if ui_state.selected_tab == 1 {
                    let mut devices_sorted = devices.to_vec();
                    devices_sorted.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                    ui_state.move_device_selection_up(&devices_sorted);
                } else if ui_state.selected_tab == 2 {
                    let mut listeners_sorted = listeners.to_vec();
                    listeners_sorted
                        .sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
                    ui_state.move_service_selection_up(&listeners_sorted);
                } else if ui_state.selected_tab == 4 {
                    let stats = app.get_sorted_interface_stats();
                    ui_state.move_interface_selection_up(&stats);
                } else if ui_state.selected_tab == 5 {
                    ui_state.move_route_selection_up(app.get_routes().len());
                } else if ui_state.grouping_enabled {
                    ui_state.move_selection_up_grouped(grouped_rows);
                } else {
                    ui_state.move_selection_up(connections);
                }
            }
            (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                if ui_state.selected_tab == 1 {
                    let mut devices_sorted = devices.to_vec();
                    devices_sorted.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                    ui_state.move_device_selection_down(&devices_sorted);
                } else if ui_state.selected_tab == 2 {
                    let mut listeners_sorted = listeners.to_vec();
                    listeners_sorted
                        .sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
                    ui_state.move_service_selection_down(&listeners_sorted);
                } else if ui_state.selected_tab == 4 {
                    let stats = app.get_sorted_interface_stats();
                    ui_state.move_interface_selection_down(&stats);
                } else if ui_state.selected_tab == 5 {
                    ui_state.move_route_selection_down(app.get_routes().len());
                } else if ui_state.grouping_enabled {
                    ui_state.move_selection_down_grouped(grouped_rows);
                } else {
                    ui_state.move_selection_down(connections);
                }
            }
            (KeyCode::PageUp, _) | (KeyCode::Char('b'), KeyModifiers::CONTROL) => {
                let page_size = ui_state.visible_rows.max(1);
                if ui_state.selected_tab == 1 {
                    let mut devices_sorted = devices.to_vec();
                    devices_sorted.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                    for _ in 0..page_size {
                        ui_state.move_device_selection_up(&devices_sorted);
                    }
                } else if ui_state.selected_tab == 2 {
                    let mut listeners_sorted = listeners.to_vec();
                    listeners_sorted
                        .sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
                    for _ in 0..page_size {
                        ui_state.move_service_selection_up(&listeners_sorted);
                    }
                } else if ui_state.grouping_enabled {
                    ui_state.move_selection_page_up_grouped(grouped_rows, page_size);
                } else {
                    ui_state.move_selection_page_up(connections, page_size);
                }
            }
            (KeyCode::PageDown, _) | (KeyCode::Char('f'), KeyModifiers::CONTROL) => {
                let page_size = ui_state.visible_rows.max(1);
                if ui_state.selected_tab == 1 {
                    let mut devices_sorted = devices.to_vec();
                    devices_sorted.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                    for _ in 0..page_size {
                        ui_state.move_device_selection_down(&devices_sorted);
                    }
                } else if ui_state.selected_tab == 2 {
                    let mut listeners_sorted = listeners.to_vec();
                    listeners_sorted
                        .sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
                    for _ in 0..page_size {
                        ui_state.move_service_selection_down(&listeners_sorted);
                    }
                } else if ui_state.grouping_enabled {
                    ui_state.move_selection_page_down_grouped(grouped_rows, page_size);
                } else {
                    ui_state.move_selection_page_down(connections, page_size);
                }
            }
            (KeyCode::Char('g'), KeyModifiers::NONE) => {
                if ui_state.selected_tab == 1 {
                    let mut devices_sorted = devices.to_vec();
                    devices_sorted.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                    ui_state.set_selected_device_by_index(&devices_sorted, 0);
                } else if ui_state.selected_tab == 2 {
                    let mut listeners_sorted = listeners.to_vec();
                    listeners_sorted
                        .sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
                    ui_state.set_selected_service_by_index(&listeners_sorted, 0);
                } else {
                    ui_state.move_selection_to_first(connections);
                }
            }
            (KeyCode::Char('G'), _) | (KeyCode::Char('g'), KeyModifiers::SHIFT) => {
                if ui_state.selected_tab == 1 {
                    let mut devices_sorted = devices.to_vec();
                    devices_sorted.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
                    ui_state.set_selected_device_by_index(
                        &devices_sorted,
                        devices_sorted.len().saturating_sub(1),
                    );
                } else if ui_state.selected_tab == 2 {
                    let mut listeners_sorted = listeners.to_vec();
                    listeners_sorted
                        .sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
                    ui_state.set_selected_service_by_index(
                        &listeners_sorted,
                        listeners_sorted.len().saturating_sub(1),
                    );
                } else {
                    ui_state.move_selection_to_last(connections);
                }
            }
            (KeyCode::Enter, _) => {
                if ui_state.show_interface_modal {
                    ui_state.show_interface_modal = false;
                } else if ui_state.show_route_modal {
                    ui_state.show_route_modal = false;
                } else if ui_state.show_device_modal {
                    ui_state.show_device_modal = false;
                } else if ui_state.show_service_modal {
                    ui_state.show_service_modal = false;
                } else if ui_state.selected_tab == 4 {
                    ui_state.show_interface_modal = true;
                } else if ui_state.selected_tab == 5 {
                    ui_state.show_route_modal = true;
                } else if ui_state.selected_tab == 0
                    && !connections.is_empty()
                    && !(ui_state.grouping_enabled && ui_state.is_group_selected())
                {
                    ui_state.details_view_mode = DetailsViewMode::Connection;
                    ui_state.selected_tab = 3;
                } else if ui_state.selected_tab == 1 && !devices.is_empty() {
                    ui_state.show_device_modal = true;
                } else if ui_state.selected_tab == 2 && !listeners.is_empty() {
                    ui_state.show_service_modal = true;
                }
            }
            (KeyCode::Char(' '), _) => {
                if ui_state.selected_tab == 0
                    && ui_state.grouping_enabled
                    && ui_state.is_group_selected()
                {
                    ui_state.toggle_group_expansion();
                    *needs_regroup = true;
                } else if ui_state.selected_tab == 5 && ui_state.grouping_enabled {
                    if let Some(idx) = ui_state.selected_route_index {
                        let routes = app.get_routes();
                        let mut groups: HashMap<String, Vec<crate::network::types::RouteEntry>> =
                            HashMap::new();
                        for r in routes {
                            groups.entry(r.interface.clone()).or_default().push(r);
                        }
                        let mut group_names: Vec<String> = groups.keys().cloned().collect();
                        group_names.sort_by_key(|n| n.to_lowercase());

                        let mut current_idx = 0;
                        for name in group_names {
                            if current_idx == idx {
                                // Selected a group header
                                if ui_state.expanded_groups.contains(&name) {
                                    ui_state.expanded_groups.remove(&name);
                                } else {
                                    ui_state.expanded_groups.insert(name);
                                }
                                *needs_regroup = true;
                                break;
                            }
                            current_idx += 1;
                            if ui_state.expanded_groups.contains(&name) {
                                current_idx += groups.get(&name).unwrap().len();
                            }
                        }
                    }
                }
            }
            (KeyCode::Left, _) if ui_state.grouping_enabled => {
                if ui_state.selected_tab == 0 {
                    ui_state.collapse_selected_group();
                    *needs_regroup = true;
                } else if ui_state.selected_tab == 5 {
                    if let Some(idx) = ui_state.selected_route_index {
                        let routes = app.get_routes();
                        let mut groups: HashMap<String, Vec<crate::network::types::RouteEntry>> =
                            HashMap::new();
                        for r in routes {
                            groups.entry(r.interface.clone()).or_default().push(r);
                        }
                        let mut group_names: Vec<String> = groups.keys().cloned().collect();
                        group_names.sort_by_key(|n| n.to_lowercase());

                        let mut current_idx = 0;
                        for name in group_names {
                            if current_idx == idx {
                                ui_state.expanded_groups.remove(&name);
                                *needs_regroup = true;
                                break;
                            }
                            current_idx += 1;
                            if ui_state.expanded_groups.contains(&name) {
                                current_idx += groups.get(&name).unwrap().len();
                            }
                        }
                    }
                }
            }
            (KeyCode::Right, _) | (KeyCode::Char('l'), _) if ui_state.grouping_enabled => {
                if ui_state.selected_tab == 0 {
                    ui_state.expand_selected_group();
                    *needs_regroup = true;
                } else if ui_state.selected_tab == 5 {
                    if let Some(idx) = ui_state.selected_route_index {
                        let routes = app.get_routes();
                        let mut groups: HashMap<String, Vec<crate::network::types::RouteEntry>> =
                            HashMap::new();
                        for r in routes {
                            groups.entry(r.interface.clone()).or_default().push(r);
                        }
                        let mut group_names: Vec<String> = groups.keys().cloned().collect();
                        group_names.sort_by_key(|n| n.to_lowercase());

                        let mut current_idx = 0;
                        for name in group_names {
                            if current_idx == idx {
                                ui_state.expanded_groups.insert(name);
                                *needs_regroup = true;
                                break;
                            }
                            current_idx += 1;
                            if ui_state.expanded_groups.contains(&name) {
                                current_idx += groups.get(&name).unwrap().len();
                            }
                        }
                    }
                }
            }
            (KeyCode::Char('a'), _) => {
                ui_state.toggle_grouping();
                *needs_regroup = true;
            }
            (KeyCode::Char('r'), _) => {
                let was_historic = ui_state.show_historic;
                ui_state.reset_view();
                if was_historic {
                    app.set_show_historic(false);
                }
                *needs_data_refresh = true;
            }
            (KeyCode::Char('p'), _) => ui_state.show_port_numbers = !ui_state.show_port_numbers,
            (KeyCode::Char('d'), _) if app.is_dns_resolution_enabled() => {
                ui_state.show_hostnames = !ui_state.show_hostnames
            }
            (KeyCode::Char('t'), _) => {
                ui_state.show_historic = !ui_state.show_historic;
                app.toggle_show_historic();
                *needs_data_refresh = true;
            }
            (KeyCode::Char('s'), KeyModifiers::NONE) => {
                ui_state.cycle_sort_column();
                *needs_data_refresh = true;
            }
            (KeyCode::Char('S'), _) => {
                ui_state.toggle_sort_direction();
                *needs_data_refresh = true;
            }
            (KeyCode::Char('c'), _) => {
                if let Some(selected_idx) = ui_state.get_selected_index(connections)
                    && let Some(conn) = connections.get(selected_idx)
                {
                    let remote_addr = conn.remote_addr.to_string();
                    copy_to_clipboard(&remote_addr, &remote_addr, ui_state, app);
                }
            }
            (KeyCode::Char('x'), _) => {
                if ui_state.clear_confirmation {
                    app.clear_all_connections();
                    ui_state.clear_confirmation = false;
                    ui_state.show_historic = false;
                    ui_state.selected_connection_key = None;
                    *needs_data_refresh = true;
                } else {
                    ui_state.clear_confirmation = true;
                }
            }
            (KeyCode::Esc, _) => {
                if ui_state.show_interface_modal {
                    ui_state.show_interface_modal = false;
                } else if ui_state.show_route_modal {
                    ui_state.show_route_modal = false;
                } else if ui_state.show_device_modal {
                    ui_state.show_device_modal = false;
                } else if ui_state.show_service_modal {
                    ui_state.show_service_modal = false;
                } else if !ui_state.filter_query.is_empty() {
                    ui_state.clear_filter();
                    *needs_data_refresh = true;
                } else if ui_state.selected_tab != 0 {
                    ui_state.selected_tab = 0;
                }
            }
            _ => {
                ui_state.quit_confirmation = false;
                ui_state.clear_confirmation = false;
            }
        }
    }
    Ok(false)
}

fn update_details_mode(ui_state: &mut UIState) {
    match ui_state.selected_tab {
        0 => ui_state.details_view_mode = DetailsViewMode::Connection,
        1 => ui_state.details_view_mode = DetailsViewMode::Device,
        2 => ui_state.details_view_mode = DetailsViewMode::Service,
        _ => {}
    }
}
