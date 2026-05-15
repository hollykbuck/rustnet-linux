use rustnet_monitor::network::types::RouteEntry;
use rustnet_monitor::ui::UIState;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

#[test]
fn test_route_grouping_logic() {
    let mut ui_state = UIState::default();
    ui_state.grouping_enabled = true;
    ui_state.selected_tab = 4;

    let routes = vec![
        RouteEntry {
            destination: IpAddr::from_str("192.168.1.0").unwrap(),
            prefix_len: 24,
            gateway: None,
            netmask: IpAddr::from_str("255.255.255.0").unwrap(),
            interface: "eth0".to_string(),
            flags: 1,
            metric: 100,
            table_id: 254, // Main
            protocol: None,
            scope: None,
            pref_src: None,
        },
        RouteEntry {
            destination: IpAddr::from_str("127.0.0.0").unwrap(),
            prefix_len: 8,
            gateway: None,
            netmask: IpAddr::from_str("255.0.0.0").unwrap(),
            interface: "lo".to_string(),
            flags: 1,
            metric: 0,
            table_id: 255, // Local
            protocol: None,
            scope: None,
            pref_src: None,
        },
    ];

    // Simulating the grouping logic in routes.rs
    use std::collections::HashMap;
    let mut groups: HashMap<u32, Vec<RouteEntry>> = HashMap::new();
    for r in routes.clone() {
        groups.entry(r.table_id).or_default().push(r);
    }

    let mut table_ids: Vec<u32> = groups.keys().cloned().collect();
    table_ids.sort();

    // Verify groups
    assert_eq!(table_ids.len(), 2);
    assert_eq!(table_ids[0], 254); // Main
    assert_eq!(table_ids[1], 255); // Local

    // Initial state: selected_route_index = Some(0) (Main group header)
    ui_state.selected_route_index = Some(0);
    let group_name_0 = "Main".to_string();

    // Verify it's not expanded initially
    assert!(!ui_state.expanded_groups.contains(&group_name_0));

    // Simulate toggle logic (like in event_loop.rs)
    let idx = ui_state.selected_route_index.unwrap();
    let mut current_idx = 0;
    let mut toggled = false;
    for id in &table_ids {
        let name = match *id {
            254 => "Main".to_string(),
            255 => "Local".to_string(),
            253 => "Default".to_string(),
            _ => format!("Table {}", id),
        };

        if current_idx == idx {
            if ui_state.expanded_groups.contains(&name) {
                ui_state.expanded_groups.remove(&name);
            } else {
                ui_state.expanded_groups.insert(name);
            }
            toggled = true;
            break;
        }
        current_idx += 1;
        if ui_state.expanded_groups.contains(&name) {
            current_idx += groups.get(id).unwrap().len();
        }
    }

    assert!(toggled);
    assert!(ui_state.expanded_groups.contains(&group_name_0));

    // Now current_idx for "Local" should be 2 (Main header + 1 route)
    let mut current_idx = 0;
    let mut local_group_idx = None;
    for id in &table_ids {
        let name = match *id {
            254 => "Main".to_string(),
            255 => "Local".to_string(),
            253 => "Default".to_string(),
            _ => format!("Table {}", id),
        };
        if *id == 255 {
            local_group_idx = Some(current_idx);
        }
        current_idx += 1;
        if ui_state.expanded_groups.contains(&name) {
            current_idx += groups.get(id).unwrap().len();
        }
    }
    assert_eq!(local_group_idx, Some(2));
}
