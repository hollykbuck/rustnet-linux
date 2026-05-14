pub mod details;
pub mod devices;
pub mod graph;
pub mod help;
pub mod interfaces;
pub mod overview;
pub mod routes;
pub mod services;

pub use details::{draw_connection_details, draw_device_details, draw_service_details};
pub use devices::draw_devices;
pub use graph::draw_graph_tab;
pub use help::draw_help;
pub use interfaces::draw_interface_stats;
pub use overview::draw_overview;
pub use routes::draw_routes_tab;
pub use services::draw_services;
