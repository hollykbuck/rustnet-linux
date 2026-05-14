use ratatui::prelude::*;
use ratatui::widgets::{Paragraph, Wrap};
use crate::ui::theme::theme;
use crate::ui::components::panel_block;

pub fn draw_help(f: &mut Frame, area: Rect) -> anyhow::Result<()> {
    let help_text: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("RustNet Monitor ", theme::bold_fg(theme::ok())),
            Span::raw("- Network Connection Monitor"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled("q ", fg(key())), Span::raw("Quit application (press twice to confirm)")]),
        Line::from(vec![Span::styled("Ctrl+C ", fg(key())), Span::raw("Quit immediately")]),
        Line::from(vec![Span::styled("x ", fg(key())), Span::raw("Clear all connections (press twice to confirm)")]),
        Line::from(vec![Span::styled("Tab ", fg(key())), Span::raw("Switch between tabs")]),
        Line::from(vec![Span::styled("↑/k, ↓/j ", fg(key())), Span::raw("Navigate connections (wraps around)")]),
        Line::from(vec![Span::styled("g, G ", fg(key())), Span::raw("Jump to first/last connection (vim-style)")]),
        Line::from(vec![Span::styled("Page Up/Down, Ctrl+B/F ", fg(key())), Span::raw("Navigate connections by page")]),
        Line::from(vec![Span::styled("c ", fg(key())), Span::raw("Copy remote address to clipboard")]),
        Line::from(vec![Span::styled("p ", fg(key())), Span::raw("Toggle between service names and port numbers")]),
        Line::from(vec![Span::styled("d ", fg(key())), Span::raw("Toggle between hostnames and IP addresses (when --resolve-dns)")]),
        Line::from(vec![Span::styled("s ", fg(key())), Span::raw("Cycle through sort columns (Bandwidth, Process, etc.)")]),
        Line::from(vec![Span::styled("S ", fg(key())), Span::raw("Toggle sort direction (ascending/descending)")]),
        Line::from(vec![Span::styled("a ", fg(key())), Span::raw("Toggle process grouping (aggregate by process)")]),
        Line::from(vec![Span::styled("Space ", fg(key())), Span::raw("Expand/collapse group (when grouping enabled)")]),
        Line::from(vec![Span::styled("←/→ or h/l ", fg(key())), Span::raw("Collapse/expand group")]),
        Line::from(vec![Span::styled("t ", fg(key())), Span::raw("Toggle display of historic (closed) connections")]),
        Line::from(vec![Span::styled("r ", fg(key())), Span::raw("Reset view (grouping, sort, filter)")]),
        Line::from(vec![Span::styled("Enter ", fg(key())), Span::raw("View connection details")]),
        Line::from(vec![Span::styled("Esc ", fg(key())), Span::raw("Return to overview")]),
        Line::from(vec![Span::styled("h ", fg(key())), Span::raw("Toggle this help screen")]),
        Line::from(vec![Span::styled("i ", fg(key())), Span::raw("Toggle interface statistics view")]),
        Line::from(vec![Span::styled("/ ", fg(key())), Span::raw("Enter filter mode on Overview")]),
        Line::from(""),
        Line::from(vec![Span::styled("Tabs:", theme::bold_fg(theme::accent()))]),
        Line::from(vec![Span::styled("  Overview ", fg(ok())), Span::raw("Connection list with mini traffic graph")]),
        Line::from(vec![Span::styled("  Details ", fg(ok())), Span::raw("Full details for selected connection")]),
        Line::from(vec![Span::styled("  Interfaces ", fg(ok())), Span::raw("Network interface statistics")]),
        Line::from(vec![Span::styled("  Graph ", fg(ok())), Span::raw("Traffic charts and protocol distribution")]),
        Line::from(vec![Span::styled("  Help ", fg(ok())), Span::raw("This help screen")]),
    ];

    let help = Paragraph::new(help_text)
        .block(panel_block("Help"))
        .style(Style::default())
        .wrap(Wrap { trim: true });

    f.render_widget(help, area);
    Ok(())
}
