use crate::ui::*;
pub use ratatui::widgets::Clear;
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};

/// Helper to create a standard styled panel block with a title.
pub fn panel_block<'a>(title: impl Into<Line<'a>>) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(fg(muted()))
        .title_style(bold_fg(heading()))
        .title(title)
}

/// Render a single-row horizontal rule between sections.
pub fn render_section_separator(f: &mut Frame, area: Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let rule: String = "─".repeat(area.width as usize);
    let para = Paragraph::new(Line::from(rule));
    f.render_widget(para, area);
}

/// Helper function to create a centered rect using up certain percentage of the available rect `r`
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
