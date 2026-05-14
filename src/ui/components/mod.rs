use crate::ui::*;
use ratatui::prelude::*;
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
