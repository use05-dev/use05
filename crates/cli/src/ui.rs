//! Terminal output that holds up: it measures the terminal, wraps to it, falls back to ASCII
//! when the locale is not UTF-8, honours NO_COLOR and dumb terminals, and never emits an escape
//! sequence when output is not a terminal.

use std::io::IsTerminal;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    Good,
    Bad,
    Warn,
    Info,
    Dim,
    Plain,
}

#[derive(Clone, Copy)]
pub enum Glyph {
    Ok,
    Bad,
    Warn,
    Dot,
    Bar,
    Rule,
    Pending,
}

#[derive(Clone)]
pub struct Ui {
    pub color: bool,
    pub unicode: bool,
    pub width: usize,
}

fn locale_is_utf8() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .is_some_and(|v| {
            let v = v.to_lowercase();
            v.contains("utf-8") || v.contains("utf8")
        })
}

impl Ui {
    fn detect(is_terminal: bool) -> Ui {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        let dumb = std::env::var("TERM").is_ok_and(|t| t == "dumb");
        let force = std::env::var_os("CLICOLOR_FORCE").is_some_and(|v| !v.is_empty() && v != "0");
        let color = !no_color && !dumb && (is_terminal || force);
        let width = if is_terminal || force { use05_core::tty::width() } else { std::env::var("COLUMNS").ok().and_then(|c| c.parse().ok()).unwrap_or(100) };
        Ui { color, unicode: locale_is_utf8() || std::env::var_os("USE05_UNICODE").is_some(), width: width.clamp(40, 120) }
    }

    pub fn stdout() -> Ui {
        Ui::detect(std::io::stdout().is_terminal())
    }

    pub fn stderr() -> Ui {
        Ui::detect(std::io::stderr().is_terminal())
    }

    /// A fixed, colourless Ui for tests and snapshots.
    pub fn fixed(width: usize, unicode: bool) -> Ui {
        Ui { color: false, unicode, width }
    }

    pub fn glyph(&self, g: Glyph) -> &'static str {
        let (u, a) = match g {
            Glyph::Ok => ("✓", "+"),
            Glyph::Bad => ("✗", "x"),
            Glyph::Warn => ("!", "!"),
            Glyph::Dot => ("·", "-"),
            Glyph::Bar => ("│", "|"),
            Glyph::Rule => ("─", "-"),
            Glyph::Pending => ("○", "o"),
        };
        if self.unicode { u } else { a }
    }

    pub fn paint(&self, tone: Tone, text: &str) -> String {
        let code = match tone {
            Tone::Good => "1;32",
            Tone::Bad => "1;31",
            Tone::Warn => "1;33",
            Tone::Info => "1;36",
            Tone::Dim => "2",
            Tone::Plain => return text.to_string(),
        };
        if self.color { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_string() }
    }

    /// Make finished output safe for a terminal that cannot show Unicode: every glyph 05 uses has
    /// a one-column ASCII stand-in, and anything else becomes `?`. Widths are preserved.
    pub fn finish(&self, text: String) -> String {
        if self.unicode || text.is_ascii() {
            return text;
        }
        text.chars()
            .map(|c| match c {
                c if c.is_ascii() => c,
                '…' => '~',
                '→' | '▸' => '>',
                '·' | '─' | '•' => '-',
                '│' => '|',
                '✓' => '+',
                '✗' => 'x',
                '○' => 'o',
                _ => '?',
            })
            .collect()
    }

    pub fn bold(&self, text: &str) -> String {
        if self.color { format!("\x1b[1m{text}\x1b[0m") } else { text.to_string() }
    }

    pub fn rule(&self, width: usize) -> String {
        self.paint(Tone::Dim, &self.glyph(Glyph::Rule).repeat(width))
    }

    /// Wrap `text` to `width` columns. Words longer than the width are cut in the middle.
    pub fn wrap(&self, text: &str, width: usize) -> Vec<String> {
        let width = width.max(10);
        let mut lines = Vec::new();
        for paragraph in text.split('\n') {
            let mut line = String::new();
            for word in paragraph.split_whitespace() {
                let word = if word.chars().count() > width { truncate_middle(word, width) } else { word.to_string() };
                let need = if line.is_empty() { 0 } else { 1 };
                if line.chars().count() + need + word.chars().count() > width && !line.is_empty() {
                    lines.push(std::mem::take(&mut line));
                }
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(&word);
            }
            lines.push(line);
        }
        if lines.is_empty() {
            lines.push(String::new());
        }
        lines
    }
}

/// Shorten the middle of a long token, keeping both ends: `refs/05/receipts/9c4e…a884`.
pub fn truncate_middle(text: &str, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max || max < 5 {
        return text.to_string();
    }
    let keep = max - 1;
    let (head, tail) = (keep.div_ceil(2), keep / 2);
    format!("{}…{}", chars[..head].iter().collect::<String>(), chars[chars.len() - tail..].iter().collect::<String>())
}

/// Shorten a sentence from the end, so what is left still reads: `Approve selection and rep…`.
pub fn truncate_end(text: &str, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max || max < 2 {
        return text.to_string();
    }
    format!("{}…", chars[..max - 1].iter().collect::<String>().trim_end())
}

/// An output document built from labelled sections, rendered to the terminal's width.
pub struct Out<'a> {
    ui: &'a Ui,
    buf: String,
    label_width: usize,
}

pub struct Item {
    pub glyph: Option<(Glyph, Tone)>,
    pub text: String,
    pub dim: bool,
    /// Already laid out in columns, to fit: kept as it is, never re-flowed.
    pub columns: bool,
}

impl Item {
    pub fn new(glyph: Glyph, tone: Tone, text: impl Into<String>) -> Item {
        Item { glyph: Some((glyph, tone)), text: text.into(), dim: false, columns: false }
    }
    pub fn plain(text: impl Into<String>) -> Item {
        Item { glyph: None, text: text.into(), dim: false, columns: false }
    }
    pub fn dim(text: impl Into<String>) -> Item {
        Item { glyph: None, text: text.into(), dim: true, columns: false }
    }
    /// A line of aligned columns, as `pending::list_rows` makes them.
    pub fn columns(glyph: Glyph, tone: Tone, text: impl Into<String>) -> Item {
        Item { glyph: Some((glyph, tone)), text: text.into(), dim: false, columns: true }
    }
}

impl<'a> Out<'a> {
    pub fn new(ui: &'a Ui, label_width: usize) -> Out<'a> {
        Out { ui, buf: String::new(), label_width }
    }

    pub fn raw(&mut self, line: &str) {
        self.buf.push_str(line);
        self.buf.push('\n');
    }

    pub fn blank(&mut self) {
        self.buf.push('\n');
    }

    /// `title` on the left, `right` aligned to the edge, then a rule.
    pub fn title(&mut self, title: &str, right: &str) {
        let width = self.ui.width;
        let room = width.saturating_sub(right.chars().count() + 2);
        let title = truncate_middle(title, room.max(10));
        let gap = width.saturating_sub(title.chars().count() + right.chars().count()).max(1);
        self.raw(&format!("{}{}{}", self.ui.bold(&title), " ".repeat(gap), self.ui.paint(Tone::Dim, right)));
        self.raw(&self.ui.rule(width));
    }

    /// A labelled block: the label sits in the left column, items flow to its right, wrapped.
    pub fn section(&mut self, label: &str, items: Vec<Item>) {
        let indent = self.label_width + 2;
        let body = self.ui.width.saturating_sub(indent).max(20);
        let mut first = true;
        for item in items {
            let (glyph_text, glyph_width) = match item.glyph {
                Some((g, tone)) => (format!("{} ", self.ui.paint(tone, self.ui.glyph(g))), 2),
                None => (String::new(), 0),
            };
            let room = body.saturating_sub(glyph_width);
            let lines = if item.columns { vec![truncate_middle(&item.text, room)] } else { self.ui.wrap(&item.text, room) };
            for (i, line) in lines.iter().enumerate() {
                let lead = if first {
                    first = false;
                    format!("{:<width$}", self.ui.paint(Tone::Dim, label), width = self.label_width + if self.ui.color { self.ui.paint(Tone::Dim, label).len() - label.len() } else { 0 })
                } else {
                    " ".repeat(self.label_width)
                };
                let prefix = if i == 0 { glyph_text.clone() } else { " ".repeat(glyph_width) };
                let text = if item.dim { self.ui.paint(Tone::Dim, line) } else { line.clone() };
                self.raw(&format!("{lead}  {prefix}{text}"));
            }
        }
        if first {
            // An empty section still shows its label, so the page keeps its shape.
            self.raw(&self.ui.paint(Tone::Dim, label));
        }
    }

    pub fn finish(self) -> String {
        self.ui.finish(self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_respects_the_width_and_never_loses_words() {
        let ui = Ui::fixed(40, true);
        let lines = ui.wrap("the quick brown fox jumps over the lazy dog again and again", 20);
        assert!(lines.iter().all(|l| l.chars().count() <= 20), "{lines:?}");
        assert_eq!(lines.join(" "), "the quick brown fox jumps over the lazy dog again and again");
    }

    #[test]
    fn an_unbreakable_token_is_shortened_not_overflowed() {
        let ui = Ui::fixed(40, true);
        let long = "refs/05/receipts/726de36789ef204adf3f4fa74bb8963aff6f9c4c/c19b61b7f373a884";
        let lines = ui.wrap(long, 24);
        assert!(lines[0].chars().count() <= 24);
        assert!(lines[0].starts_with("refs/") && lines[0].ends_with("a884"), "{lines:?}");
    }

    #[test]
    fn middle_truncation_keeps_both_ends() {
        assert_eq!(truncate_middle("abcdefghij", 6), "abc…ij");
        assert_eq!(truncate_end("Approve selection and repo", 12), "Approve sel…");
        assert_eq!(truncate_end("short", 12), "short");
        assert_eq!(truncate_middle("short", 10), "short");
        assert_eq!(truncate_middle("héllo wörld", 6).chars().count(), 6, "counts characters, not bytes");
    }

    #[test]
    fn ascii_fallback_has_no_non_ascii() {
        let ui = Ui::fixed(80, false);
        for g in [Glyph::Ok, Glyph::Bad, Glyph::Warn, Glyph::Dot, Glyph::Bar, Glyph::Rule, Glyph::Pending] {
            assert!(ui.glyph(g).is_ascii());
        }
    }

    #[test]
    fn sections_align_and_wrap_with_a_hanging_indent() {
        let ui = Ui::fixed(50, true);
        let mut out = Out::new(&ui, 9);
        out.section("Intent", vec![Item::plain("Stop retrying failed charges after three attempts, and record each one.")]);
        let text = out.finish();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines.len() >= 2);
        assert!(lines[0].starts_with("Intent"));
        assert!(lines[1].starts_with("           "), "continuation lines align under the text: {lines:?}");
        assert!(lines.iter().all(|l| l.chars().count() <= 50), "{lines:?}");
    }

    #[test]
    fn nothing_but_plain_text_when_colour_is_off() {
        let ui = Ui::fixed(80, true);
        assert_eq!(ui.paint(Tone::Bad, "x"), "x");
        assert!(!ui.rule(10).contains('\x1b'));
    }
}
