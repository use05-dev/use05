//! Questions on the terminal, with a default for each: Enter accepts it. Reads and writes plain
//! streams, so the guided setup can be driven by a script or a test as well as a person.

use std::io::{BufRead, Write};

use crate::ui::{Glyph, Tone, Ui};

/// Asks questions on `output` and reads answers from `input`. Every answer is optional: `None`
/// means the input ended, and the caller stops without changing anything.
pub struct Asker<R: BufRead, W: Write> {
    input: R,
    output: W,
    ui: Ui,
    /// The answers do not come from a person typing (a pipe, a file): end each answer's line
    /// ourselves, as their Enter would have.
    echo_newline: bool,
}

/// A bad answer is asked again this many times; then the default stands.
const TRIES: usize = 3;

impl<R: BufRead, W: Write> Asker<R, W> {
    /// Plain output, as for a test.
    #[cfg(test)]
    pub fn new(input: R, output: W) -> Self {
        Asker { input, output, ui: Ui::fixed(80, true), echo_newline: false }
    }

    /// Styled for the terminal `ui` describes: colour, Unicode and width when it has them.
    pub fn styled(input: R, output: W, ui: Ui) -> Self {
        use std::io::IsTerminal;
        Asker { input, output, ui, echo_newline: !std::io::stdin().is_terminal() }
    }

    #[cfg(test)]
    pub fn output(&self) -> &W {
        &self.output
    }

    fn put(&mut self, text: &str) {
        let text = self.ui.finish(text.to_string());
        let _ = write!(self.output, "{text}");
    }

    /// Wrap at spaces; a word longer than the line is broken across lines, never cut short.
    fn lines(&self, text: &str, width: usize) -> Vec<String> {
        let width = width.max(10);
        let mut out: Vec<String> = Vec::new();
        let mut line = String::new();
        for word in text.split_whitespace() {
            let mut word: Vec<char> = word.chars().collect();
            while word.len() > width {
                if !line.is_empty() {
                    out.push(std::mem::take(&mut line));
                }
                out.push(word.drain(..width).collect());
            }
            let word: String = word.into_iter().collect();
            if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
                out.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(&word);
        }
        if !line.is_empty() || out.is_empty() {
            out.push(line);
        }
        out
    }

    fn width(&self) -> usize {
        self.ui.width.min(76)
    }

    /// Text for the person: an explanation or a note, wrapped to the terminal.
    pub fn say(&mut self, text: &str) {
        let (lead, body) = match text.strip_prefix('\n') {
            Some(rest) => ("\n", rest),
            None => ("", text),
        };
        let indent = if body.starts_with("  ") { "  " } else { "" };
        let lines = self.lines(body.trim_start(), self.width() - 2 - indent.len());
        let shown: Vec<String> = lines.iter().map(|l| format!("  {indent}{l}")).collect();
        self.put(&format!("{lead}{}\n", shown.join("\n")));
    }

    /// The title of a run of questions.
    pub fn banner(&mut self, title: &str, subtitle: &str) {
        let w = self.width();
        let sub: Vec<String> = self.lines(subtitle, w).iter().map(|l| format!("  {}", self.ui.paint(Tone::Dim, l))).collect();
        let line = format!("\n  {}  {}\n{}\n", self.ui.paint(Tone::Good, "05"), self.ui.bold(title), sub.join("\n"));
        self.put(&line);
        let rule = self.ui.rule(w);
        self.put(&format!("  {rule}\n"));
    }

    /// A numbered step: `2/7  Where changes land`, over a rule.
    pub fn step(&mut self, n: usize, total: usize, title: &str) {
        let w = self.width();
        let head = format!("\n  {}  {}\n", self.ui.paint(Tone::Info, &format!("{n}/{total}")), self.ui.bold(title));
        self.put(&head);
        let rule = self.ui.rule(w);
        self.put(&format!("  {rule}\n"));
    }

    /// Rows of `label   value`, the labels aligned.
    pub fn table(&mut self, rows: &[(&str, String)]) {
        let pad = rows.iter().map(|(l, _)| l.chars().count()).max().unwrap_or(0) + 3;
        let w = self.width();
        for (label, value) in rows {
            let gap = " ".repeat(pad - label.chars().count());
            let lines = self.lines(value, w.saturating_sub(pad + 2).max(20));
            let first = format!("  {}{gap}{}\n", self.ui.paint(Tone::Dim, label), lines.first().cloned().unwrap_or_default());
            self.put(&first);
            for more in lines.iter().skip(1) {
                let rest = format!("  {}{more}\n", " ".repeat(pad));
                self.put(&rest);
            }
        }
    }

    fn question(&mut self, question: &str) {
        let lines = self.lines(question, self.width() - 2);
        let shown: Vec<String> = lines.iter().map(|l| format!("  {}", self.ui.bold(l))).collect();
        self.put(&format!("\n{}\n", shown.join("\n")));
    }

    fn prompt(&mut self, hint: &str) {
        let arrow = self.ui.paint(Tone::Info, if self.ui.unicode { "›" } else { ">" });
        let hint = self.ui.paint(Tone::Dim, hint);
        self.put(&format!("  {arrow} {hint} "));
    }

    fn note(&mut self, text: &str) {
        let line = format!("    {} {}\n", self.ui.paint(Tone::Warn, self.ui.glyph(Glyph::Warn)), text);
        self.put(&line);
    }

    fn read(&mut self) -> Option<String> {
        let _ = self.output.flush();
        let mut line = String::new();
        let read = match self.input.read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line.trim().to_string()),
        };
        if self.echo_newline {
            let _ = writeln!(self.output);
        }
        read
    }

    /// One of `options`; Enter takes `default`.
    pub fn choice(&mut self, question: &str, options: &[&str], default: usize) -> Option<usize> {
        self.question(question);
        self.put("\n");
        for (i, o) in options.iter().enumerate() {
            let line = if i == default {
                let marker = self.ui.paint(Tone::Good, if self.ui.unicode { "›" } else { ">" });
                format!("  {marker} {}  {}  {}\n", self.ui.paint(Tone::Good, &(i + 1).to_string()), self.ui.bold(o), self.ui.paint(Tone::Dim, "(default)"))
            } else {
                format!("    {}  {o}\n", self.ui.paint(Tone::Dim, &(i + 1).to_string()))
            };
            self.put(&line);
        }
        self.put("\n");
        let hint = format!("Choose 1 to {}, or press Enter for {}:", options.len(), default + 1);
        for _ in 0..TRIES {
            self.prompt(&hint);
            let answer = self.read()?;
            if answer.is_empty() {
                return Some(default);
            }
            match answer.parse::<usize>() {
                Ok(n) if (1..=options.len()).contains(&n) => return Some(n - 1),
                _ => self.note(&format!("Type a number from 1 to {}.", options.len())),
            }
        }
        self.note(&format!("Keeping the default: {}.", options[default]));
        Some(default)
    }

    /// Free text; Enter takes `default`.
    pub fn text(&mut self, question: &str, default: &str) -> Option<String> {
        self.question(question);
        let hint = if default.is_empty() { "Type it, or press Enter to go on:".to_string() } else { format!("Press Enter for {default}, or type another:") };
        self.prompt(&hint);
        let answer = self.read()?;
        Some(if answer.is_empty() { default.to_string() } else { answer })
    }

    /// A comma-separated list; Enter keeps `default`, `none` empties it.
    pub fn list(&mut self, question: &str, default: &[String]) -> Option<Vec<String>> {
        self.question(question);
        let shown = if default.is_empty() { "none".to_string() } else { default.join(", ") };
        let hint = format!("Enter keeps {shown}. Separate several with commas; type none for none:");
        self.prompt(&hint);
        let answer = self.read()?;
        Some(match answer.as_str() {
            "" => default.to_vec(),
            "none" | "-" => Vec::new(),
            a => a.split(',').map(str::trim).filter(|p| !p.is_empty()).map(str::to_string).collect(),
        })
    }

    /// A confirmation before something is written: Enter means yes, and anything but a clear
    /// yes, after three tries, means no.
    pub fn confirm(&mut self, question: &str) -> Option<bool> {
        self.question(question);
        for _ in 0..TRIES {
            self.prompt("[Y/n]");
            match self.read()?.to_ascii_lowercase().as_str() {
                "" | "y" | "yes" => return Some(true),
                "n" | "no" => return Some(false),
                _ => self.note("Type y or n."),
            }
        }
        self.note("Not writing anything.");
        Some(false)
    }

    /// Yes or no; Enter takes `default`.
    pub fn yes(&mut self, question: &str, default: bool) -> Option<bool> {
        self.question(question);
        for _ in 0..TRIES {
            self.prompt(if default { "[Y/n]" } else { "[y/N]" });
            match self.read()?.to_ascii_lowercase().as_str() {
                "" => return Some(default),
                "y" | "yes" => return Some(true),
                "n" | "no" => return Some(false),
                _ => self.note("Type y or n."),
            }
        }
        Some(default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asker(input: &str) -> Asker<std::io::Cursor<Vec<u8>>, Vec<u8>> {
        Asker::new(std::io::Cursor::new(input.as_bytes().to_vec()), Vec::new())
    }

    #[test]
    fn enter_takes_the_default_and_a_number_picks_an_option() {
        let mut a = asker("\n3\n");
        assert_eq!(a.choice("Who works here?", &["Just me", "A small team", "A larger team"], 0), Some(0));
        assert_eq!(a.choice("Who works here?", &["Just me", "A small team", "A larger team"], 0), Some(2));
        let shown = String::from_utf8(a.output().clone()).unwrap();
        assert!(shown.contains("› 1  Just me  (default)") && shown.contains("    3  A larger team"), "{shown}");
        assert!(shown.contains("Choose 1 to 3, or press Enter for 1"), "{shown}");
    }

    #[test]
    fn a_bad_answer_is_asked_again_then_the_default_is_taken() {
        let mut a = asker("9\nnope\n2\n");
        assert_eq!(a.choice("Pick", &["a", "b"], 0), Some(1));
        let mut a = asker("9\n9\n9\n");
        assert_eq!(a.choice("Pick", &["a", "b"], 1), Some(1), "after three bad answers, the default");
    }

    #[test]
    fn text_lists_and_yes_no() {
        let mut a = asker("\nprod\nsrc/**, infra/**\n\nnone\nn\n\n");
        assert_eq!(a.text("Branch", "main").as_deref(), Some("main"));
        assert_eq!(a.text("Branch", "main").as_deref(), Some("prod"));
        assert_eq!(a.list("Paths", &[]), Some(vec!["src/**".to_string(), "infra/**".to_string()]));
        assert_eq!(a.list("Paths", &["a/**".to_string()]), Some(vec!["a/**".to_string()]), "Enter keeps the default");
        assert_eq!(a.list("Paths", &["a/**".to_string()]), Some(vec![]), "none clears it");
        assert_eq!(a.yes("Write?", true), Some(false));
        assert_eq!(a.yes("Write?", true), Some(true));
    }

    #[test]
    fn steps_and_the_summary_are_laid_out() {
        let mut a = asker("");
        a.step(2, 7, "Where changes land");
        a.table(&[("Changes land on", "main".to_string()), ("Approvals", "1".to_string())]);
        let shown = String::from_utf8(a.output().clone()).unwrap();
        assert!(shown.contains("2/7  Where changes land"), "{shown}");
        assert!(shown.contains("Changes land on   main") && shown.contains("Approvals         1"), "aligned: {shown}");
    }

    #[test]
    fn the_end_of_input_stops_the_questions() {
        let mut a = asker("");
        assert_eq!(a.choice("Pick", &["a", "b"], 0), None);
        assert_eq!(a.text("Branch", "main"), None);
    }
}
