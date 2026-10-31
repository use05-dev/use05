//! One result, two renderings. Human output and `--json` are built from the same `Report`,
//! so they cannot drift apart.

use std::io::IsTerminal;
use std::process::ExitCode;

use serde_json::{Value, json};

pub use crate::ui::Tone;
use crate::ui::{Glyph, Ui};

pub struct Report {
    pub command: &'static str,
    /// Machine word: valid, invalid, stale, malformed, passed, failed, error, ...
    pub outcome: &'static str,
    /// Stable code, for scripts and `--json`.
    pub code: &'static str,
    pub tone: Tone,
    pub headline: String,
    pub rows: Vec<(String, String)>,
    pub notes: Vec<String>,
    pub next: Option<String>,
    /// The end of a failed command's output. Shown to a person only: never signed, stored, or
    /// included in `--json`.
    pub excerpt: Vec<String>,
    pub details: Value,
    pub exit: u8,
}

impl Report {
    pub fn json(&self) -> Value {
        json!({
            "v": 1,
            "command": self.command,
            "ok": self.exit == 0,
            "outcome": self.outcome,
            "code": self.code,
            "message": self.headline,
            "notes": self.notes,
            "next": self.next,
            "details": self.details,
        })
    }

    pub fn error(command: &'static str, code: &'static str, message: String, next: Option<String>, exit: u8) -> Report {
        Report {
            command,
            outcome: "error",
            code,
            tone: Tone::Bad,
            headline: message,
            rows: Vec::new(),
            notes: Vec::new(),
            next,
            excerpt: Vec::new(),
            details: Value::Null,
            exit,
        }
    }

    pub fn from_core(command: &'static str, e: use05_core::Error) -> Report {
        let exit = if matches!(e.code, "GIT_MISSING" | "IO_ERROR" | "NO_USER_DIR") { 4 } else { 6 };
        Report::error(command, e.code, e.message, e.next, exit)
    }
}

pub fn render_human(report: &Report, ui: &Ui) -> String {
    let glyph = match report.tone {
        Tone::Good => ui.glyph(Glyph::Ok),
        Tone::Bad => ui.glyph(Glyph::Bad),
        Tone::Warn | Tone::Info => ui.glyph(Glyph::Warn),
        _ => ui.glyph(Glyph::Dot),
    };
    let mut out = String::new();
    let head = ui.wrap(&report.headline, ui.width.saturating_sub(2));
    for (i, line) in head.iter().enumerate() {
        let lead = if i == 0 { ui.paint(report.tone, glyph) } else { " ".to_string() };
        out.push_str(&format!("{lead} {line}\n"));
    }

    let label_w = report.rows.iter().map(|(l, _)| l.chars().count()).max().unwrap_or(0);
    let value_w = ui.width.saturating_sub(label_w + 4).max(20);
    for (label, value) in &report.rows {
        for (i, line) in ui.wrap(value, value_w).iter().enumerate() {
            let lead = if i == 0 { ui.paint(Tone::Dim, &format!("{label:<label_w$}")) } else { " ".repeat(label_w) };
            out.push_str(&format!("  {lead}  {line}\n"));
        }
    }
    for note in &report.notes {
        for line in ui.wrap(note, ui.width.saturating_sub(4)) {
            out.push_str(&format!("  {}\n", ui.paint(Tone::Dim, &line)));
        }
    }
    if !report.excerpt.is_empty() {
        out.push_str(&format!("\n  {}\n", ui.paint(Tone::Dim, "last output (shown here only; not in the receipt):")));
        for line in &report.excerpt {
            let room = ui.width.saturating_sub(6);
            let line = crate::ui::truncate_middle(line, room);
            out.push_str(&format!("  {} {line}\n", ui.paint(Tone::Dim, ui.glyph(Glyph::Bar))));
        }
    }
    if let Some(next) = &report.next {
        out.push('\n');
        let lines = ui.wrap(next, ui.width.saturating_sub(6));
        for (i, line) in lines.iter().enumerate() {
            let lead = if i == 0 { format!("{} ", ui.paint(Tone::Info, "Next:")) } else { "      ".to_string() };
            out.push_str(&format!("{lead}{line}\n"));
        }
    }
    ui.finish(out)
}

/// Print the report and return its exit code. Requests that failed go to stderr, results to stdout.
pub fn emit(report: &Report, json: bool) -> ExitCode {
    if json {
        println!("{}", serde_json::to_string_pretty(&report.json()).expect("report serialises"));
    } else if report.outcome == "error" {
        eprint!("{}", render_human(report, &Ui::stderr()));
    } else {
        let _ = std::io::stdout().is_terminal();
        print!("{}", render_human(report, &Ui::stdout()));
    }
    ExitCode::from(report.exit)
}

/// How long something took, for people: `340ms`, `12.4s`, `3m05s`.
pub fn duration(ms: u64) -> String {
    match ms {
        0..=999 => format!("{ms}ms"),
        1000..=59_999 => format!("{:.1}s", ms as f64 / 1000.0),
        _ => format!("{}m{:02}s", ms / 60_000, (ms % 60_000) / 1000),
    }
}

/// A command line for display: quoted where needed, shortened if long.
pub fn command_text(argv: &[String]) -> String {
    let quote = |arg: &String| {
        if !arg.is_empty() && arg.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:,@+".contains(c)) {
            arg.clone()
        } else {
            format!("'{}'", arg.replace('\'', r"'\''"))
        }
    };
    let text = argv.iter().map(quote).collect::<Vec<_>>().join(" ");
    if text.chars().count() > 60 {
        format!("{}…", text.chars().take(59).collect::<String>())
    } else {
        text
    }
}

/// Turn the end of untrusted command output into something safe to print: control characters
/// (including escape sequences that could rewrite the terminal) become a visible dot.
pub fn excerpt_lines(tail: &[u8], max_lines: usize) -> Vec<String> {
    let text = String::from_utf8_lossy(tail);
    let clean: String = text
        .chars()
        .map(|c| match c {
            '\n' => '\n',
            '\t' => ' ',
            c if c.is_control() => '·',
            c => c,
        })
        .collect();
    let lines: Vec<&str> = clean.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..]
        .iter()
        .map(|line| if line.chars().count() > 160 { format!("{}…", line.chars().take(159).collect::<String>()) } else { line.to_string() })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_naturally() {
        assert_eq!(duration(5), "5ms");
        assert_eq!(duration(12_400), "12.4s");
        assert_eq!(duration(185_000), "3m05s");
    }

    #[test]
    fn output_excerpts_cannot_carry_terminal_escapes() {
        let hostile = b"fine line\n\x1b[2J\x1b]0;owned\x07\rcarriage\nlast";
        let lines = excerpt_lines(hostile, 10);
        assert!(lines.iter().all(|l| !l.chars().any(|c| c.is_control())), "{lines:?}");
        assert_eq!(lines.last().unwrap(), "last");
        assert_eq!(excerpt_lines(b"a\nb\nc\nd", 2), ["c", "d"], "only the end is kept");
    }

    #[test]
    fn commands_are_quoted_and_shortened() {
        let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(command_text(&argv(&["cargo", "test", "--all"])), "cargo test --all");
        assert_eq!(command_text(&argv(&["sh", "-c", "exit 3"])), "sh -c 'exit 3'");
        assert!(command_text(&argv(&["echo", &"x".repeat(100)])).ends_with('…'));
    }

    #[test]
    fn a_narrow_terminal_wraps_instead_of_overflowing() {
        let mut r = Report::error("t", "X", "x".into(), None, 0);
        r.outcome = "ok";
        r.tone = Tone::Good;
        r.headline = "Proved: a fairly long command line that will need to wrap on a narrow screen".into();
        r.rows = vec![("receipt".to_string(), "05-receipts/545b03fcf8edc260/receipts/726de36789ef204adf3f4fa74bb8963aff6f9c4c/c19b61b7f373a884.json".into())];
        r.next = Some("use05 verify 05-receipts/545b03fcf8edc260 --key dev.key.pub --tree HEAD and then something more".into());
        for width in [40, 60, 100] {
            let text = render_human(&r, &Ui::fixed(width, true));
            assert!(text.lines().all(|l| l.chars().count() <= width), "width {width}:\n{text}");
        }
    }
}
