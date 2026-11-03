//! Picking one thing from a numbered list, for a person at a terminal. There is no default: Enter
//! alone picks nothing, so an approval is never given to whatever happened to be first.

use std::io::{BufRead, Write};

use crate::ui::{Tone, Ui};

/// Show `rows` numbered, under `title` when given, and ask which. Returns the index chosen, or
/// `None` for `q`, end of input, or an answer that is not on the list. The list and the question
/// go to `out` (stderr for a command whose result goes to stdout); the answer comes from `input`.
pub fn choose(ui: &Ui, input: &mut impl BufRead, out: &mut impl Write, title: Option<&str>, rows: &[String], quit: &str) -> Option<usize> {
    let _ = writeln!(out);
    if let Some(title) = title {
        let _ = writeln!(out, "{}\n", ui.bold(title));
    }
    let width = rows.len().to_string().len();
    for (i, row) in rows.iter().enumerate() {
        let _ = writeln!(out, "  {}  {row}", ui.paint(Tone::Info, &format!("{:>width$}", i + 1)));
    }
    ask(ui, input, out, rows.len(), quit)
}

/// The question alone, for a list already on the screen: `count` things are numbered.
pub fn ask(ui: &Ui, input: &mut impl BufRead, out: &mut impl Write, count: usize, quit: &str) -> Option<usize> {
    ask_or(ui, input, out, count, quit, false)
}

/// [`ask`], where Enter alone picks the first entry: the one thing to do next (D91).
pub fn ask_or(ui: &Ui, input: &mut impl BufRead, out: &mut impl Write, count: usize, quit: &str, enter_picks_first: bool) -> Option<usize> {
    let width = count.to_string().len();
    let _ = writeln!(out, "  {}  {quit}", ui.paint(Tone::Dim, &format!("{:>width$}", "q")));
    let _ = write!(out, "\n{}> ", if enter_picks_first { ui.paint(Tone::Dim, "Enter does 1 ") } else { String::new() });
    let _ = out.flush();
    let mut line = String::new();
    if input.read_line(&mut line).ok()? == 0 {
        return None;
    }
    if enter_picks_first && line.trim().is_empty() {
        return Some(0);
    }
    let pick: usize = line.trim().parse().ok()?;
    (1..=count).contains(&pick).then(|| pick - 1)
}

/// [`choose`], where Enter alone picks the first row.
pub fn choose_first(ui: &Ui, input: &mut impl BufRead, out: &mut impl Write, rows: &[String], quit: &str) -> Option<usize> {
    let _ = writeln!(out);
    let width = rows.len().to_string().len();
    for (i, row) in rows.iter().enumerate() {
        let _ = writeln!(out, "  {}  {row}", ui.paint(Tone::Info, &format!("{:>width$}", i + 1)));
    }
    ask_or(ui, input, out, rows.len(), quit, true)
}

/// [`choose`] on the real terminal: the list on stderr, the answer from stdin.
pub fn choose_here(ui: &Ui, title: Option<&str>, rows: &[String], quit: &str) -> Option<usize> {
    choose(ui, &mut std::io::stdin().lock(), &mut std::io::stderr(), title, rows, quit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(answer: &str, rows: &[&str]) -> (Option<usize>, String) {
        let rows: Vec<String> = rows.iter().map(|r| r.to_string()).collect();
        let mut out = Vec::new();
        let picked = choose(&Ui::fixed(80, true), &mut std::io::Cursor::new(answer.as_bytes().to_vec()), &mut out, Some("Which?"), &rows, "Quit");
        (picked, String::from_utf8(out).unwrap())
    }

    #[test]
    fn a_number_picks_and_nothing_else_does() {
        assert_eq!(ask("2\n", &["a", "b"]).0, Some(1));
        assert_eq!(ask("\n", &["a", "b"]).0, None, "Enter alone picks nothing");
        assert_eq!(ask("q\n", &["a", "b"]).0, None);
        assert_eq!(ask("3\n", &["a", "b"]).0, None);
        assert_eq!(ask("0\n", &["a", "b"]).0, None);
        assert_eq!(ask("", &["a", "b"]).0, None, "end of input");
        let rows = vec!["do it".to_string(), "other".to_string()];
        let first = |answer: &str| choose_first(&Ui::fixed(80, true), &mut std::io::Cursor::new(answer.as_bytes().to_vec()), &mut Vec::new(), &rows, "Quit");
        assert_eq!(first("\n"), Some(0), "Enter does the first, where it is the next step");
        assert_eq!((first("2\n"), first("q\n"), first("")), (Some(1), None, None));
    }

    #[test]
    fn the_list_is_numbered_and_offers_to_quit() {
        let (_, shown) = ask("q\n", &["first", "second"]);
        assert!(shown.contains("Which?") && shown.contains("  1  first") && shown.contains("  2  second") && shown.contains("  q  Quit"), "{shown}");
    }
}
