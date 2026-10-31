//! Questions on the terminal, with a default for each: Enter accepts it. Reads and writes plain
//! streams, so the guided setup can be driven by a script or a test as well as a person.

use std::io::{BufRead, Write};

/// Asks questions on `output` and reads answers from `input`. Every answer is optional: `None`
/// means the input ended, and the caller stops without changing anything.
pub struct Asker<R: BufRead, W: Write> {
    input: R,
    output: W,
}

/// A bad answer is asked again this many times; then the default stands.
const TRIES: usize = 3;

impl<R: BufRead, W: Write> Asker<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Asker { input, output }
    }

    #[cfg(test)]
    pub fn output(&self) -> &W {
        &self.output
    }

    /// Text for the person: a heading, an explanation.
    pub fn say(&mut self, text: &str) {
        let _ = writeln!(self.output, "{text}");
    }

    fn read(&mut self) -> Option<String> {
        let _ = self.output.flush();
        let mut line = String::new();
        match self.input.read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line.trim().to_string()),
        }
    }

    /// One of `options`; Enter takes `default`.
    pub fn choice(&mut self, question: &str, options: &[&str], default: usize) -> Option<usize> {
        let _ = writeln!(self.output, "\n{question}");
        for (i, o) in options.iter().enumerate() {
            let _ = writeln!(self.output, "  {}) {o}{}", i + 1, if i == default { " (default)" } else { "" });
        }
        for _ in 0..TRIES {
            let _ = write!(self.output, "> [{}] ", default + 1);
            let answer = self.read()?;
            if answer.is_empty() {
                return Some(default);
            }
            match answer.parse::<usize>() {
                Ok(n) if (1..=options.len()).contains(&n) => return Some(n - 1),
                _ => {
                    let _ = writeln!(self.output, "  Type a number from 1 to {}, or press Enter for {}.", options.len(), default + 1);
                }
            }
        }
        let _ = writeln!(self.output, "  Keeping the default: {}.", options[default]);
        Some(default)
    }

    /// Free text; Enter takes `default`.
    pub fn text(&mut self, question: &str, default: &str) -> Option<String> {
        let shown = if default.is_empty() { String::new() } else { format!("[{default}] ") };
        let _ = write!(self.output, "\n{question}\n> {shown}");
        let answer = self.read()?;
        Some(if answer.is_empty() { default.to_string() } else { answer })
    }

    /// A comma-separated list; Enter keeps `default`, `none` empties it.
    pub fn list(&mut self, question: &str, default: &[String]) -> Option<Vec<String>> {
        let shown = if default.is_empty() { "none".to_string() } else { default.join(", ") };
        let _ = write!(self.output, "\n{question}\n  Separate several with commas; type none for none.\n> [{shown}] ");
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
        for _ in 0..TRIES {
            let _ = write!(self.output, "\n{question} [Y/n] ");
            match self.read()?.to_ascii_lowercase().as_str() {
                "" | "y" | "yes" => return Some(true),
                "n" | "no" => return Some(false),
                _ => {
                    let _ = writeln!(self.output, "  Type y or n.");
                }
            }
        }
        let _ = writeln!(self.output, "  Not writing anything.");
        Some(false)
    }

    /// Yes or no; Enter takes `default`.
    pub fn yes(&mut self, question: &str, default: bool) -> Option<bool> {
        for _ in 0..TRIES {
            let _ = write!(self.output, "\n{question} [{}] ", if default { "Y/n" } else { "y/N" });
            match self.read()?.to_ascii_lowercase().as_str() {
                "" => return Some(default),
                "y" | "yes" => return Some(true),
                "n" | "no" => return Some(false),
                _ => {
                    let _ = writeln!(self.output, "  Type y or n.");
                }
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
        assert!(shown.contains("1) Just me (default)") && shown.contains("3) A larger team"), "{shown}");
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
    fn the_end_of_input_stops_the_questions() {
        let mut a = asker("");
        assert_eq!(a.choice("Pick", &["a", "b"], 0), None);
        assert_eq!(a.text("Branch", "main"), None);
    }
}
