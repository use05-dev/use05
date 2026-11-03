//! `--help` anywhere prints the commands and does nothing else: a subcommand asked for help must
//! never pair, install, sync or report.

use std::process::Command;

#[test]
fn help_on_any_command_prints_the_commands_and_touches_nothing() {
    let home = tempfile::tempdir().unwrap();
    for args in [&["--help"][..], &["install", "--help"], &["sync", "-h"], &["login", "https://console.example.com", "--help"], &["ci", "report", "--help"], &["status", "--help"]] {
        let out = Command::new(env!("CARGO_BIN_EXE_use05-cloud")).args(args).env("HOME", home.path()).env("USE05_HOME", home.path()).env("XDG_CONFIG_HOME", home.path()).output().unwrap();
        let said = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(said.contains("login <url>") && said.contains("connects out only"), "{args:?} prints the commands:\n{said}");
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0, "{args:?} wrote nothing");
    }
}
