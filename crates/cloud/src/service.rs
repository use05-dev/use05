//! Keeping the helper running: a launchd job on macOS, a `systemd --user` unit on Linux, and
//! where neither is there, the command to run under whatever supervisor you have.

/// The launchd job (macOS): run at login, kept alive, logging to `log`.
/// `developer_dir` is where the command line developer tools are. A login shell usually sets it; a
/// launchd job starts without it, and on a Mac whose Xcode licence is not accepted `/usr/bin/git`
/// then refuses to run, so the helper could see no repository.
pub fn launchd_plist(exe: &str, path_env: &str, developer_dir: Option<&str>, log: &str) -> String {
    let dev = developer_dir.map(|d| format!("<key>DEVELOPER_DIR</key><string>{d}</string>")).unwrap_or_default();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>dev.use05.cloud</string>\n<key>ProgramArguments</key><array><string>{exe}</string><string>run</string></array>\n<key>EnvironmentVariables</key><dict><key>PATH</key><string>{path_env}</string>{dev}</dict>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>StandardOutPath</key><string>{log}</string>\n<key>StandardErrorPath</key><string>{log}</string>\n</dict></plist>\n"
    )
}

/// The `systemd --user` unit (Linux): started with your session, restarted if it stops.
pub fn systemd_unit(exe: &str, path_env: &str, log: &str) -> String {
    format!(
        "[Unit]\nDescription=05 console helper\nAfter=network-online.target\n\n[Service]\nExecStart=\"{exe}\" run\nEnvironment=\"PATH={path_env}\"\nRestart=always\nRestartSec=5\nStandardOutput=append:{log}\nStandardError=append:{log}\n\n[Install]\nWantedBy=default.target\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_linux_unit_restarts_the_helper_and_starts_with_the_session() {
        let unit = systemd_unit("/home/a b/.local/bin/use05-cloud", "/usr/bin:/bin", "/home/a b/.config/05/cloud.log");
        assert!(unit.contains("ExecStart=\"/home/a b/.local/bin/use05-cloud\" run"), "{unit}");
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("Environment=\"PATH=/usr/bin:/bin\""));
        assert!(unit.contains("StandardOutput=append:/home/a b/.config/05/cloud.log"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn the_mac_job_keeps_the_helper_alive() {
        let plist = launchd_plist("/usr/local/bin/use05-cloud", "/usr/bin:/bin", None, "/Users/a/.config/05/cloud.log");
        assert!(plist.contains("<string>dev.use05.cloud</string>") && plist.contains("<key>KeepAlive</key><true/>"), "{plist}");
        assert!(plist.contains("<string>/usr/local/bin/use05-cloud</string><string>run</string>"));
    }

    #[test]
    fn the_mac_job_hands_the_helper_the_developer_tools() {
        let plist = launchd_plist("/x/use05-cloud", "/usr/bin:/bin", Some("/Library/Developer/CommandLineTools"), "/l");
        assert!(plist.contains("<key>DEVELOPER_DIR</key><string>/Library/Developer/CommandLineTools</string>"), "{plist}");
        assert!(!launchd_plist("/x/use05-cloud", "/usr/bin:/bin", None, "/l").contains("DEVELOPER_DIR"));
    }
}
