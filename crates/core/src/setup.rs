//! What a guided setup needs to know about a repository: its long-lived branches, which
//! environment each probably is, and the starting rules for the kind of team working in it (D82).

use std::path::Path;

use crate::policy::{CheckDef, IntentMode, LandMode, Policy, Severity};

/// An environment's role on the ladder, lowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Dev,
    Uat,
    PreProd,
    Prod,
}

impl Role {
    pub const ALL: [Role; 4] = [Role::Dev, Role::Uat, Role::PreProd, Role::Prod];

    pub fn name(self) -> &'static str {
        match self {
            Role::Dev => "dev",
            Role::Uat => "uat",
            Role::PreProd => "pre-prod",
            Role::Prod => "prod",
        }
    }

    pub fn from_name(name: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.name() == name)
    }
}

/// The role a branch's name suggests, if any. Only a suggestion: the person decides.
pub fn suggest_role(branch: &str) -> Option<Role> {
    match branch.to_ascii_lowercase().as_str() {
        "main" | "master" | "develop" | "development" | "dev" | "trunk" => Some(Role::Dev),
        "qa" | "test" | "testing" | "uat" | "staging" => Some(Role::Uat),
        "preprod" | "pre-prod" | "pre-production" | "stage" => Some(Role::PreProd),
        "prod" | "production" | "live" | "release" => Some(Role::Prod),
        _ => None,
    }
}

/// A branch worth asking about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchInfo {
    pub name: String,
    pub local: bool,
    pub remote: bool,
}

/// Long-lived branches, here and on `origin`: not agents' working branches, not bots' branches,
/// not temporary ones. Lowest suggested role first, then branches with no suggestion, each by name.
pub fn scan(top: &Path, policy: &Policy) -> Vec<BranchInfo> {
    let refs = crate::git::text(top, &["for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes/origin"]).unwrap_or_default();
    let mut out: Vec<BranchInfo> = Vec::new();
    for r in refs.lines() {
        let (name, local) = match (r.strip_prefix("refs/heads/"), r.strip_prefix("refs/remotes/origin/")) {
            (Some(n), _) => (n, true),
            (None, Some(n)) => (n, false),
            _ => continue,
        };
        let temporary = name == "HEAD"
            || crate::branches::is_work(policy, name)
            || ["dependabot/", "renovate/", "promote-"].iter().any(|p| name.starts_with(p))
            || name.ends_with("-tmp");
        if temporary {
            continue;
        }
        match out.iter_mut().find(|b| b.name == name) {
            Some(b) if local => b.local = true,
            Some(b) => b.remote = true,
            None => out.push(BranchInfo { name: name.to_string(), local, remote: !local }),
        }
    }
    out.sort_by(|a, b| {
        let rank = |n: &str| suggest_role(n).map_or(Role::ALL.len(), |r| r as usize);
        rank(&a.name).cmp(&rank(&b.name)).then(a.name.cmp(&b.name))
    });
    out
}

/// Who works in the repository: the starting point for how strict the rules are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Team {
    Solo,
    Small,
    Regulated,
}

impl Team {
    pub fn from_name(name: &str) -> Option<Team> {
        match name {
            "solo" => Some(Team::Solo),
            "small" => Some(Team::Small),
            "regulated" => Some(Team::Regulated),
            _ => None,
        }
    }
}

/// The settings a team's preset starts from; every one can be changed afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preset {
    pub intent: IntentMode,
    pub scope: Severity,
    pub dependencies: Severity,
    pub overlap: Severity,
    pub tests: Severity,
    pub approvals_min: u32,
    /// How finished work lands: on its own for a person working alone (D91).
    pub land: LandMode,
}

pub fn preset(team: Team) -> Preset {
    match team {
        Team::Solo => Preset { intent: IntentMode::Inferred, scope: Severity::Warn, dependencies: Severity::Warn, overlap: Severity::Warn, tests: Severity::Approval, approvals_min: 1, land: LandMode::Auto },
        Team::Small => Preset { intent: IntentMode::Risky, scope: Severity::Approval, dependencies: Severity::Approval, overlap: Severity::Approval, tests: Severity::Approval, approvals_min: 1, land: LandMode::Manual },
        Team::Regulated => Preset { intent: IntentMode::Always, scope: Severity::Deny, dependencies: Severity::Approval, overlap: Severity::Deny, tests: Severity::Deny, approvals_min: 2, land: LandMode::Manual },
    }
}

// ----------------------------------------------------------------------------- workspaces (D97)

/// One package of a monorepo: where it is, which tool manages it, and the command that tests it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    /// Relative to the top of the repository, with `/`.
    pub dir: String,
    /// `npm`, `pnpm`, `yarn`, `cargo`, `go` or `uv`.
    pub kind: &'static str,
    pub test: Vec<String>,
}

/// The packages found, and the patterns and members that were left out, said in plain words.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceScan {
    pub workspaces: Vec<Workspace>,
    pub skipped: Vec<String>,
    /// The top of the repository is itself a package (a root crate beside its members, a `use .`
    /// in `go.work`, a root with its own `src` and test script), which no per-package check covers.
    pub root_is_package: bool,
}

/// The packages of the repository's workspaces, read from manifest files only: no network and no
/// package manager is run. A member list is expanded when it is a folder or `folder/*`.
pub fn workspaces(top: &Path) -> Vec<Workspace> {
    scan_workspaces(top).workspaces
}

/// Like [`workspaces`], and also what could not be expanded or used, for init to say.
pub fn scan_workspaces(top: &Path) -> WorkspaceScan {
    let mut scan = WorkspaceScan::default();
    let read = |name: &str| std::fs::read_to_string(top.join(name)).ok();
    let toml_of = |name: &str| read(name).and_then(|t| toml::from_str::<toml::Table>(&t).ok());
    let strings = |v: Option<&toml::Value>| -> Vec<String> { v.and_then(toml::Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default() };

    // npm, yarn and pnpm: packages with a package.json, tested with their `test` script.
    let pnpm = read("pnpm-workspace.yaml").map(|t| yaml_packages(&t));
    let package_json = read("package.json").and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
    let from_package_json = || -> Vec<String> {
        let w = package_json.as_ref().and_then(|p| p.get("workspaces"));
        let list = w.and_then(|w| w.as_array().or_else(|| w.get("packages").and_then(|p| p.as_array())));
        list.map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
    };
    let (js_kind, js_patterns) = match pnpm {
        Some(p) => ("pnpm", p),
        None => {
            let yarn = top.join("yarn.lock").is_file() || package_json.as_ref().and_then(|p| p.get("packageManager")).and_then(|m| m.as_str()).is_some_and(|m| m.starts_with("yarn@"));
            (if yarn { "yarn" } else { "npm" }, from_package_json())
        }
    };
    let root_test = package_json.as_ref().and_then(|p| p.get("scripts")).and_then(|s| s.get("test")).is_some();
    if !js_patterns.is_empty() && root_test && top.join("src").is_dir() {
        scan.root_is_package = true;
    }
    for dir in expand(top, &js_patterns, "package.json", &mut scan.skipped) {
        let manifest: Option<serde_json::Value> = std::fs::read_to_string(top.join(&dir).join("package.json")).ok().and_then(|t| serde_json::from_str(&t).ok());
        if manifest.as_ref().and_then(|m| m.get("scripts")).and_then(|s| s.get("test")).is_none() {
            scan.skipped.push(format!("{dir} has no test script in its package.json, so no check was suggested for it"));
            continue;
        }
        let name = manifest.as_ref().and_then(|m| m.get("name")).and_then(|n| n.as_str()).map(str::to_string);
        let test = match js_kind {
            "pnpm" => vec!["pnpm".to_string(), "--filter".into(), format!("./{dir}"), "test".into()],
            "yarn" => match name {
                Some(n) => vec!["yarn".to_string(), "workspace".into(), n, "test".into()],
                None => {
                    scan.skipped.push(format!("{dir} has no name in its package.json, so no yarn check was suggested for it"));
                    continue;
                }
            },
            _ => vec!["npm".to_string(), "test".into(), "--workspace".into(), dir.clone()],
        };
        scan.workspaces.push(Workspace { dir, kind: js_kind, test });
    }

    // Cargo and uv: members named in the manifest, tested by package name.
    for (kind, file, section, name_in, test) in [
        ("cargo", "Cargo.toml", "workspace", "package", &["cargo", "test", "-p"][..]),
        ("uv", "pyproject.toml", "tool.uv.workspace", "project", &["uv", "run", "--package"][..]),
    ] {
        let Some(table) = toml_of(file) else { continue };
        let Some(ws) = section.split('.').try_fold(&table, |t, key| t.get(key).and_then(toml::Value::as_table)) else { continue };
        if table.get(name_in).is_some() {
            scan.root_is_package = true; // a root crate or project beside its members
        }
        let mut patterns = strings(ws.get("members"));
        patterns.extend(strings(ws.get("exclude")).into_iter().map(|e| format!("!{e}")));
        for dir in expand(top, &patterns, file, &mut scan.skipped) {
            let Some(name) = toml_of(&format!("{dir}/{file}")).and_then(|t| t.get(name_in)?.get("name")?.as_str().map(str::to_string)) else {
                scan.skipped.push(format!("{dir} has no package name in its {file}, so no check was suggested for it"));
                continue;
            };
            let mut command: Vec<String> = test.iter().map(|s| s.to_string()).collect();
            command.push(name);
            if kind == "uv" {
                command.push("pytest".into());
            }
            scan.workspaces.push(Workspace { dir, kind, test: command });
        }
    }

    // Go: the modules a go.work uses, each tested from its own folder.
    if let Some(text) = read("go.work") {
        let patterns = go_work_uses(&text);
        if patterns.iter().any(|p| p.trim().trim_start_matches("./").trim_end_matches('/') == ".") {
            scan.root_is_package = true;
        }
        let modules = expand(top, &patterns, "go.mod", &mut scan.skipped);
        scan.workspaces.extend(modules.into_iter().map(|dir| Workspace { dir, kind: "go", test: vec!["go".into(), "test".into(), "./...".into()] }));
    }
    scan
}

impl Workspace {
    /// Go tests run from the module's own folder; the others are run from the top, naming the package.
    pub fn runs_in_dir(&self) -> bool {
        self.kind == "go"
    }

    /// The files at the top that define the workspace, which exist: a change to one can change
    /// every package.
    pub fn manifests(&self, top: &Path) -> Vec<&'static str> {
        let names: &[&'static str] = match self.kind {
            "pnpm" => &["pnpm-workspace.yaml", "package.json"],
            "cargo" => &["Cargo.toml"],
            "go" => &["go.work"],
            "uv" => &["pyproject.toml"],
            _ => &["package.json"],
        };
        names.iter().copied().filter(|n| top.join(n).is_file()).collect()
    }

    /// The lockfile at the top of the repository that a change to this package's dependencies edits.
    pub fn lockfile(&self) -> &'static str {
        match self.kind {
            "npm" => "package-lock.json",
            "pnpm" => "pnpm-lock.yaml",
            "yarn" => "yarn.lock",
            "cargo" => "Cargo.lock",
            "go" => "go.work.sum",
            _ => "uv.lock",
        }
    }
}

/// One check per package: required only when the change touches the package or its root
/// lockfile (D97). Names are `test-<folder>`, kept apart when two packages share a folder name.
pub fn workspace_checks(top: &Path, found: &[Workspace]) -> Vec<CheckDef> {
    let clean = |s: &str| -> String { s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '-' }).collect::<String>().trim_matches('-').to_string() };
    let mut names: Vec<String> = Vec::new();
    found
        .iter()
        .map(|w| {
            let last = clean(w.dir.rsplit('/').next().unwrap_or(&w.dir));
            let candidates = [format!("test-{last}"), format!("test-{}", clean(&w.dir)), format!("test-{}-{}", clean(&w.dir), w.kind)];
            let name = candidates.iter().find(|c| !names.contains(c)).cloned().unwrap_or_else(|| format!("test-{}-{}-{}", clean(&w.dir), w.kind, names.len()));
            names.push(name.clone());
            let mut paths = vec![format!("{}/**", w.dir)];
            paths.extend(w.manifests(top).into_iter().map(str::to_string));
            if top.join(w.lockfile()).is_file() {
                paths.push(w.lockfile().to_string());
            }
            CheckDef {
                name,
                run: w.test.clone(),
                env: if matches!(w.kind, "cargo" | "go") { vec!["HOME".into()] } else { Vec::new() },
                paths,
                dir: w.runs_in_dir().then(|| w.dir.clone()),
                ..CheckDef::default()
            }
        })
        .collect()
}

/// What init says about the per-package checks it found, in one sentence.
pub fn workspace_note(found: &[Workspace], root_is_package: bool) -> String {
    let mut kinds: Vec<&str> = found.iter().map(|w| w.kind).collect();
    kinds.sort();
    kinds.dedup();
    format!(
        "Found {} in this monorepo ({}): each gets its own check, required only when a change touches its folder, the files that define the workspace or its lockfile, in place of the single `test` check{}.",
        if found.len() == 1 { "1 package".to_string() } else { format!("{} packages", found.len()) },
        kinds.join(", "),
        if root_is_package { " (the top of the repository is a package too, so its `test` check stays and runs for every change)" } else { "" }
    )
}

/// Said after init wrote per-package checks: what scoping by folder cannot see.
pub fn workspace_caveat() -> &'static str {
    "A package is not rerun when only a package it depends on changes, unless its `paths` name that folder: add \"<folder>/**\" to that check's `paths` in the policy file (`use05 policy add` cannot address one check)."
}

/// The checks init starts from in a repository with workspaces: those found at the top, with the
/// single `test` check given up for one per package, which cover what it covered. When the top
/// is itself a package, its `test` check stays, for every change, since no package check covers it.
pub fn with_workspace_checks(top_level: Vec<CheckDef>, per_package: Vec<CheckDef>, root_is_package: bool) -> Vec<CheckDef> {
    if per_package.is_empty() {
        return top_level;
    }
    top_level.into_iter().filter(|c| c.name != "test" || root_is_package).chain(per_package).collect()
}

/// `packages:` in a `pnpm-workspace.yaml`, the lines of a list or a one-line `[a, b]`. Nothing
/// else of the file is read.
fn yaml_packages(text: &str) -> Vec<String> {
    let unquote = |s: &str| s.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
    let mut out = Vec::new();
    let mut inside = false;
    for raw in text.lines() {
        let cut = if raw.trim_start().starts_with('#') { Some(0) } else { raw.find(" #") };
        let line = cut.map_or(raw, |at| &raw[..at]);
        if line.trim().is_empty() {
            continue;
        }
        let indented = line.starts_with([' ', '\t']);
        if !indented && !line.starts_with('-') {
            inside = false;
            if let Some(rest) = line.strip_prefix("packages:") {
                let rest = rest.trim();
                if let Some(flow) = rest.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
                    out.extend(flow.split(',').map(unquote).filter(|s| !s.is_empty()));
                } else {
                    inside = rest.is_empty();
                }
            }
            continue;
        }
        if inside {
            if let Some(item) = line.trim_start().strip_prefix('-') {
                out.push(unquote(item));
            }
        }
    }
    out
}

/// The folders a `go.work` uses: `use ./a`, or a `use ( ... )` block.
fn go_work_uses(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut block = false;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        let item = if block {
            if line == ")" {
                block = false;
                continue;
            }
            line
        } else if let Some(rest) = line.strip_prefix("use").filter(|r| r.starts_with([' ', '\t', '('])) {
            let rest = rest.trim();
            if rest == "(" {
                block = true;
                continue;
            }
            rest
        } else {
            continue;
        };
        let item = item.trim().trim_matches('"');
        if !item.is_empty() {
            out.push(item.to_string());
        }
    }
    out
}

/// Members a manifest lists, as folders that exist and hold `manifest`. A member is a folder or
/// `folder/*`; `!` before a pattern leaves matches out. Anything else is left out and said.
fn expand(top: &Path, patterns: &[String], manifest: &str, skipped: &mut Vec<String>) -> Vec<String> {
    let tidy = |p: &str| p.trim().trim_start_matches("./").trim_end_matches('/').to_string();
    let wild = |p: &str| p.contains(['*', '?', '[', '{']);
    let outside = |p: &str| p.is_empty() || p.starts_with('/') || p.contains(['\\', ':']) || p.split('/').any(|s| s == "..");
    // `folder/*`, or `*` for the top itself: the folder whose children are meant.
    let children_of = |p: &str| -> Option<String> {
        let prefix = if p == "*" { "" } else { p.strip_suffix("/*")? };
        (!wild(prefix) && (prefix.is_empty() || !outside(prefix))).then(|| prefix.to_string())
    };
    let mut found: Vec<String> = Vec::new();
    let mut left_out: Vec<String> = Vec::new();
    for pattern in patterns {
        let (negated, body) = match pattern.strip_prefix('!') {
            Some(rest) => (true, tidy(rest)),
            None => (false, tidy(pattern)),
        };
        if body == "." {
            continue; // the top itself: init's own checks cover it
        }
        if body != "*" && outside(&body) {
            skipped.push(format!("{pattern:?} points outside the repository, so it was left out"));
            continue;
        }
        let matched: Vec<String> = if !wild(&body) {
            vec![body.clone()]
        } else if let Some(prefix) = children_of(&body) {
            let mut dirs: Vec<String> = std::fs::read_dir(top.join(&prefix))
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| !n.starts_with('.') && n != "node_modules" && n != "target")
                .map(|n| if prefix.is_empty() { n } else { format!("{prefix}/{n}") })
                .collect();
            dirs.sort();
            dirs
        } else {
            skipped.push(format!("{pattern:?} is more than a folder or folder/*, so 05 did not expand it; add a check for those packages yourself"));
            continue;
        };
        if negated {
            left_out.extend(matched);
        } else {
            for dir in matched {
                if !top.join(&dir).join(manifest).is_file() {
                    if !wild(&body) {
                        skipped.push(format!("{dir} has no {manifest}, so it was left out"));
                    }
                    continue;
                }
                if !found.contains(&dir) {
                    found.push(dir);
                }
            }
        }
    }
    found.retain(|d| !left_out.contains(d));
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(dir: &std::path::Path, args: &[&str]) {
        let ok = std::process::Command::new("git").arg("-C").arg(dir).args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]).args(args).output().unwrap();
        assert!(ok.status.success(), "{args:?}: {}", String::from_utf8_lossy(&ok.stderr));
    }

    #[test]
    fn long_lived_branches_are_found_locally_and_on_origin_and_work_branches_left_out() {
        let origin = tempfile::tempdir().unwrap();
        git(origin.path(), &["init", "-q", "-b", "main"]);
        git(origin.path(), &["commit", "-q", "--allow-empty", "-m", "first"]);
        for b in ["uat", "production", "claude/fix-1", "dependabot/npm/x", "feature-tmp"] {
            git(origin.path(), &["branch", b]);
        }
        let clone = tempfile::tempdir().unwrap();
        git(clone.path(), &["clone", "-q", origin.path().to_str().unwrap(), "."]);
        git(clone.path(), &["branch", "dev"]);
        let names: Vec<String> = scan(clone.path(), &Policy::default()).into_iter().map(|b| b.name).collect();
        assert_eq!(names, ["dev", "main", "uat", "production"], "ladder order by suggested role, then name");
    }

    #[test]
    fn roles_are_suggested_from_common_names() {
        let cases = [("main", Some(Role::Dev)), ("develop", Some(Role::Dev)), ("staging", Some(Role::Uat)), ("QA", Some(Role::Uat)), ("pre-prod", Some(Role::PreProd)), ("production", Some(Role::Prod)), ("live", Some(Role::Prod)), ("feature/x", None)];
        for (name, role) in cases {
            assert_eq!(suggest_role(name), role, "{name}");
        }
        assert_eq!(Role::PreProd.name(), "pre-prod");
        assert_eq!(Role::from_name("pre-prod"), Some(Role::PreProd));
    }

    #[test]
    fn presets_get_stricter_with_the_team() {
        let solo = preset(Team::Solo);
        assert_eq!((solo.intent, solo.scope, solo.tests, solo.approvals_min, solo.land), (IntentMode::Inferred, Severity::Warn, Severity::Approval, 1, LandMode::Auto));
        let small = preset(Team::Small);
        assert_eq!((small.intent, small.scope, small.dependencies, small.overlap, small.approvals_min), (IntentMode::Risky, Severity::Approval, Severity::Approval, Severity::Approval, 1));
        let reg = preset(Team::Regulated);
        assert_eq!((reg.intent, reg.scope, reg.overlap, reg.tests, reg.approvals_min), (IntentMode::Always, Severity::Deny, Severity::Deny, Severity::Deny, 2));
    }
}

#[cfg(test)]
mod workspace_tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, body) in files {
            let full = dir.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, body).unwrap();
        }
        dir
    }

    fn pkg(name: &str) -> String {
        format!("{{\"name\":\"{name}\",\"scripts\":{{\"test\":\"x\"}}}}")
    }

    fn dirs(found: &[Workspace]) -> Vec<&str> {
        found.iter().map(|w| w.dir.as_str()).collect()
    }

    #[test]
    fn pnpm_packages_are_found_by_folder_with_exclusions_and_packages_without_a_test_script_noted() {
        let yaml = "# the packages\npackages:\n  - 'packages/*'   # all of them\n  - \"tools/cli\"\n  - '!packages/legacy'\n\nonlyBuiltDependencies:\n  - esbuild\n";
        let root = tree(&[
            ("pnpm-workspace.yaml", yaml),
            ("packages/api/package.json", &pkg("@acme/api")),
            ("packages/web/package.json", &pkg("@acme/web")),
            ("packages/legacy/package.json", &pkg("@acme/legacy")),
            ("packages/docs/package.json", "{\"name\":\"docs\"}"),
            ("packages/notes/readme.md", "not a package"),
            ("tools/cli/package.json", &pkg("cli")),
        ]);
        let scan = scan_workspaces(root.path());
        assert_eq!(dirs(&scan.workspaces), ["packages/api", "packages/web", "tools/cli"]);
        assert_eq!(scan.workspaces[0].test, ["pnpm", "--filter", "./packages/api", "test"]);
        assert!(scan.workspaces.iter().all(|w| w.kind == "pnpm"));
        assert_eq!(scan.skipped.len(), 1, "{:?}", scan.skipped);
        assert!(scan.skipped[0].contains("packages/docs") && scan.skipped[0].contains("no test script"), "{:?}", scan.skipped);
    }

    #[test]
    fn npm_workspaces_in_either_form_get_the_workspace_flag_and_yarn_is_told_by_its_lockfile() {
        let files = |manifest: &str, extra: &[(&'static str, &'static str)]| {
            let mut all = vec![("package.json", manifest.to_string()), ("apps/a/package.json", pkg("a")), ("apps/b/package.json", pkg("b"))];
            all.extend(extra.iter().map(|(p, b)| (*p, b.to_string())));
            let refs: Vec<(&str, &str)> = all.iter().map(|(p, b)| (*p, b.as_str())).collect();
            tree(&refs)
        };
        let npm = files("{\"workspaces\":[\"apps/*\"]}", &[]);
        let found = workspaces(npm.path());
        assert_eq!(dirs(&found), ["apps/a", "apps/b"]);
        assert_eq!((found[0].kind, found[0].test.clone()), ("npm", ["npm", "test", "--workspace", "apps/a"].map(String::from).to_vec()));

        let object_form = files("{\"workspaces\":{\"packages\":[\"apps/a\"]}}", &[]);
        assert_eq!(dirs(&workspaces(object_form.path())), ["apps/a"]);

        let yarn = files("{\"workspaces\":[\"apps/*\"]}", &[("yarn.lock", "")]);
        let found = workspaces(yarn.path());
        assert_eq!((found[1].kind, found[1].test.clone()), ("yarn", ["yarn", "workspace", "b", "test"].map(String::from).to_vec()));
    }

    #[test]
    fn cargo_members_are_tested_by_package_name_and_exclusions_and_non_members_are_left_out() {
        let root = tree(&[
            ("Cargo.toml", "[workspace]\nmembers = [\"crates/*\", \"tools/xtask\"]\nexclude = [\"crates/scratch\"]\n"),
            ("crates/core/Cargo.toml", "[package]\nname = \"acme-core\"\nversion = \"0.1.0\"\n"),
            ("crates/cli/Cargo.toml", "[package]\nname = \"acme-cli\"\nversion = \"0.1.0\"\n"),
            ("crates/scratch/Cargo.toml", "[package]\nname = \"scratch\"\n"),
            ("crates/README.md", "no manifest here"),
            ("Cargo.lock", ""),
        ]);
        let scan = scan_workspaces(root.path());
        assert_eq!(dirs(&scan.workspaces), ["crates/cli", "crates/core"]);
        assert_eq!(scan.workspaces[1].test, ["cargo", "test", "-p", "acme-core"]);
        assert_eq!(scan.skipped, ["tools/xtask has no Cargo.toml, so it was left out"]);
    }

    #[test]
    fn go_modules_run_in_their_own_folder_and_uv_members_by_package_name() {
        let root = tree(&[
            ("go.work", "go 1.22\n\nuse (\n\t./svc/orders // the orders service\n\t./svc/users\n)\nuse ./lib\nuserdata ./nope\n"),
            ("svc/orders/go.mod", "module orders\n"),
            ("svc/users/go.mod", "module users\n"),
            ("lib/go.mod", "module lib\n"),
            ("pyproject.toml", "[tool.uv.workspace]\nmembers = [\"py/*\"]\n"),
            ("py/etl/pyproject.toml", "[project]\nname = \"acme-etl\"\n"),
        ]);
        let found = workspaces(root.path());
        let go: Vec<&Workspace> = found.iter().filter(|w| w.kind == "go").collect();
        assert_eq!(go.iter().map(|w| w.dir.as_str()).collect::<Vec<_>>(), ["lib", "svc/orders", "svc/users"]);
        assert!(go.iter().all(|w| w.runs_in_dir() && w.test == ["go", "test", "./..."]));
        let uv: Vec<&Workspace> = found.iter().filter(|w| w.kind == "uv").collect();
        assert_eq!(uv.len(), 1);
        assert_eq!((uv[0].dir.as_str(), uv[0].test.clone()), ("py/etl", ["uv", "run", "--package", "acme-etl", "pytest"].map(String::from).to_vec()));
        assert!(!uv[0].runs_in_dir());
    }

    #[test]
    fn patterns_that_cannot_be_expanded_or_leave_the_repository_are_skipped_with_a_note() {
        let root = tree(&[
            ("package.json", "{\"workspaces\":[\"packages/**\", \"../elsewhere\", \"/abs\", \"apps/{a,b}\", \"ok\"]}"),
            ("ok/package.json", &pkg("ok")),
            ("packages/x/package.json", &pkg("x")),
        ]);
        let scan = scan_workspaces(root.path());
        assert_eq!(dirs(&scan.workspaces), ["ok"]);
        assert_eq!(scan.skipped.len(), 4, "{:?}", scan.skipped);
        assert!(scan.skipped.iter().any(|n| n.contains("packages/**") && n.contains("did not expand")));
        assert!(scan.skipped.iter().filter(|n| n.contains("outside the repository")).count() == 2);
    }

    #[test]
    fn a_repository_without_workspaces_has_none() {
        let root = tree(&[("package.json", "{\"scripts\":{\"test\":\"x\"}}"), ("Cargo.toml", "[package]\nname = \"a\"\n"), ("go.mod", "module a\n")]);
        assert!(scan_workspaces(root.path()).workspaces.is_empty());
        assert!(scan_workspaces(root.path()).skipped.is_empty());
    }

    #[test]
    fn each_package_gets_a_check_scoped_to_its_folder_and_its_root_lockfile() {
        let root = tree(&[
            ("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n  - 'tools/api'\n"),
            ("pnpm-lock.yaml", ""),
            ("package-lock.json", ""),
            ("packages/api/package.json", &pkg("api")),
            ("tools/api/package.json", &pkg("tools-api")),
        ]);
        let checks = workspace_checks(root.path(), &workspaces(root.path()));
        assert_eq!(checks.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["test-api", "test-tools-api"], "two folders called api are kept apart");
        assert_eq!(checks[0].paths, ["packages/api/**", "pnpm-workspace.yaml", "pnpm-lock.yaml"], "its folder, the file that defines the workspace, and only the lockfile of its own tool");
        assert_eq!(checks[0].run, ["pnpm", "--filter", "./packages/api", "test"]);
        assert!(checks[0].dir.is_none() && checks[0].required);

        let go = tree(&[("go.work", "use ./svc\n"), ("svc/go.mod", "module svc\n")]);
        let checks = workspace_checks(go.path(), &workspaces(go.path()));
        assert_eq!((checks[0].dir.as_deref(), checks[0].paths.clone(), checks[0].env.clone()), (Some("svc"), vec!["svc/**".to_string(), "go.work".to_string()], vec!["HOME".to_string()]), "the workspace file counts; no go.work.sum here, so no lockfile path");
    }

    #[test]
    fn the_single_test_check_is_given_up_for_the_per_package_ones_only_when_there_are_some() {
        let check = |name: &str| CheckDef { name: name.into(), run: vec![name.into()], ..CheckDef::default() };
        let names = |v: Vec<CheckDef>| v.into_iter().map(|c| c.name).collect::<Vec<_>>();
        assert_eq!(names(with_workspace_checks(vec![check("test"), check("lint")], vec![check("test-a")], false)), ["lint", "test-a"]);
        assert_eq!(names(with_workspace_checks(vec![check("test"), check("lint")], vec![], false)), ["test", "lint"]);
        assert_eq!(names(with_workspace_checks(vec![check("test"), check("lint")], vec![check("test-a")], true)), ["test", "lint", "test-a"], "a root that is a package keeps its test");
    }

    #[test]
    fn the_workspace_manifests_count_for_every_package() {
        let root = tree(&[
            ("pnpm-workspace.yaml", "packages:\n  - 'p/*'\n"),
            ("package.json", "{\"private\":true}"),
            ("p/a/package.json", &pkg("a")),
        ]);
        let checks = workspace_checks(root.path(), &workspaces(root.path()));
        assert_eq!(checks[0].paths, ["p/a/**", "pnpm-workspace.yaml", "package.json"]);
        let cargo = tree(&[("Cargo.toml", "[workspace]\nmembers = [\"c/*\"]\n"), ("c/a/Cargo.toml", "[package]\nname = \"a\"\n"), ("Cargo.lock", "")]);
        assert_eq!(workspace_checks(cargo.path(), &workspaces(cargo.path()))[0].paths, ["c/a/**", "Cargo.toml", "Cargo.lock"]);
    }

    #[test]
    fn a_top_that_is_a_package_itself_is_noticed() {
        let go = tree(&[("go.work", "use (\n\t.\n\t./svc\n)\n"), ("go.mod", "module root\n"), ("svc/go.mod", "module svc\n")]);
        let scan = scan_workspaces(go.path());
        assert!(scan.root_is_package);
        assert_eq!(dirs(&scan.workspaces), ["svc"], "the top itself is not listed as a package");
        let cargo = tree(&[("Cargo.toml", "[package]\nname = \"root\"\n[workspace]\nmembers = [\"c/a\"]\n"), ("c/a/Cargo.toml", "[package]\nname = \"a\"\n")]);
        assert!(scan_workspaces(cargo.path()).root_is_package);
        let virtual_cargo = tree(&[("Cargo.toml", "[workspace]\nmembers = [\"c/a\"]\n"), ("c/a/Cargo.toml", "[package]\nname = \"a\"\n")]);
        assert!(!scan_workspaces(virtual_cargo.path()).root_is_package, "a virtual manifest has no package of its own");
        // A root with its own src and test script is a package; one that only runs the others is not.
        let own = tree(&[("package.json", "{\"workspaces\":[\"a\"],\"scripts\":{\"test\":\"x\"}}"), ("src/index.js", ""), ("a/package.json", &pkg("a"))]);
        assert!(scan_workspaces(own.path()).root_is_package);
        let aggregator = tree(&[("package.json", "{\"workspaces\":[\"a\"],\"scripts\":{\"test\":\"npm test -ws\"}}"), ("a/package.json", &pkg("a"))]);
        assert!(!scan_workspaces(aggregator.path()).root_is_package);
    }
}
