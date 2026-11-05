//! The guided setup (D82): plain questions about the team, the branches and the rules, answered
//! on the terminal or given as flags, written into `.05/policy.toml`. Used by `use05 init` and
//! `use05 policy --edit`.

use std::io::{BufRead, Write};
use std::path::Path;

use use05_core::policy::{CheckDef, Environment, IntentMode, LandMode, Policy, Require, Severity};
use use05_core::setup::{Role, Team, preset, scan, suggest_role};

use crate::policy_edit::Settings;
use crate::prompt::Asker;

/// Answers given as flags. Each one skips its question.
#[derive(Default, Clone)]
pub struct Flags {
    pub team: Option<Team>,
    pub target: Option<String>,
    pub envs: Vec<Environment>,
}

impl Flags {
    pub fn any(&self) -> bool {
        self.team.is_some() || self.target.is_some() || !self.envs.is_empty()
    }

    /// `--env dev=main`, or `--env dev-eu=eu-main:dev` for a name that is not a level.
    pub fn parse_env(text: &str) -> Result<Environment, String> {
        let usage = format!("--env takes NAME=BRANCH, or NAME=BRANCH:LEVEL for a name that is not a level: dev=main, prod=production, dev-eu=eu-main:dev (got {text:?})");
        let (name, rest) = text.split_once('=').ok_or_else(|| usage.clone())?;
        let (branch, level) = match rest.rsplit_once(':') {
            Some((b, l)) => (b, Some(l.trim().to_string())),
            None => (rest, None),
        };
        let (name, branch) = (name.trim(), branch.trim());
        if name.is_empty() || branch.is_empty() {
            return Err(usage);
        }
        match &level {
            Some(l) if Role::from_name(l).is_none() => Err(format!("{l:?} is not a level; use dev, uat, pre-prod or prod")),
            // A common name (staging, production) says its level, as 0.0.4 accepted.
            None if Role::from_name(name).is_none() => match suggest_role(name) {
                Some(r) => Ok(Environment::new(name, branch, Some(r.name()))),
                None => Err(format!("{name:?} is not a level, so give one: --env {name}={branch}:dev (or uat, pre-prod, prod)")),
            },
            _ => Ok(Environment::new(name, branch, level.filter(|l| l != name).as_deref())),
        }
    }
}

fn apply_team(s: &mut Settings, team: Team) {
    let p = preset(team);
    s.intent = p.intent;
    s.scope = p.scope;
    s.dependencies = p.dependencies;
    s.overlap = p.overlap;
    s.tests = p.tests;
    s.approvals_min = p.approvals_min;
    s.land = p.land;
}

/// The team's start for promoting into the last rung (D93): just you, an agent may promote there
/// too; a small team keeps it for people (the policy's default); a larger or regulated team also
/// asks a person's sign-off there. Only for environments new to the policy: one it already has
/// keeps its own settings.
fn team_promotion(envs: &mut [Environment], current: &[Environment], team: Team) {
    let rungs = use05_core::policy::ladder(envs);
    if rungs.len() < 2 {
        return;
    }
    let last: Vec<String> = rungs.last().map(|r| r.iter().map(|e| e.name.clone()).collect()).unwrap_or_default();
    for e in envs.iter_mut().filter(|e| last.contains(&e.name) && !current.iter().any(|c| c.name == e.name)) {
        match team {
            Team::Solo => e.agent = Some(true),
            Team::Small => {}
            Team::Regulated => e.rules.sign_off = use05_core::policy::Severity::Approval,
        }
    }
}

/// The answers given as flags, with no questions.
pub fn from_flags(current: &Policy, flags: &Flags) -> Settings {
    let mut s = Settings::from_policy(current);
    if let Some(team) = flags.team {
        apply_team(&mut s, team);
    }
    if let Some(t) = &flags.target {
        s.target = Some(t.clone());
    }
    if !flags.envs.is_empty() {
        s.environments = flags.envs.clone();
        keep_promotion(&mut s.environments, &current.environment);
    }
    if let Some(team) = flags.team {
        team_promotion(&mut s.environments, &current.environment, team);
    }
    s
}

/// The steps of the setup, for the `n/7` headings.
const STEPS: usize = 7;

/// Fresh base: what happens when an agent starts from older code than origin has.
const FRESH_OPTIONS: [(&str, Severity); 4] = [
    ("do not check", Severity::Allow),
    ("tell the agent, and note it in the brief", Severity::Warn),
    ("hold the change until a person approves", Severity::Approval),
    ("refuse the change", Severity::Deny),
];

/// The one `[[require]]` rule the setup asks about: these folders change with any change.
fn docs_rule(s: &Settings) -> Option<&Require> {
    s.require.iter().find(|r| r.when == ["**"])
}

/// How a strictness reads in notes.
const SEVERITY: [(&str, Severity); 4] = [("let it", Severity::Allow), ("note it in the brief", Severity::Warn), ("a person approves", Severity::Approval), ("refuse", Severity::Deny)];

/// Outside the plan, each strictness also changes what the agent's hook does at the edit.
const SCOPE_OPTIONS: [(&str, Severity); 4] = [
    ("let it", Severity::Allow),
    ("let it, but ask me before each edit outside the plan", Severity::Warn),
    ("stop the agent; a person approves a wider plan", Severity::Approval),
    ("stop the agent and refuse the change", Severity::Deny),
];

/// Weakened tests are found in the finished change, so no hook is involved.
const TESTS_OPTIONS: [(&str, Severity); 4] = [
    ("let it", Severity::Allow),
    ("let it, and note it in the brief", Severity::Warn),
    ("hold the change until a person approves", Severity::Approval),
    ("refuse the change", Severity::Deny),
];

fn severity_choice<R: BufRead, W: Write>(a: &mut Asker<R, W>, question: &str, options: &[(&str, Severity)], current: Severity) -> Option<Severity> {
    let labels: Vec<&str> = options.iter().map(|(l, _)| *l).collect();
    let default = options.iter().position(|(_, s)| *s == current).unwrap_or(0);
    a.choice(question, &labels, default).map(|i| options[i].1)
}

/// `lint: npm run lint` into a check. A command with shell syntax runs through `sh -c`.
fn parse_check(text: &str) -> Option<CheckDef> {
    let (name, command) = text.split_once(':')?;
    let (name, command) = (name.trim(), command.trim());
    if name.is_empty() || command.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    let shell = command.chars().any(|c| "|&;<>()$`\\\"'*?~=".contains(c));
    let run = if shell { vec!["sh".to_string(), "-c".to_string(), command.to_string()] } else { command.split_whitespace().map(str::to_string).collect() };
    Some(CheckDef { name: name.to_string(), run, ..CheckDef::default() })
}

/// A check in words: `name (command)`, and when it is required if that is not always.
fn describe_check(c: &CheckDef) -> String {
    let when = if c.paths.is_empty() { String::new() } else { format!(", when {} change", c.paths.join(" or ")) };
    format!("{} ({}{when})", c.name, c.run.join(" "))
}

/// Folders in the repository that look like database migrations: a suggestion for append-only.
fn migration_dirs(top: &Path) -> Vec<String> {
    let files = use05_core::git::text(top, &["ls-files"]).unwrap_or_default();
    let mut dirs: Vec<String> = files
        .lines()
        .filter_map(|f| {
            let parts: Vec<&str> = f.split('/').collect();
            let at = parts.iter().enumerate().position(|(i, p)| *p == "migrations" || (*p == "migrate" && i > 0 && parts[i - 1] == "db"))?;
            (at + 1 < parts.len()).then(|| format!("{}/**", parts[..=at].join("/")))
        })
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
}

/// An environment chosen again keeps the promotion settings it had (D93): setup asks only for its
/// name, branch and level. It is found by name, else by branch.
fn keep_promotion(chosen: &mut [Environment], current: &[Environment]) {
    for e in chosen.iter_mut() {
        if let Some(old) = current.iter().find(|o| o.name == e.name).or_else(|| current.iter().find(|o| o.branch == e.branch)) {
            *e = Environment { name: e.name.clone(), branch: e.branch.clone(), level: e.level.clone(), ..old.clone() };
        }
    }
}

/// A name for a new environment that no chosen one has: `wanted`, or with `-2`, `-3` added.
fn unique_name(wanted: &str, chosen: &[Environment]) -> String {
    let mut name = wanted.to_string();
    let mut n = 2;
    while chosen.iter().any(|e| e.name == name) {
        name = format!("{wanted}-{n}");
        n += 1;
    }
    name
}

/// An environment for `branch` at `level`: named after the level when that is free, otherwise
/// named by the person (a second dev environment, say).
fn at_level<R: BufRead, W: Write>(a: &mut Asker<R, W>, chosen: &[Environment], branch: &str, level: &str) -> Option<Environment> {
    if !chosen.iter().any(|e| e.name == level) {
        return Some(Environment::new(level, branch, None));
    }
    let suggestion = unique_name(&format!("{level}-{}", branch.replace('/', "-")), chosen);
    let name = a.text(&format!("There is already a {level} environment. What should this one, on {branch}, be called?"), &suggestion)?;
    Some(Environment::new(&unique_name(&name, chosen), branch, Some(level)))
}

/// An environment the person names, then places on a level.
fn named_env<R: BufRead, W: Write>(a: &mut Asker<R, W>, chosen: &[Environment], branch: &str) -> Option<Environment> {
    let name = a.text(&format!("What is the environment on {branch} called?"), &unique_name(&branch.replace('/', "-"), chosen))?;
    let name = unique_name(&name, chosen);
    let levels: Vec<&str> = Role::ALL.iter().map(|r| r.name()).collect();
    let default = Role::from_name(&name).or_else(|| suggest_role(branch)).map_or(0, |r| r as usize);
    let level = levels[a.choice(&format!("Which level is {name} on?"), &levels, default)?];
    Some(Environment::new(&name, branch, (name != level).then_some(level)))
}

/// The branch exists here or on `origin`.
fn branch_exists(top: &Path, name: &str) -> bool {
    use05_core::git::resolve_commit(top, &format!("refs/heads/{name}")).is_some() || use05_core::git::resolve_commit(top, &format!("refs/remotes/origin/{name}")).is_some()
}

/// The landing branch, questioned when no such branch exists (a typo, most likely). A repository
/// with no commits yet has no branches to check against.
fn ask_landing<R: BufRead, W: Write>(a: &mut Asker<R, W>, top: &Path, default: &str) -> Option<String> {
    let has_commits = use05_core::git::head_commit(top).is_some();
    for _ in 0..3 {
        let answer = a.text("Which branch do finished changes land on?", default)?;
        if !has_commits || branch_exists(top, &answer) {
            return Some(answer);
        }
        a.say(&format!("  There is no branch {answer} here or on origin."));
        if a.yes("Use it anyway?", false)? {
            return Some(answer);
        }
    }
    Some(default.to_string())
}

/// The landing branch to suggest, and whether it is the remote's default (followed, so not
/// written down): the policy's, else the remote's default, else the current branch.
fn landing_default(top: &Path, current: &Policy) -> (String, bool) {
    if let Some(t) = &current.branches.target {
        return (t.clone(), false);
    }
    let remote = use05_core::git::text(top, &["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"]).ok().and_then(|r| r.strip_prefix("origin/").map(str::to_string)).filter(|b| !b.is_empty());
    match remote {
        Some(r) => (r, true),
        None => (use05_core::git::current_branch(top).unwrap_or_else(|| "main".to_string()), false),
    }
}

/// The words a question used for an answer.
fn option(options: &[(&str, Severity)], v: Severity) -> String {
    options.iter().find(|(_, x)| *x == v).map(|(l, _)| l.to_string()).unwrap_or_default()
}

fn summary(s: &Settings) -> Vec<(&'static str, String)> {
    let sev = |v: Severity| SEVERITY.iter().find(|(_, x)| *x == v).map(|(l, _)| *l).unwrap_or("note it in the brief").to_string();
    let list = |l: &[String]| if l.is_empty() { "none".to_string() } else { l.join(", ") };
    let plan = match s.intent {
        IntentMode::Inferred => "inferred from the work",
        IntentMode::Risky => "written down for risky changes",
        IntentMode::Always => "written down for every change",
    };
    let envs = if s.environments.is_empty() {
        "none".to_string()
    } else {
        s.environments.iter().map(|e| match &e.level {
            Some(l) => format!("{} = {} ({l})", e.name, e.branch),
            None => format!("{} = {}", e.name, e.branch),
        }).collect::<Vec<_>>().join(", ")
    };
    vec![
        ("Changes land on", s.target.clone().unwrap_or_else(|| "the remote's default branch".into())),
        ("Environments", envs),
        ("Checks", if s.checks.is_empty() { "none".into() } else { s.checks.iter().map(describe_check).collect::<Vec<_>>().join(", ") }),
        ("A plan is", plan.into()),
        ("Need approval", list(&s.protect_paths)),
        ("Locked", list(&s.locked)),
        ("New files only", list(&s.append_only)),
        ("Agents may not read", list(&s.no_read)),
        ("Outside the plan", option(&SCOPE_OPTIONS, s.scope)),
        ("Weakened tests", option(&TESTS_OPTIONS, s.tests)),
        ("Starts behind origin", option(&FRESH_OPTIONS, s.fresh_base)),
        ("Must change too", {
            let rules: Vec<String> = s.require.iter().map(|r| if r.when == ["**"] { format!("{} with every change", r.also.join(" or ")) } else { r.describe() }).collect();
            list(&rules)
        }),
        ("Dependency changes", sev(s.dependencies)),
        ("Two agents, one file", sev(s.overlap)),
        ("Approvals needed", s.approvals_min.to_string()),
        ("Finished changes", if s.land == LandMode::Auto { "land automatically when 05 allows it".into() } else { "land when you run use05 land".into() }),
        ("Then", if s.push == LandMode::Auto { "05 pushes them to origin".into() } else { "you push them".into() }),
    ]
}

/// Ask every question. `current` is the policy as it is (the template, for a new repository);
/// its values are the defaults. `None` when the input ended or the person chose not to write.
pub fn ask<R: BufRead, W: Write>(a: &mut Asker<R, W>, top: &Path, current: &Policy, editing: bool, flags: &Flags) -> Option<Settings> {
    let mut s = Settings::from_policy(current);
    if editing {
        a.banner("Change your 05 settings", "Your current settings are the defaults: press Enter to keep each one. Nothing is written until you say so.");
    } else {
        a.banner("Set up 05 for this repository", "Each question has a default: press Enter to take it. Nothing is written until you say so.");
    }

    // 1. The team, and so how strict to start.
    a.step(1, STEPS, "Who works here");
    let mut team_chosen = flags.team;
    match flags.team {
        Some(team) => apply_team(&mut s, team),
        None => {
            let mut options = vec!["Just me", "A small team (2 to 10 people)", "A larger or regulated team"];
            if editing {
                options.insert(0, "Keep my current rules");
            }
            let pick = a.choice("Who works in this repository?", &options, 0)?;
            let team = [Team::Solo, Team::Small, Team::Regulated];
            let chosen = if editing { pick.checked_sub(1).map(|i| team[i]) } else { Some(team[pick]) };
            if let Some(t) = chosen {
                apply_team(&mut s, t);
            }
            team_chosen = chosen;
        }
    }

    // 2. Where finished changes land.
    a.step(2, STEPS, "Where changes land");
    match &flags.target {
        Some(t) => s.target = Some(t.clone()),
        None => {
            let (default, follows_remote) = landing_default(top, current);
            let answer = ask_landing(a, top, &default)?;
            // Accepting a default the policy does not state keeps it unstated: it goes on
            // following the remote, and an edit changes nothing.
            if !(answer == default && current.branches.target.is_none() && (follows_remote || editing)) {
                s.target = Some(answer);
            }
        }
    }

    // 3. Which branch is which environment.
    a.step(3, STEPS, "Environments");
    if !flags.envs.is_empty() {
        s.environments = flags.envs.clone();
        keep_promotion(&mut s.environments, &current.environment);
        a.say("Set with --env.");
    } else {
        // Ask about branches that look long-lived: a name that suggests a level, a branch the
        // policy keeps by name, the landing branch, and the environments already set. Any other
        // branch can be added afterwards.
        let landing = s.target.clone().unwrap_or_else(|| use05_core::branches::target_for(current, None, top));
        let kept_by_name = |b: &str| current.branches.keep.iter().any(|k| k == b);
        let (scanned, others): (Vec<String>, Vec<String>) = scan(top, current)
            .into_iter()
            .map(|b| b.name)
            .partition(|b| suggest_role(b).is_some() || kept_by_name(b) || *b == landing || current.environment.iter().any(|e| &e.branch == b));
        // The environments already set come first, in the order the policy lists them.
        let mut branches: Vec<String> = current.environment.iter().map(|e| e.branch.clone()).collect();
        branches.extend(scanned.into_iter().filter(|b| !current.environment.iter().any(|e| &e.branch == b)));
        a.say("Which branch is dev, uat, pre-prod and prod. A level can hold several environments, such as two dev environments on their own branches. 05 shows them, and judges a promotion from one to the next under the rules in .05/policy.toml; an environment chosen again keeps its rules.");
        if !others.is_empty() {
            a.say(&match others.len() {
                1 => "1 other branch is not asked about; you can add it at the end.".to_string(),
                n => format!("{n} other branches (feature branches and the like) are not asked about; you can add any of them at the end."),
            });
        }
        let mut chosen: Vec<Environment> = Vec::new();
        for b in &branches {
            let existing = current.environment.iter().find(|e| &e.branch == b);
            let custom = existing.filter(|e| Role::from_name(&e.name).is_none() || e.level.is_some());
            let mut labels: Vec<String> = Role::ALL.iter().map(|r| r.name().to_string()).collect();
            let keep_at = custom.map(|e| {
                labels.push(format!("keep it as {} ({})", e.name, e.level().unwrap_or("no level")));
                labels.len() - 1
            });
            labels.push("another environment, named by you".to_string());
            let named = labels.len() - 1;
            labels.push("not an environment".to_string());
            let none = labels.len() - 1;
            let holder = |level: &str, chosen: &[Environment]| chosen.iter().find(|e| e.level() == Some(level)).map(|e| e.branch.clone());
            let default = match existing {
                Some(_) if keep_at.is_some() => keep_at.unwrap_or(none),
                Some(e) => e.level().and_then(Role::from_name).map_or(none, |r| r as usize),
                None if editing => none,
                None => match suggest_role(b) {
                    Some(r) => match holder(r.name(), &chosen) {
                        Some(h) => {
                            a.say(&format!("{} is already {h}. Choose {} again to add a second {} environment.", r.name(), r.name(), r.name()));
                            none
                        }
                        None => r as usize,
                    },
                    None => none,
                },
            };
            let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
            let pick = a.choice(&format!("Which environment is the branch {b}?"), &refs, default)?;
            // Names already given, and the names of environments not asked about yet.
            let taken: Vec<Environment> = chosen.iter().cloned().chain(current.environment.iter().filter(|e| &e.branch != b && !chosen.iter().any(|c| c.branch == e.branch)).cloned()).collect();
            let env = if let Some(role) = Role::ALL.get(pick) {
                Some(at_level(a, &taken, b, role.name())?)
            } else if Some(pick) == keep_at {
                custom.cloned()
            } else if pick == named {
                Some(named_env(a, &taken, b)?)
            } else {
                None
            };
            chosen.extend(env);
        }
        // Any other branch, by name.
        loop {
            let b = a.text("Add another branch as an environment: type its name, or press Enter to go on.", "")?;
            if b.is_empty() {
                break;
            }
            if chosen.iter().any(|e| e.branch == b) {
                a.say(&format!("  {b} is already an environment."));
                continue;
            }
            if !branch_exists(top, &b) {
                a.say(&format!("  There is no branch {b} here or on origin."));
                continue;
            }
            let env = named_env(a, &chosen, &b)?;
            chosen.push(env);
        }
        keep_promotion(&mut chosen, &current.environment);
        // The same environments as before keep the policy's order; otherwise new ones take their
        // place on the ladder, after those already on their level.
        if chosen.len() == current.environment.len() && chosen.iter().all(|e| current.environment.contains(e)) {
            s.environments = current.environment.clone();
        } else {
            let keys = use05_core::policy::ladder_keys(&chosen);
            let mut order: Vec<usize> = (0..chosen.len()).collect();
            order.sort_by_key(|&i| keys[i]);
            s.environments = order.into_iter().map(|i| chosen[i].clone()).collect();
        }
    }
    if let Some(team) = team_chosen {
        team_promotion(&mut s.environments, &current.environment, team);
    }

    // 4. Checks.
    a.step(4, STEPS, "Checks");
    // A monorepo: one check per package, each required only when a change touches it (D97).
    let mut approved_packages = false;
    if !editing {
        let scan = use05_core::setup::scan_workspaces(top);
        let per_package = use05_core::setup::workspace_checks(top, &scan.workspaces);
        for note in &scan.skipped {
            a.say(&format!("  {note}."));
        }
        if !per_package.is_empty() {
            a.say(&use05_core::setup::workspace_note(&scan.workspaces, scan.root_is_package));
            for c in &per_package {
                a.say(&format!("  {}", describe_check(c)));
            }
            if a.yes("Use these checks?", true)? {
                s.checks = use05_core::setup::with_workspace_checks(std::mem::take(&mut s.checks), per_package, scan.root_is_package);
                approved_packages = true;
                a.say(use05_core::setup::workspace_caveat());
            }
        }
    }
    if !s.checks.is_empty() && !approved_packages {
        let names: Vec<String> = s.checks.iter().map(describe_check).collect();
        let when = if s.checks.iter().any(|c| !c.paths.is_empty()) { "the changes they apply to" } else { "every change" };
        if !a.yes(&format!("These checks run on {when}: {}. Keep them?", names.join(", ")), true)? {
            s.checks.clear();
        }
    }
    loop {
        let added = a.text("Add a check as name: command (for example lint: npm run lint), or press Enter to go on.", "")?;
        if added.is_empty() {
            break;
        }
        match parse_check(&added) {
            Some(c) if !s.checks.iter().any(|o| o.name == c.name) => s.checks.push(c),
            Some(c) => a.say(&format!("  There is already a check called {}.", c.name)),
            None => a.say("  Write it as name: command, with no spaces in the name."),
        }
    }

    // 5. Folder and file rules.
    a.step(5, STEPS, "Folder and file rules");
    s.protect_paths = a.list("Folders or files that need a person's approval before they change (for example infra/**).", &s.protect_paths)?;
    s.locked = a.list("Folders or files that must never change (locked).", &s.locked)?;
    let append_default = if s.append_only.is_empty() && !editing { migration_dirs(top) } else { s.append_only.clone() };
    s.append_only = a.list("Folders where only new files may be added, like database migrations (append-only).", &append_default)?;
    let has_env = std::fs::read_dir(top).map(|d| d.filter_map(|e| e.ok()).any(|e| e.file_name().to_string_lossy().starts_with(".env"))).unwrap_or(false);
    let read_default = if s.no_read.is_empty() && !editing && has_env { vec![".env*".to_string()] } else { s.no_read.clone() };
    s.no_read = a.list("Files agents may not read, like secrets.", &read_default)?;
    let docs_default: Vec<String> = docs_rule(&s).map(|r| r.also.clone()).unwrap_or_default();
    let docs = a.list("Folders that must be updated with every change, like docs/** or CHANGELOG.md (05 checks that they changed, not what they say).", &docs_default)?;
    if docs != docs_default {
        s.require.retain(|r| r.when != ["**"]);
        if !docs.is_empty() {
            s.require.push(Require { when: vec!["**".into()], also: docs, severity: Severity::Approval, why: None });
        }
    }

    // 6. How strict.
    a.step(6, STEPS, "How strict, and how changes land");
    s.scope = severity_choice(a, "When an agent changes files outside its plan:", &SCOPE_OPTIONS, s.scope)?;
    s.tests = severity_choice(a, "When a change weakens or removes tests:", &TESTS_OPTIONS, s.tests)?;
    s.fresh_base = severity_choice(a, "When an agent starts from older code than origin has (05 fetches origin when a session starts):", &FRESH_OPTIONS, s.fresh_base)?;
    let land = a.choice("How should a finished change land?", &["I run use05 land", "Automatically, when 05 allows it"], usize::from(s.land == LandMode::Auto))?;
    s.land = if land == 1 { LandMode::Auto } else { LandMode::Manual };
    let push = a.choice("Once a change has landed, who pushes it?", &["I do (git push, or yes when 05 asks)", "05 pushes it to origin"], usize::from(s.push == LandMode::Auto))?;
    s.push = if push == 1 { LandMode::Auto } else { LandMode::Manual };

    // 7. Confirm.
    a.step(7, STEPS, "Review");
    let rows = summary(&s);
    let rows: Vec<(&str, String)> = rows.iter().map(|(k, v)| (*k, v.clone())).collect();
    a.table(&rows);
    let write = a.confirm("Write this to .05/policy.toml?")?;
    a.say("");
    write.then_some(s)
}

/// What a run of the setup came to.
pub enum Outcome {
    /// The policy text with the answers in it.
    Written(String),
    /// The answers match the policy as it is.
    Unchanged,
    /// The input ended, or the person chose not to write: nothing changes.
    Stopped,
    /// Nobody answered within the limit (D98): nothing changes.
    NoAnswer,
}

/// Run the setup on a policy `text`: ask on the terminal (questions on stderr, so `--json` on
/// stdout stays clean) when `interactive`, else take the flags. The result is checked to parse.
/// The notes name each answer an organisation's stricter rule overrides.
pub fn run_on(text: &str, top: &Path, editing: bool, interactive: bool, flags: &Flags) -> Result<(Outcome, Vec<String>), String> {
    let current = Policy::parse(text).map_err(|e| e.message)?;
    let settings = if interactive {
        let mut a = crate::prompt::on_stdin(crate::ui::Ui::stderr());
        match ask(&mut a, top, &current, editing, flags) {
            Some(s) => s,
            None if a.timed_out() => return Ok((Outcome::NoAnswer, Vec::new())),
            None => return Ok((Outcome::Stopped, Vec::new())),
        }
    } else {
        from_flags(&current, flags)
    };
    let out = crate::policy_edit::apply(text, &settings)?;
    let notes = org_overrides(&out);
    Ok((if out == text { Outcome::Unchanged } else { Outcome::Written(out) }, notes))
}

/// Where this machine's organisation layer is stricter than the policy text, in plain words.
fn org_overrides(text: &str) -> Vec<String> {
    let Ok(Some((org, floor))) = use05_core::org::load() else { return Vec::new() };
    let Ok(mine) = Policy::parse(text) else { return Vec::new() };
    let mut effective = mine.clone();
    effective.tighten(&floor);
    let sev = |v: Severity| SEVERITY.iter().find(|(_, x)| *x == v).map(|(l, _)| *l).unwrap_or("warn the agent");
    let mut notes = Vec::new();
    for (what, yours, theirs) in [
        ("when an agent changes files outside its plan", mine.drift.scope, effective.drift.scope),
        ("when a change weakens or removes tests", mine.drift.tests, effective.drift.tests),
        ("when dependency files change", mine.drift.dependencies, effective.drift.dependencies),
        ("when two agents change the same files", mine.drift.overlap, effective.drift.overlap),
    ] {
        if yours != theirs {
            notes.push(format!("Your organisation ({org}) requires {:?} {what}; that applies instead of {:?}.", sev(theirs), sev(yours)));
        }
    }
    if mine.branches.fresh_base != effective.branches.fresh_base {
        notes.push(format!("Your organisation ({org}) requires {:?} when an agent starts behind origin; that applies instead of {:?}.", sev(effective.branches.fresh_base), sev(mine.branches.fresh_base)));
    }
    if mine.require.len() != effective.require.len() {
        notes.push(format!("Your organisation ({org}) adds files that must change together: {}.", effective.require.iter().filter(|r| !mine.require.contains(r)).map(use05_core::policy::Require::describe).collect::<Vec<_>>().join("; ")));
    }
    if mine.approvals.min != effective.approvals.min {
        notes.push(format!("Your organisation ({org}) requires {} approvals; that applies instead of {}.", effective.approvals.min, mine.approvals.min));
    }
    if mine.intent.mode != effective.intent.mode {
        notes.push(format!("Your organisation ({org}) requires a written plan {}; that applies instead of your answer.", if effective.intent.mode == IntentMode::Always { "for every change" } else { "for risky changes" }));
    }
    notes
}

/// What to do after the policy file changed in a repository whose policy is already committed.
pub const AFTER_EDIT: &str = "05 reads the rules from each change's base, so the new settings apply once this change lands. The policy is a protected file: commit it (git add .05/policy.toml && git commit), approve it with use05 approve --outcome, then use05 land or push.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_team_decides_who_may_promote_into_the_last_rung() {
        let ladder = || vec![Environment::new("dev", "main", None), Environment::new("uat", "uat", None), Environment::new("prod", "production", None)];
        let promoting = |team: Team, current: &[Environment]| {
            let mut envs = ladder();
            team_promotion(&mut envs, current, team);
            envs.iter().map(|e| (e.name.clone(), e.agent, e.rules.sign_off)).collect::<Vec<_>>()
        };
        use use05_core::policy::Severity;
        // Just you: an agent may promote into prod too.
        assert_eq!(promoting(Team::Solo, &[])[2], ("prod".into(), Some(true), Severity::Allow));
        // A small team keeps the policy's default: prod for people, nothing to set.
        assert_eq!(promoting(Team::Small, &[]), ladder().iter().map(|e| (e.name.clone(), e.agent, e.rules.sign_off)).collect::<Vec<_>>());
        // A larger or regulated team also asks a person's sign-off into prod.
        assert_eq!(promoting(Team::Regulated, &[])[2], ("prod".into(), None, Severity::Approval));
        // Only the last rung, and never an environment the policy already has.
        assert_eq!(promoting(Team::Solo, &[])[1].1, None);
        assert_eq!(promoting(Team::Solo, &[Environment::new("prod", "production", None)])[2].1, None, "prod is already set up: kept as it is");
        // One environment is the landing branch alone: nothing is promoted into it.
        let mut one = vec![Environment::new("dev", "main", None)];
        team_promotion(&mut one, &[], Team::Solo);
        assert_eq!(one[0].agent, None);
    }

    #[test]
    fn a_check_with_shell_syntax_runs_through_sh() {
        assert_eq!(parse_check("test: FOO=1 npm test").unwrap().run, ["sh", "-c", "FOO=1 npm test"]);
        assert_eq!(parse_check("lint: npm run lint").unwrap().run, ["npm", "run", "lint"]);
        assert!(parse_check("no colon here").is_none() && parse_check("two words: x").is_none());
    }

    #[test]
    fn an_environment_chosen_again_keeps_its_promotion_settings_by_name_or_branch() {
        let mut old = Environment::new("prod", "production", None);
        old.agent = Some(false);
        old.soak_minutes = Some(30);
        let current = vec![Environment::new("uat", "uat", None), old];
        let mut chosen = vec![Environment::new("prod", "production", None), Environment::new("live", "production", Some("prod")), Environment::new("qa", "qa", Some("uat"))];
        keep_promotion(&mut chosen, &current);
        assert_eq!((chosen[0].agent, chosen[0].soak_minutes), (Some(false), Some(30)), "same name");
        assert_eq!((chosen[1].name.as_str(), chosen[1].level.as_deref(), chosen[1].soak_minutes), ("live", Some("prod"), Some(30)), "renamed on the same branch: its new name and level, its old rules");
        assert_eq!(chosen[2], Environment::new("qa", "qa", Some("uat")), "a new one has none");
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;

    #[test]
    fn rails_migrations_are_suggested_too() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path();
        let git = |args: &[&str]| assert!(std::process::Command::new("git").arg("-C").arg(top).args(["-c", "user.name=t", "-c", "user.email=t@t"]).args(args).output().unwrap().status.success());
        git(&["init", "-q"]);
        std::fs::create_dir_all(top.join("db/migrate")).unwrap();
        std::fs::create_dir_all(top.join("api/migrations")).unwrap();
        std::fs::write(top.join("db/migrate/001_init.rb"), "x").unwrap();
        std::fs::write(top.join("api/migrations/0001.sql"), "x").unwrap();
        git(&["add", "-A"]);
        assert_eq!(migration_dirs(top), ["api/migrations/**", "db/migrate/**"]);
    }

    #[test]
    fn strictness_options_say_what_happens_for_each_question() {
        let scope: Vec<&str> = SCOPE_OPTIONS.iter().map(|(l, _)| *l).collect();
        assert!(scope.iter().any(|l| l.contains("ask me")) && scope.iter().any(|l| l.contains("stop the agent")), "{scope:?}");
        let tests: Vec<&str> = TESTS_OPTIONS.iter().map(|(l, _)| *l).collect();
        assert!(!tests.iter().any(|l| l.contains("agent")), "no hook is involved for tests: {tests:?}");
    }

    #[test]
    fn a_landing_branch_that_does_not_exist_is_questioned() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path();
        let git = |args: &[&str]| assert!(std::process::Command::new("git").arg("-C").arg(top).args(["-c", "user.name=t", "-c", "user.email=t@t"]).args(args).output().unwrap().status.success());
        git(&["init", "-q", "-b", "main"]);
        git(&["commit", "-q", "--allow-empty", "-m", "first"]);
        // A typo, then "no, ask again", then the real branch.
        let mut a = Asker::new(std::io::Cursor::new(b"mian\nn\nmain\n".to_vec()), Vec::new());
        assert_eq!(ask_landing(&mut a, top, "main").as_deref(), Some("main"));
        let shown = String::from_utf8(a.output().clone()).unwrap();
        assert!(shown.contains("There is no branch mian"), "{shown}");
    }
}
