//! The guided setup (D82): plain questions about the team, the branches and the rules, answered
//! on the terminal or given as flags, written into `.05/policy.toml`. Used by `use05 init` and
//! `use05 policy --edit`.

use std::io::{BufRead, Write};
use std::path::Path;

use use05_core::policy::{CheckDef, Environment, IntentMode, LandMode, Policy, Severity};
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

    /// `--env dev=main` into an environment.
    pub fn parse_env(text: &str) -> Result<Environment, String> {
        match text.split_once('=') {
            Some((name, branch)) if !name.trim().is_empty() && !branch.trim().is_empty() => Ok(Environment { name: name.trim().to_string(), branch: branch.trim().to_string() }),
            _ => Err(format!("--env takes NAME=BRANCH, e.g. dev=main or prod=production (got {text:?})")),
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
    }
    s
}

const SEVERITY: [(&str, Severity); 4] = [("let it", Severity::Allow), ("warn the agent", Severity::Warn), ("ask a person", Severity::Approval), ("refuse", Severity::Deny)];

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

/// Folders in the repository that look like database migrations: a suggestion for append-only.
fn migration_dirs(top: &Path) -> Vec<String> {
    let files = use05_core::git::text(top, &["ls-files"]).unwrap_or_default();
    let mut dirs: Vec<String> = files
        .lines()
        .filter_map(|f| {
            let parts: Vec<&str> = f.split('/').collect();
            let at = parts.iter().position(|p| *p == "migrations")?;
            (at + 1 < parts.len()).then(|| format!("{}/**", parts[..=at].join("/")))
        })
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
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

fn summary(s: &Settings) -> Vec<String> {
    let sev = |v: Severity| SEVERITY.iter().find(|(_, x)| *x == v).map(|(l, _)| *l).unwrap_or("warn the agent");
    let list = |l: &[String]| if l.is_empty() { "none".to_string() } else { l.join(", ") };
    let plan = match s.intent {
        IntentMode::Inferred => "inferred from the work",
        IntentMode::Risky => "written down for risky changes",
        IntentMode::Always => "written down for every change",
    };
    vec![
        format!("Changes land on:          {}", s.target.as_deref().unwrap_or("the remote's default branch")),
        format!(
            "Environments:             {}",
            if s.environments.is_empty() { "none".to_string() } else { s.environments.iter().map(|e| format!("{} = {}", e.name, e.branch)).collect::<Vec<_>>().join(", ") }
        ),
        format!("Checks:                   {}", if s.checks.is_empty() { "none".to_string() } else { s.checks.iter().map(|c| format!("{} ({})", c.name, c.run.join(" "))).collect::<Vec<_>>().join(", ") }),
        format!("A plan is:                {plan}"),
        format!("Need approval:            {}", list(&s.protect_paths)),
        format!("Locked:                   {}", list(&s.locked)),
        format!("Add new files only:       {}", list(&s.append_only)),
        format!("Agents may not read:      {}", list(&s.no_read)),
        format!("Outside the plan:         {}", sev(s.scope)),
        format!("Weakened tests:           {}", sev(s.tests)),
        format!("Dependency changes:       {}", sev(s.dependencies)),
        format!("Two agents, same files:   {}", sev(s.overlap)),
        format!("Approvals needed:         {}", s.approvals_min),
        format!("Finished changes land:    {}", if s.land == LandMode::Auto { "automatically when 05 allows it" } else { "when you run use05 land" }),
    ]
}

/// Ask every question. `current` is the policy as it is (the template, for a new repository);
/// its values are the defaults. `None` when the input ended or the person chose not to write.
pub fn ask<R: BufRead, W: Write>(a: &mut Asker<R, W>, top: &Path, current: &Policy, editing: bool, flags: &Flags) -> Option<Settings> {
    let mut s = Settings::from_policy(current);
    a.say(if editing { "Let's go through your 05 settings. Press Enter to keep what is shown." } else { "Let's set up 05 for this repository. Press Enter to take what is shown." });

    // 1. The team, and so how strict to start.
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
        }
    }

    // 2. Where finished changes land.
    match &flags.target {
        Some(t) => s.target = Some(t.clone()),
        None => {
            let (default, follows_remote) = landing_default(top, current);
            let answer = a.text("Which branch do finished changes land on?", &default)?;
            // Accepting a default the policy does not state keeps it unstated: it goes on
            // following the remote, and an edit changes nothing.
            if !(answer == default && current.branches.target.is_none() && (follows_remote || editing)) {
                s.target = Some(answer);
            }
        }
    }

    // 3. Which branch is which environment.
    if !flags.envs.is_empty() {
        s.environments = flags.envs.clone();
    } else {
        // Ask about branches that look long-lived: a name that suggests a role, a branch the
        // policy keeps by name, the landing branch, and the environments already set. Feature
        // branches and the like are counted, not asked about.
        let landing = s.target.clone().unwrap_or_else(|| use05_core::branches::target_for(current, None, top));
        let kept_by_name = |b: &str| current.branches.keep.iter().any(|k| k == b);
        let (mut branches, others): (Vec<String>, Vec<String>) = scan(top, current)
            .into_iter()
            .map(|b| b.name)
            .partition(|b| suggest_role(b).is_some() || kept_by_name(b) || *b == landing || current.environment.iter().any(|e| &e.branch == b));
        for e in &current.environment {
            if !branches.contains(&e.branch) {
                branches.push(e.branch.clone());
            }
        }
        if branches.is_empty() {
            a.say("\nNo long-lived branches yet, so no environments to set. Run this again once you have them.");
        } else {
            a.say("\nEnvironments: which branch is dev, uat, pre-prod and prod. 05 records them and shows them; rules for promoting between them come later.");
            if !others.is_empty() {
                a.say(&format!("{} other branches (feature branches and the like) are left out.", others.len()));
            }
            // Each environment's rank on the ladder: a standard role's place, and for a name the
            // person wrote by hand, just above the standard one listed before it.
            let rank_of = |name: &str| -> i32 {
                if let Some(r) = Role::from_name(name) {
                    return 2 * r as i32;
                }
                let before = current.environment.iter().take_while(|e| e.name != name).filter_map(|e| Role::from_name(&e.name)).last();
                before.map_or(-1, |r| 2 * r as i32 + 1)
            };
            let mut chosen: Vec<(i32, Environment)> = Vec::new();
            for b in &branches {
                let existing = current.environment.iter().find(|e| &e.branch == b);
                let custom = existing.map(|e| e.name.clone()).filter(|n| Role::from_name(n).is_none());
                let mut names: Vec<String> = Role::ALL.iter().map(|r| r.name().to_string()).collect();
                if let Some(c) = &custom {
                    names.push(c.clone());
                }
                let none = names.len();
                let taken = |n: &str, chosen: &[(i32, Environment)]| chosen.iter().find(|(_, e)| e.name == n).map(|(_, e)| e.branch.clone());
                let default = match existing {
                    Some(e) => names.iter().position(|n| *n == e.name).unwrap_or(none),
                    None if editing && !current.environment.is_empty() => none,
                    None => match suggest_role(b) {
                        Some(r) => match taken(r.name(), &chosen) {
                            Some(holder) => {
                                a.say(&format!("{} is already {holder}, so {b} is not suggested as {}.", r.name(), r.name()));
                                none
                            }
                            None => r as usize,
                        },
                        None => none,
                    },
                };
                let mut labels: Vec<String> = names.clone();
                if let Some(c) = &custom {
                    labels[names.len() - 1] = format!("keep it as {c}");
                }
                labels.push("not an environment".to_string());
                let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
                let mut pick = a.choice(&format!("Which environment is the branch {b}?"), &labels, default)?;
                for _ in 0..3 {
                    match names.get(pick).and_then(|n| taken(n, &chosen).map(|h| (n.clone(), h))) {
                        Some((n, holder)) => {
                            a.say(&format!("  {n} is already {holder}. Choose another, or not an environment."));
                            pick = a.choice(&format!("Which environment is the branch {b}?"), &labels, none)?;
                        }
                        None => break,
                    }
                }
                if let Some(name) = names.get(pick).filter(|n| taken(n, &chosen).is_none()) {
                    chosen.push((rank_of(name), Environment { name: name.clone(), branch: b.clone() }));
                }
            }
            chosen.sort_by_key(|(rank, _)| *rank);
            s.environments = chosen.into_iter().map(|(_, e)| e).collect();
        }
    }

    // 4. Checks.
    if !s.checks.is_empty() {
        let names: Vec<String> = s.checks.iter().map(|c| format!("{} ({})", c.name, c.run.join(" "))).collect();
        if !a.yes(&format!("These checks run on every change: {}. Keep them?", names.join(", ")), true)? {
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
    s.protect_paths = a.list("Folders or files that need a person's approval before they change (for example infra/**).", &s.protect_paths)?;
    s.locked = a.list("Folders or files that must never change (locked).", &s.locked)?;
    let append_default = if s.append_only.is_empty() && !editing { migration_dirs(top) } else { s.append_only.clone() };
    s.append_only = a.list("Folders where only new files may be added, like database migrations (append-only).", &append_default)?;
    let has_env = std::fs::read_dir(top).map(|d| d.filter_map(|e| e.ok()).any(|e| e.file_name().to_string_lossy().starts_with(".env"))).unwrap_or(false);
    let read_default = if s.no_read.is_empty() && !editing && has_env { vec![".env*".to_string()] } else { s.no_read.clone() };
    s.no_read = a.list("Files agents may not read, like secrets.", &read_default)?;

    // 6. How strict.
    s.scope = severity_choice(a, "When an agent changes files outside its plan:", &SEVERITY, s.scope)?;
    s.tests = severity_choice(a, "When a change weakens or removes tests:", &SEVERITY, s.tests)?;
    let land = a.choice("How should a finished change land?", &["I run use05 land", "Automatically, when 05 allows it"], usize::from(s.land == LandMode::Auto))?;
    s.land = if land == 1 { LandMode::Auto } else { LandMode::Manual };

    // 7. Confirm.
    a.say("\nYour settings:");
    for line in summary(&s) {
        a.say(&format!("  {line}"));
    }
    a.confirm("Write this to .05/policy.toml?")?.then_some(s)
}

/// What a run of the setup came to.
pub enum Outcome {
    /// The policy text with the answers in it.
    Written(String),
    /// The answers match the policy as it is.
    Unchanged,
    /// The input ended, or the person chose not to write: nothing changes.
    Stopped,
}

/// Run the setup on a policy `text`: ask on the terminal (questions on stderr, so `--json` on
/// stdout stays clean) when `interactive`, else take the flags. The result is checked to parse.
/// The notes name each answer an organisation's stricter rule overrides.
pub fn run_on(text: &str, top: &Path, editing: bool, interactive: bool, flags: &Flags) -> Result<(Outcome, Vec<String>), String> {
    let current = Policy::parse(text).map_err(|e| e.message)?;
    let settings = if interactive {
        let mut a = Asker::new(std::io::stdin().lock(), std::io::stderr());
        match ask(&mut a, top, &current, editing, flags) {
            Some(s) => s,
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
    fn a_check_with_shell_syntax_runs_through_sh() {
        assert_eq!(parse_check("test: FOO=1 npm test").unwrap().run, ["sh", "-c", "FOO=1 npm test"]);
        assert_eq!(parse_check("lint: npm run lint").unwrap().run, ["npm", "run", "lint"]);
        assert!(parse_check("no colon here").is_none() && parse_check("two words: x").is_none());
    }
}
