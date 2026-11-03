//! `use05 init` and `use05 uninstall`.
//!
//! Init says exactly what it changed. It records each change in `.git/05/install.json`, and
//! uninstall reverses exactly those changes and nothing else. It never overwrites a hook or a
//! file it did not create, and it says what is therefore not covered.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use use05_core::keys;
use use05_core::policy::{CheckDef, POLICY_PATH, detect_checks};
use use05_core::{git, task::Store};

use crate::report::{Report, Tone};

pub const HOOK_MARK: &str = "# 05 pre-push hook";
const BLOCK_BEGIN: &str = "<!-- 05:begin -->";
const BLOCK_END: &str = "<!-- 05:end -->";
const AGENT_COMMAND_PREFIX: &str = "use05 hook ";

pub struct Args {
    pub ci: Option<String>,
    pub no_hooks: bool,
    /// Claude Code's hooks in the committed settings, so they travel with the repository (D86).
    pub shared_hooks: bool,
    pub no_agents_md: bool,
    pub repo: PathBuf,
    /// Ask the setup questions (on a terminal, or with --guided).
    pub interactive: bool,
    /// Answers given as flags.
    pub flags: crate::cmd::setup::Flags,
}

#[derive(Serialize, Deserialize, Default)]
struct Manifest {
    items: Vec<Item>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Item {
    /// A file 05 created, with the hash it had when created.
    File { path: String, sha256: String },
    /// Hook entries added to an agent's settings JSON.
    AgentHooks { path: String },
    /// A delimited block added to a text file.
    Block { path: String },
}

fn sha(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn manifest_path(store: &Store) -> PathBuf {
    store.state_dir().join("install.json")
}

fn load_manifest(store: &Store) -> Manifest {
    fs::read(manifest_path(store)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_manifest(store: &Store, m: &Manifest) -> Result<(), String> {
    let path = manifest_path(store);
    fs::create_dir_all(path.parent().expect("has parent")).map_err(|e| e.to_string())?;
    fs::write(path, serde_json::to_vec_pretty(m).expect("manifest serialises")).map_err(|e| e.to_string())
}

// ----------------------------------------------------------------------------- inspection

#[derive(Default, Clone)]
pub struct Setup {
    pub policy_file: bool,
    pub claude_hooks: bool,
    pub codex_hooks: bool,
    pub pre_push: Hook,
    pub ci_workflow: bool,
    pub agents_block: bool,
    pub on_path: bool,
}

#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub enum Hook {
    #[default]
    Missing,
    Ours,
    /// Another tool's hook is in the way; 05 did not touch it.
    Foreign,
}

fn has_agent_hooks(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|t| t.contains(AGENT_COMMAND_PREFIX))
}

fn hooks_dir(top: &Path) -> PathBuf {
    let raw = git::text(top, &["rev-parse", "--git-path", "hooks"]).unwrap_or_else(|_| ".git/hooks".into());
    let p = PathBuf::from(raw);
    if p.is_absolute() { p } else { top.join(p) }
}

pub fn inspect(top: &Path) -> Setup {
    let pre_push = hooks_dir(top).join("pre-push");
    Setup {
        policy_file: top.join(POLICY_PATH).exists(),
        claude_hooks: has_agent_hooks(&top.join(".claude/settings.local.json")) || has_agent_hooks(&top.join(".claude/settings.json")),
        codex_hooks: has_agent_hooks(&top.join(".codex/hooks.json")),
        pre_push: match fs::read_to_string(&pre_push) {
            Ok(t) if t.contains(HOOK_MARK) => Hook::Ours,
            Ok(_) => Hook::Foreign,
            Err(_) => Hook::Missing,
        },
        ci_workflow: top.join(".github/workflows/05.yml").exists(),
        agents_block: fs::read_to_string(top.join("AGENTS.md")).is_ok_and(|t| t.contains(BLOCK_BEGIN)),
        on_path: std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("use05").is_file())),
    }
}

// ----------------------------------------------------------------------------- init

pub(crate) fn policy_template(checks: &[CheckDef]) -> String {
    let mut text = format!(
        "# 05 policy. A change is held to the rules at its base, so editing this file needs a person's approval.\n\
         \n\
         [use05]\n\
         min_version = \"{}\"     # the oldest use05 that reads this file; older ones ask to be upgraded\n\
         \n\
         [intent]\n\
         mode = \"inferred\"        # inferred: no card needed | risky: a card for risky changes | always\n\
         \n",
        env!("CARGO_PKG_VERSION")
    );
    if checks.is_empty() {
        text.push_str("# No checks were detected. Add the commands that decide whether a change is good:\n# [[check]]\n# name = \"test\"\n# run = [\"npm\", \"test\"]\n\n");
    } else {
        text.push_str("# Checks 05 runs on the exact tree. Required ones must pass before a change is allowed.\n");
        for c in checks {
            text.push_str(&format!("[[check]]\nname = \"{}\"\nrun = [{}]\n", c.name, c.run.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>().join(", ")));
            if !c.env.is_empty() {
                text.push_str(&format!("env = [{}]   # passed to the check by name; values are never stored\n", c.env.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>().join(", ")));
            }
            text.push('\n');
        }
    }
    text.push_str(
        "[protect]\n\
         paths = []                 # a change here needs a person's approval, e.g. [\"infra/**\"]. .05/** is always protected.\n\
         # locked = []              # never changed; no approval clears it, a person's bypass can (absolute = [] for locks no bypass clears)\n\
         # append_only = []         # new files only, e.g. [\"migrations/**\"]: existing ones are never edited, renamed or deleted\n\
         # no_delete = []           # may be edited, never deleted\n\
         # no_read = []             # agents may not open these, e.g. [\".env*\"] (agent hooks only: advisory)\n\
         # bypass = true            # false: no bypass clears any of the above\n\
         \n\
         [branches]\n\
         keep = [\"main\", \"master\", \"develop\", \"release/*\"]   # real branches: never deleted\n\
         work = [\"05/*\", \"agent/*\", \"claude/*\", \"codex/*\"]   # agents' working branches: removed with their worktree once landed\n\
         land = \"manual\"            # manual: `use05 land` | auto: the Stop hook lands a change the gate allows\n\
         fresh_base = \"warn\"        # an agent that starts behind origin: allow (do not check) | warn (tell it) | approval | deny\n\
         \n\
         [risk]                     # built-in risk areas (auth, money, migrations, secrets, deployment, ...) need one approval\n\
         exempt = []                # paths a risk pattern catches by mistake, e.g. [\"src/session_store.rs\"]\n\
         \n\
         [drift]\n\
         scope = \"warn\"             # files outside the declared scope: allow | warn | approval | deny\n\
         dependencies = \"warn\"      # dependency files changed\n\
         overlap = \"warn\"           # another agent session edited the same file lately: warn (tell the agent) | approval (ask a person) | deny\n\
         tests = \"approval\"         # the change deletes, skips or loosens tests, or lets a failing check pass\n\
         claims = \"warn\"            # an agent's claim the evidence does not support\n\
         \n\
         [evidence]\n\
         accept = [\"local\", \"runner\"]   # [\"runner\"] counts only evidence signed in CI\n\
         \n\
         [approvals]\n\
         min = 1\n\
         expire_days = 7\n\
         \n\
         [record]\n\
         middle = \"local\"           # what agents did is recorded on this machine, never uploaded\n\
         \n\
         [enforce]\n\
         on_error = \"open\"          # if 05 itself fails: open (warn loudly, let it through) | closed\n\
         \n\
         # Trust a CI runner so its receipts count as authoritative:\n\
         # [[trust.key]]\n\
         # name = \"ci\"\n\
         # role = \"runner\"\n\
         # public = \"use05-ed25519-public:...\"\n\
         # expires = \"2027-12-31\"   # optional: stop trusting this key after this date\n\
         \n\
         # Files that must change together: a change to `when` must also change one of `also`.\n\
         # [[require]]\n\
         # when = [\"src/api/**\"]\n\
         # also = [\"docs/api/**\"]\n\
         # severity = \"approval\"    # allow | warn | approval | deny\n\
         # why = \"the API docs\"     # said to the agent and in the brief\n",
    );
    text
}

/// Where a project-level npm install keeps its command: `node_modules/.bin` at the top of the
/// main work tree, found through git so agents' linked worktrees reach it too. Appended to PATH,
/// so a use05 installed for the whole machine still wins.
const LOCAL_BIN_PATH: &str = "PATH=\"$PATH:$(git rev-parse --path-format=absolute --git-common-dir)/../node_modules/.bin\"";

/// How hooks call use05: by name, and when this copy was run from a project's `node_modules`
/// (`npx use05 init`), with that `node_modules/.bin` added to PATH so the hooks find it.
fn hook_runner() -> String {
    let local = std::env::current_exe().ok().and_then(|p| p.canonicalize().ok()).is_some_and(|p| p.components().any(|c| c.as_os_str() == "node_modules"));
    if local { format!("{LOCAL_BIN_PATH} ") } else { String::new() }
}

/// In a Claude Code cloud session (D86): install this 05 when the session lacks it, and report to
/// your console when the session has a token (`USE05_SESSION`). Nothing happens on your own
/// machine. The trailing comment marks it as 05's, so `uninstall` takes it out with the rest.
fn cloud_session_hook() -> Value {
    let version = env!("CARGO_PKG_VERSION");
    json!({ "type": "command", "command": format!("[ \"$CLAUDE_CODE_REMOTE\" = true ] || exit 0; command -v use05 >/dev/null 2>&1 || npm install -g --silent @use05/cli@{version} >/dev/null 2>&1; [ -z \"$USE05_SESSION\" ] || use05-cloud session --background; exit 0 # {AGENT_COMMAND_PREFIX}cloud-session"), "timeout": 120 })
}

fn claude_hook_json() -> Value {
    // The Stop hook may prove the change before the agent finishes (D65), so it gets longer.
    let run = hook_runner();
    let hook = |event: &str| json!({ "type": "command", "command": format!("{run}{AGENT_COMMAND_PREFIX}claude-code {event}"), "timeout": if event == "Stop" { 90 } else { 10 } });
    json!({
        "SessionStart": [ { "hooks": [cloud_session_hook(), hook("SessionStart")] } ],
        "UserPromptSubmit": [ { "hooks": [hook("UserPromptSubmit")] } ],
        "PreToolUse":   [ { "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash|Read|Grep|Glob", "hooks": [hook("PreToolUse")] } ],
        "PostToolUse":  [ { "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash", "hooks": [hook("PostToolUse")] } ],
        "Stop":         [ { "hooks": [hook("Stop")] } ],
        "SubagentStart": [ { "hooks": [hook("SubagentStart")] } ],
        "SubagentStop": [ { "hooks": [hook("SubagentStop")] } ],
        "SessionEnd":   [ { "hooks": [hook("SessionEnd")] } ],
    })
}

fn codex_hook_json() -> Value {
    let run = hook_runner();
    let hook = |event: &str| json!({ "type": "command", "command": format!("{run}{AGENT_COMMAND_PREFIX}codex {event}"), "timeout": if event == "Stop" { 90 } else { 10 } });
    json!({
        "PreToolUse":  [ { "matcher": "^(Bash|shell|apply_patch|Edit|Write)$", "hooks": [hook("PreToolUse")] } ],
        "PostToolUse": [ { "matcher": "^(Bash|shell|apply_patch|Edit|Write)$", "hooks": [hook("PostToolUse")] } ],
        "Stop":        [ { "hooks": [hook("Stop")] } ],
        "SubagentStart": [ { "hooks": [hook("SubagentStart")] } ],
        "SubagentStop": [ { "hooks": [hook("SubagentStop")] } ],
    })
}

/// Commands an agent may run without a permission prompt. Reading and recording only: never
/// `approve`, `bypass`, `key`, `init`, `uninstall` or `gate`, which stay a person's.
const AGENT_ALLOWED: &[&str] = &["start", "prove", "finish", "brief", "verify", "policy", "doctor", "land"];

fn allowed_rules() -> Vec<String> {
    AGENT_ALLOWED.iter().flat_map(|c| [format!("Bash(use05 {c})"), format!("Bash(use05 {c} *)")]).collect()
}

/// Merge our hook groups (and, for Claude Code, permission rules) into an agent's settings file,
/// leaving everything else alone.
fn merge_agent_hooks(path: &Path, ours: &Value, allow: &[String]) -> Result<(), String> {
    let mut root: Value = match fs::read_to_string(path) {
        Ok(t) if !t.trim().is_empty() => serde_json::from_str(&t).map_err(|e| format!("{} is not valid JSON ({e}); not touching it", path.display()))?,
        _ => json!({}),
    };
    let hooks = root.as_object_mut().ok_or("settings is not a JSON object")?.entry("hooks").or_insert_with(|| json!({}));
    let hooks = hooks.as_object_mut().ok_or("\"hooks\" is not an object")?;
    for (event, groups) in ours.as_object().expect("object") {
        let list = hooks.entry(event.clone()).or_insert_with(|| json!([]));
        let list = list.as_array_mut().ok_or("a hook event is not a list")?;
        // Our groups replace what an older use05 installed, in the same place, so an upgrade gets
        // the new matchers. Other tools' groups are never touched.
        let at = list.iter().position(|g| g.to_string().contains(AGENT_COMMAND_PREFIX)).unwrap_or(list.len());
        list.retain(|g| !g.to_string().contains(AGENT_COMMAND_PREFIX));
        let at = at.min(list.len());
        list.splice(at..at, groups.as_array().expect("array").iter().cloned());
    }
    if !allow.is_empty() {
        let permissions = root.as_object_mut().expect("object").entry("permissions").or_insert_with(|| json!({}));
        let list = permissions.as_object_mut().ok_or("\"permissions\" is not an object")?.entry("allow").or_insert_with(|| json!([]));
        let list = list.as_array_mut().ok_or("\"permissions.allow\" is not a list")?;
        for rule in allow {
            if !list.iter().any(|r| r == rule) {
                list.push(json!(rule));
            }
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(path, serde_json::to_string_pretty(&root).expect("json") + "\n").map_err(|e| e.to_string())
}

fn remove_agent_hooks(path: &Path) -> Result<bool, String> {
    let Ok(text) = fs::read_to_string(path) else { return Ok(false) };
    let mut root: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let mut changed = false;
    if let Some(hooks) = root.get_mut("hooks").and_then(Value::as_object_mut) {
        for (_, groups) in hooks.iter_mut() {
            if let Some(list) = groups.as_array_mut() {
                let before = list.len();
                list.retain(|g| !g.to_string().contains(AGENT_COMMAND_PREFIX));
                changed |= list.len() != before;
            }
        }
        hooks.retain(|_, v| v.as_array().is_none_or(|l| !l.is_empty()));
    }
    if root.get("hooks").and_then(Value::as_object).is_some_and(|h| h.is_empty()) {
        root.as_object_mut().expect("object").remove("hooks");
    }
    let ours = allowed_rules();
    if let Some(list) = root.pointer_mut("/permissions/allow").and_then(Value::as_array_mut) {
        let before = list.len();
        list.retain(|r| !r.as_str().is_some_and(|r| ours.iter().any(|o| o == r)));
        changed |= list.len() != before;
        if list.is_empty() {
            root["permissions"].as_object_mut().expect("object").remove("allow");
        }
    }
    if root.get("permissions").and_then(Value::as_object).is_some_and(|p| p.is_empty()) {
        root.as_object_mut().expect("object").remove("permissions");
    }
    if changed {
        if root.as_object().is_some_and(|o| o.is_empty()) {
            fs::remove_file(path).map_err(|e| e.to_string())?;
        } else {
            fs::write(path, serde_json::to_string_pretty(&root).expect("json") + "\n").map_err(|e| e.to_string())?;
        }
    }
    Ok(changed)
}

fn agents_block() -> String {
    format!(
        "{BLOCK_BEGIN}\n## 05\n\nThis repository uses 05 (https://use05.dev) to check AI-written changes.\n\n\
         - Before you edit, declare your plan: `use05 start \"<what you will do>\" --scope \"<paths>\" --check <name>`, with a check name from `use05 policy`. 05 seals it; another agent's work area is shown to you.\n\
         - Stay inside your scope. Protected paths and risky areas need a person's approval; ask the user.\n\
         - When you are done, say what you did: `use05 finish --outcome \"<what you did>\"`. 05 runs the checks itself.\n\
         - If you are on a working branch (one you, your tool or the user made), `use05 land` moves it into its target when the gate allows it, and 05 cleans up the branch and worktree afterwards. Do not create branches just for 05.\n\
         - `use05 approve` and `use05 bypass` need the approver passphrase, which agents do not have.\n\
         {BLOCK_END}\n"
    )
}

fn ci_workflow() -> &'static str {
    "name: 05\n\
     \n\
     # Every pushed branch is gated, so an agent's branch is checked before it lands; landing\n\
     # fast-forwards that same commit onto main, with or without a pull request. 05's own\n\
     # receipts branches are not changes to gate.\n\
     on:\n  pull_request:\n  push:\n    branches-ignore: [\"05-receipts/**\"]\n\
     \n\
     # write: the runner pushes its own receipts branch (05-receipts/<runner key>), so what it\n\
     # sealed outlives the job. Nothing else is pushed.\n\
     permissions:\n  contents: write\n\
     \n\
     jobs:\n  acceptance:\n    runs-on: ubuntu-latest\n    steps:\n\
     \x20     # The token is not left in .git/config, where the code under test could read it.\n\
     \x20     - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n          persist-credentials: false\n\
     \n\
     \x20     # Installs a checksum-verified release. It fails loudly if no release can be fetched,\n\
     \x20     # instead of passing without checking anything.\n\
     \x20     - name: Install use05\n        run: |\n          curl -fsSL https://use05.dev/install.sh | sh\n          echo \"$HOME/.local/bin\" >> \"$GITHUB_PATH\"\n\
     \n\
     \x20     # Proves the policy's required checks with the runner key (a CI secret the agent cannot\n\
     \x20     # read), then gates the change. Make this job a required check in branch protection.\n\
     \x20     - name: Prove and gate\n        env:\n          USE05_RUNNER_KEY: ${{ secrets.USE05_RUNNER_KEY }}\n          USE05_PUSH_TOKEN: ${{ github.token }}\n        run: use05 gate --ci --push\n"
}

pub fn run(args: Args) -> Report {
    let store = match Store::open(&args.repo) {
        Ok(s) => s,
        Err(e) => return Report::from_core("init", e),
    };
    let top = store.dirs.top.clone();
    let mut manifest = load_manifest(&store);
    let mut changed: Vec<String> = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    let mut gaps: Vec<String> = Vec::new();

    // Policy
    let policy_path = top.join(POLICY_PATH);
    use crate::cmd::setup::{AFTER_EDIT, Outcome, run_on};
    let stopped = || Report::error("init", "SETUP_STOPPED", "Setup stopped; nothing was changed.".into(), Some("run use05 init again when you are ready".into()), 1);
    let mut after = Vec::new();
    if policy_path.exists() {
        let wanted = if args.interactive {
            let mut a = crate::prompt::Asker::styled(std::io::stdin().lock(), std::io::stderr(), crate::ui::Ui::stderr());
            match a.yes("05 is already set up here. Change your settings?", false) {
                None => return stopped(),
                Some(yes) => yes,
            }
        } else {
            args.flags.any()
        };
        let current = fs::read_to_string(&policy_path).unwrap_or_default();
        match if wanted { run_on(&current, &top, true, args.interactive, &args.flags) } else { Ok((Outcome::Unchanged, Vec::new())) } {
            Err(e) => return Report::error("init", "POLICY_INVALID", format!("{POLICY_PATH}: {e}"), Some("fix the file, or move it away and run use05 init again".into()), 3),
            Ok((Outcome::Stopped, _)) => return stopped(),
            Ok((Outcome::Written(text), notes)) => {
                if let Err(e) = fs::write(&policy_path, &text) {
                    return Report::error("init", "IO_ERROR", format!("cannot write {POLICY_PATH}: {e}"), None, 4);
                }
                changed.push(format!("updated {POLICY_PATH} with your answers"));
                after.extend(notes);
                after.push(AFTER_EDIT.to_string());
            }
            Ok((Outcome::Unchanged, notes)) => {
                after.extend(notes);
                kept.push(format!("{POLICY_PATH} already exists; left as it is"));
            }
        }
    } else {
        let checks = detect_checks(&top);
        let text = policy_template(&checks);
        let text = if args.interactive || args.flags.any() {
            match run_on(&text, &top, false, args.interactive, &args.flags) {
                Err(e) => return Report::error("init", "SETUP_INVALID", e, None, 6),
                Ok((Outcome::Stopped, _)) => return stopped(),
                Ok((Outcome::Written(t), notes)) => {
                    after.extend(notes);
                    t
                }
                Ok((Outcome::Unchanged, notes)) => {
                    after.extend(notes);
                    text
                }
            }
        } else {
            text
        };
        if let Err(e) = fs::create_dir_all(policy_path.parent().expect("has parent")).and_then(|_| fs::write(&policy_path, &text)) {
            return Report::error("init", "IO_ERROR", format!("cannot write {POLICY_PATH}: {e}"), None, 4);
        }
        manifest.items.push(Item::File { path: POLICY_PATH.into(), sha256: sha(&text) });
        changed.push(if args.interactive || args.flags.any() {
            format!("created {POLICY_PATH} with your answers")
        } else if checks.is_empty() {
            format!("created {POLICY_PATH} (no checks detected; add yours)")
        } else {
            format!("created {POLICY_PATH}, proposing the checks: {}", checks.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", "))
        });
    }

    // Agents' unsealed declarations wait in .05/inbox; git must never pick them up.
    let ignore = top.join(".05/.gitignore");
    if !ignore.exists() {
        let text = "inbox/\n";
        match fs::create_dir_all(top.join(".05")).and_then(|_| fs::write(&ignore, text)) {
            Ok(()) => {
                manifest.items.push(Item::File { path: ".05/.gitignore".into(), sha256: sha(text) });
                changed.push("created .05/.gitignore so agents' unsealed declarations stay out of git".into());
            }
            Err(e) => gaps.push(format!("could not write .05/.gitignore: {e}")),
        }
    }

    // Keys
    match keys::ensure_local() {
        Ok((_, true)) => changed.push("created this machine's signing key (advisory: it signs what you prove locally)".into()),
        Ok((_, false)) => kept.push("this machine's signing key already exists".into()),
        Err(e) => return Report::from_core("init", e),
    }
    if !keys::approver_exists() {
        gaps.push("no approver key yet, so nobody can approve or break glass: run `use05 key new --approver`".into());
    }

    if !args.no_hooks {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let has = |p: &str| top.join(p).exists() || home.as_ref().is_some_and(|h| h.join(p).exists());
        // Claude Code
        if has(".claude") {
            let file = if args.shared_hooks { ".claude/settings.json" } else { ".claude/settings.local.json" };
            let path = top.join(file);
            match merge_agent_hooks(&path, &claude_hook_json(), &allowed_rules()) {
                Ok(()) => {
                    if !manifest.items.iter().any(|i| matches!(i, Item::AgentHooks { path } if path == file)) {
                        manifest.items.push(Item::AgentHooks { path: file.into() });
                    }
                    changed.push(format!("installed Claude Code hooks in {file} (advisory: they fail open) and let the agent run start, prove, finish, brief and land without a prompt once you have trusted this folder in Claude Code (never approve or bypass){}", if args.shared_hooks { "; commit it, so every checkout and cloud session runs under 05" } else { "" }));
                }
                Err(e) => gaps.push(format!("Claude Code hooks not installed: {e}")),
            }
        } else {
            gaps.push("Claude Code not detected, so no Claude Code hooks".into());
        }
        // Codex
        if has(".codex") {
            let path = top.join(".codex/hooks.json");
            match merge_agent_hooks(&path, &codex_hook_json(), &[]) {
                Ok(()) => {
                    if !manifest.items.iter().any(|i| matches!(i, Item::AgentHooks { path } if path.ends_with("hooks.json"))) {
                        manifest.items.push(Item::AgentHooks { path: ".codex/hooks.json".into() });
                    }
                    changed.push("installed Codex hooks in .codex/hooks.json (Codex asks you to trust them: run /hooks in Codex)".into());
                }
                Err(e) => gaps.push(format!("Codex hooks not installed: {e}")),
            }
        } else {
            gaps.push("Codex not detected, so no Codex hooks".into());
        }
        // git pre-push
        let hook = hooks_dir(&top).join("pre-push");
        match fs::read_to_string(&hook) {
            Ok(t) if t.contains(HOOK_MARK) => kept.push("the git pre-push hook is already installed".into()),
            Ok(_) => gaps.push(format!("an existing pre-push hook at {} was left alone, so pushes are not checked by 05", hook.display())),
            Err(_) => {
                let script = format!("#!/bin/sh\n{HOOK_MARK} (installed by `use05 init`; remove with `use05 uninstall`)\n# A project-level npm install is found too; one on PATH comes first.\nexport {LOCAL_BIN_PATH}\ncommand -v use05 >/dev/null 2>&1 || {{ echo \"05: use05 is not on PATH; this push was not checked\" >&2; exit 0; }}\nexec use05 gate --git-hook pre-push \"$@\"\n");
                let written = fs::create_dir_all(hook.parent().expect("has parent")).and_then(|_| fs::write(&hook, &script));
                match written {
                    Ok(()) => {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&hook, fs::Permissions::from_mode(0o755));
                        manifest.items.push(Item::File { path: hook.strip_prefix(&top).unwrap_or(&hook).display().to_string(), sha256: sha(&script) });
                        changed.push("installed the git pre-push hook (advisory: `git push --no-verify` skips it)".into());
                    }
                    Err(e) => gaps.push(format!("could not install the pre-push hook: {e}")),
                }
            }
        }
    }

    // AGENTS.md
    if !args.no_agents_md {
        let path = top.join("AGENTS.md");
        let existing = fs::read_to_string(&path).unwrap_or_default();
        if existing.contains(BLOCK_BEGIN) {
            kept.push("AGENTS.md already has the 05 block".into());
        } else {
            let sep = if existing.is_empty() || existing.ends_with("\n\n") { "" } else if existing.ends_with('\n') { "\n" } else { "\n\n" };
            match fs::write(&path, format!("{existing}{sep}{}", agents_block())) {
                Ok(()) => {
                    manifest.items.push(Item::Block { path: "AGENTS.md".into() });
                    changed.push("added a short 05 block to AGENTS.md for agents to read".into());
                }
                Err(e) => gaps.push(format!("could not update AGENTS.md: {e}")),
            }
        }
    }

    // CI
    match args.ci.as_deref() {
        Some("github") => {
            let path = top.join(".github/workflows/05.yml");
            if path.exists() {
                kept.push(".github/workflows/05.yml already exists; left as it is".into());
            } else {
                let text = ci_workflow();
                match fs::create_dir_all(path.parent().expect("has parent")).and_then(|_| fs::write(&path, text)) {
                    Ok(()) => {
                        manifest.items.push(Item::File { path: ".github/workflows/05.yml".into(), sha256: sha(text) });
                        changed.push("wrote .github/workflows/05.yml (it proves and gates in CI; add USE05_RUNNER_KEY as a secret)".into());
                    }
                    Err(e) => gaps.push(format!("could not write the CI workflow: {e}")),
                }
            }
        }
        Some(other) => return Report::error("init", "CI_UNSUPPORTED", format!("no CI template for {other:?} yet"), Some("use --ci github, or run `use05 gate --ci` from any CI".into()), 6),
        None => gaps.push("no merge enforcement yet: add a CI check with `use05 init --ci github`, then make it required in branch protection".into()),
    }

    if let Err(e) = save_manifest(&store, &manifest) {
        return Report::error("init", "IO_ERROR", format!("could not record what was installed: {e}"), None, 4);
    }

    let mut rows: Vec<(String, String)> = Vec::new();
    for c in &changed {
        rows.push(("changed".into(), c.clone()));
    }
    for k in &kept {
        rows.push(("kept".into(), k.clone()));
    }
    for g in &gaps {
        rows.push(("not covered".into(), g.clone()));
    }
    Report {
        command: "init",
        outcome: "ready",
        code: "INIT",
        tone: Tone::Good,
        headline: if changed.is_empty() { "Already set up".to_string() } else { format!("Set up 05 in this repository ({} change{})", changed.len(), if changed.len() == 1 { "" } else { "s" }) },
        rows,
        notes: {
            let mut notes = vec!["Everything above is recorded; `use05 uninstall` reverses exactly it, and never touches your code, your branches or your policy file.".to_string()];
            notes.extend(after);
            notes
        },
        next: Some(match uncommitted_setup(&top) {
            // The rules count at a push and in CI only once committed.
            Some(paths) => format!("git add {paths} && git commit -m \"Set up 05\"   so your rules count at a push"),
            None => "use05 doctor   to see how strongly each control is enforced".into(),
        }),
        excerpt: vec![],
        details: json!({ "changed": changed, "kept": kept, "not_covered": gaps }),
        exit: 0,
    }
}

/// What `init` wrote for everyone that is not committed yet, as `git add` arguments.
fn uncommitted_setup(top: &Path) -> Option<String> {
    let paths: Vec<&str> = [".05", ".codex", "AGENTS.md", ".claude/settings.json", ".github/workflows/05.yml"]
        .into_iter()
        .filter(|p| top.join(p).exists() && git::text(top, &["status", "--porcelain", "--", p]).is_ok_and(|s| !s.trim().is_empty()))
        .collect();
    (!paths.is_empty()).then(|| paths.join(" "))
}

pub fn uninstall(repo: &Path) -> Report {
    let store = match Store::open(repo) {
        Ok(s) => s,
        Err(e) => return Report::from_core("uninstall", e),
    };
    let top = store.dirs.top.clone();
    let manifest = load_manifest(&store);
    if manifest.items.is_empty() {
        return Report { command: "uninstall", outcome: "nothing", code: "NOTHING_TO_UNINSTALL", tone: Tone::Plain, headline: "Nothing to uninstall: 05 recorded no changes in this repository".into(), rows: vec![], notes: vec![], next: None, excerpt: vec![], details: Value::Null, exit: 0 };
    }
    let mut rows: Vec<(String, String)> = Vec::new();
    for item in &manifest.items {
        match item {
            Item::File { path, sha256 } => {
                let full = top.join(path);
                if path == POLICY_PATH {
                    rows.push(("left".into(), format!("{path} (your policy; delete it yourself if you want it gone)")));
                    continue;
                }
                match fs::read_to_string(&full) {
                    Ok(t) if sha(&t) == *sha256 => {
                        let _ = fs::remove_file(&full);
                        rows.push(("removed".into(), path.clone()));
                    }
                    Ok(_) => rows.push(("left".into(), format!("{path} (it was edited since init)"))),
                    Err(_) => rows.push(("gone".into(), format!("{path} was already removed"))),
                }
            }
            Item::AgentHooks { path } => match remove_agent_hooks(&top.join(path)) {
                Ok(true) => rows.push(("removed".into(), format!("05's hook entries from {path}"))),
                Ok(false) => rows.push(("gone".into(), format!("{path} had no 05 entries"))),
                Err(e) => rows.push(("left".into(), format!("{path} ({e})"))),
            },
            Item::Block { path } => {
                let full = top.join(path);
                match fs::read_to_string(&full) {
                    Ok(t) => match (t.find(BLOCK_BEGIN), t.find(BLOCK_END)) {
                        (Some(a), Some(b)) if b > a => {
                            let end = b + BLOCK_END.len();
                            let rest = format!("{}{}", t[..a].trim_end_matches('\n'), t[end..].trim_start_matches('\n'));
                            let cleaned = if rest.trim().is_empty() { String::new() } else { format!("{}\n", rest.trim_end_matches('\n')) };
                            if cleaned.is_empty() { let _ = fs::remove_file(&full); } else { let _ = fs::write(&full, cleaned); }
                            rows.push(("removed".into(), format!("the 05 block from {path}")));
                        }
                        _ => rows.push(("gone".into(), format!("{path} had no 05 block"))),
                    },
                    Err(_) => rows.push(("gone".into(), format!("{path} was already removed"))),
                }
            }
        }
    }
    let _ = fs::remove_file(manifest_path(&store));
    Report {
        command: "uninstall",
        outcome: "removed",
        code: "UNINSTALLED",
        tone: Tone::Good,
        headline: "Removed what `use05 init` installed".into(),
        rows,
        notes: vec!["Receipts branches, the local log and your keys are kept: delete them yourself if you want them gone.".into()],
        next: None,
        excerpt: vec![],
        details: Value::Null,
        exit: 0,
    }
}
