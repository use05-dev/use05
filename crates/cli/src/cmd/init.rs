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

use crate::host;
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

/// What Git LFS's own pre-push hook runs, and so what 05's must run before its own check (D96):
/// LFS uploads the large files a push refers to, and a push without it leaves bare pointers.
const LFS_CALL: &str = "git lfs pre-push";

/// A `.gitattributes` line that sends files through the LFS filter and is not a comment.
const LFS_FILTER_LINE: &str = "^[[:space:]]*[^#[:space:]].*filter=lfs";
/// An `lfs.*` setting in the repository's own config that says it uses Git LFS: any but
/// `lfs.repositoryformatversion`, which Git LFS writes into every repository it runs in.
const LFS_CONFIG: &str = "^lfs\\.([^r]|r[^e]|re[^p])";

/// 05's pre-push hook. git hands it the pushed refs on stdin once, and both Git LFS and 05 need
/// them, so they are kept in a file. Git LFS goes first, and a failure there fails the push.
fn pre_push_script() -> String {
    format!(
        "#!/bin/sh\n\
         {HOOK_MARK} (installed by `use05 init`; remove with `use05 uninstall`)\n\
         # A project-level npm install is found too; one on PATH comes first.\n\
         export {LOCAL_BIN_PATH}\n\
         input=$(mktemp \"${{TMPDIR:-/tmp}}/05-pre-push.XXXXXX\") || exit 1\n\
         trap 'rm -f \"$input\"' EXIT\n\
         trap 'exit 1' HUP INT TERM\n\
         cat > \"$input\"\n\
         # Git LFS first, when this repository uses it: its objects must be uploaded before the pointers.\n\
         # Without git-lfs the push stops, as Git LFS's own hook stops it: pointers must not go out alone.\n\
         # Used: lfs settings in this repository's own config, or a line in a tracked .gitattributes that is not a comment.\n\
         if git config --local --get-regexp '{LFS_CONFIG}' >/dev/null 2>&1 || git grep -q -E '{LFS_FILTER_LINE}' -- '*.gitattributes' >/dev/null 2>&1; then\n\
         \x20 command -v git-lfs >/dev/null 2>&1 || {{ echo \"05: this repository uses Git LFS, but git-lfs was not found on PATH, so this push was stopped before its large files could be uploaded. Install git-lfs (https://git-lfs.com) or put it on PATH, then push again.\" >&2; exit 2; }}\n\
         \x20 {LFS_CALL} \"$@\" < \"$input\" || exit $?\n\
         fi\n\
         command -v use05 >/dev/null 2>&1 || {{ echo \"05: use05 is not on PATH; this push was not checked\" >&2; exit 0; }}\n\
         use05 gate --git-hook pre-push \"$@\" < \"$input\"\n"
    )
}

/// The hook `git lfs install` writes, and only that: a check that git-lfs is installed, with a
/// message and `exit 2`, then `git lfs pre-push "$@"` (older versions had only the second line).
/// Whitespace may differ. A hook that adds anything of its own is another tool's, and kept.
fn is_standard_lfs_hook(text: &str) -> bool {
    let body: Vec<String> = text.lines().map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    let call = |l: &String| l == "git lfs pre-push \"$@\"";
    // `command -v git-lfs ... || { echo >&2 "<message>"; exit 2; }` (or `printf >&2 "<fmt>" "<message>"`):
    // outside its quotes it is only the printing command, and nothing in the quotes runs anything.
    let check = |l: &String| {
        let inner = l.strip_prefix("command -v git-lfs >/dev/null 2>&1 || { ").and_then(|r| r.strip_suffix("; exit 2; }"));
        let Some(inner) = inner else { return false };
        let (mut outside, mut quoted, mut open) = (String::new(), String::new(), false);
        for c in inner.chars() {
            match (c, open) {
                ('"', _) => open = !open,
                (c, true) => quoted.push(c),
                (c, false) => outside.push(c),
            }
        }
        let outside = outside.split_whitespace().collect::<Vec<_>>().join(" ");
        !open && (outside == "echo >&2" || outside == "printf >&2") && quoted.contains("configured for Git LFS") && !quoted.contains(['$', '`'])
    };
    match body.as_slice() {
        [only] => call(only),
        [first, second] => check(first) && call(second),
        _ => false,
    }
}

/// Whether this repository uses Git LFS: lfs settings in its git config, or a `.gitattributes`
/// that sends files through the LFS filter.
pub fn repo_uses_lfs(top: &Path) -> bool {
    git::text(top, &["config", "--local", "--get-regexp", LFS_CONFIG]).is_ok_and(|t| !t.is_empty()) || git::run(top, &["grep", "-q", "-E", LFS_FILTER_LINE, "--", "*.gitattributes"]).is_ok()
}

/// A warning when Git LFS is used here and the installed pre-push hook does not run its upload
/// step: pointers would be pushed without their files. `true` for a problem (05's own hook, which
/// should have it), `false` for a note (another tool's hook, which may reach LFS another way: a
/// hook manager, or a `core.hooksPath` wrapper).
pub fn lfs_hook_problem(top: &Path, hook: &Hook) -> Option<(bool, String)> {
    if *hook == Hook::Missing || !repo_uses_lfs(top) {
        return None;
    }
    let text = fs::read_to_string(hooks_dir(top).join("pre-push")).unwrap_or_default();
    if text.contains(LFS_CALL) {
        return None;
    }
    Some(match hook {
        Hook::Ours => (true, "pre-push hook  this repository uses Git LFS, but the installed hook does not run Git LFS's upload step, so LFS files may not be uploaded when you push. `use05 uninstall`, then `use05 init`, installs one that does".into()),
        _ => (false, "pre-push hook  this repository uses Git LFS, but the installed hook does not run `git lfs pre-push` itself. If it reaches Git LFS another way (a hook manager, a wrapper) that is fine; if not, LFS files may not be uploaded when you push: add `git lfs pre-push \"$@\"` to it (it needs the same standard input as the hook itself)".into()),
    })
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
        ci_workflow: host::all().iter().any(|h| h.workflows().iter().any(|(rel, _)| top.join(rel).exists())),
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
            if !c.paths.is_empty() {
                text.push_str(&format!("paths = [{}]   # required only when a change touches one of these\n", c.paths.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>().join(", ")));
            }
            if let Some(dir) = &c.dir {
                text.push_str(&format!("dir = {dir:?}   # the folder of the checked tree it runs in\n"));
            }
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

/// The template with `lock` as its one locked path, in place of the commented-out example.
fn lock_in_template(template: &str, lock: &str) -> String {
    let line = format!("locked = [\"{lock}\"]   # never changed: the CI gate, so a branch cannot change what judges it. No approval clears it, a person's bypass can");
    template.lines().map(|l| if l.starts_with("# locked = []") { line.as_str() } else { l }).collect::<Vec<_>>().join("\n") + "\n"
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

/// The hook events this version installs for Claude Code, in the order it installs them. The
/// settings below must name exactly these; a test holds them together.
pub const CLAUDE_EVENTS: &[&str] = &["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SubagentStart", "SubagentStop", "SessionEnd"];

/// The same for Codex.
pub const CODEX_EVENTS: &[&str] = &["PreToolUse", "PostToolUse", "Stop", "SubagentStart", "SubagentStop"];

/// Events this version installs that the hooks already in the repository lack, once any of 05's
/// hooks is there: what an older 05 installed. Nothing when no agent hooks are installed at all.
pub fn missing_hook_events(top: &Path) -> Vec<&'static str> {
    let installed = |agent: &str, files: &[&str], events: &[&'static str]| -> Vec<&'static str> {
        let texts: Vec<String> = files.iter().filter_map(|f| fs::read_to_string(top.join(f)).ok()).filter(|t| t.contains(AGENT_COMMAND_PREFIX)).collect();
        if texts.is_empty() {
            return Vec::new();
        }
        events.iter().copied().filter(|e| !texts.iter().any(|t| t.contains(&format!("{AGENT_COMMAND_PREFIX}{agent} {e}")))).collect()
    };
    let mut missing = installed("claude-code", &[".claude/settings.local.json", ".claude/settings.json"], CLAUDE_EVENTS);
    for e in installed("codex", &[".codex/hooks.json"], CODEX_EVENTS) {
        if !missing.contains(&e) {
            missing.push(e);
        }
    }
    missing
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
         - `use05 approve` and `use05 bypass` need the person: Touch ID or the approver passphrase, which agents do not have.\n\
         - If `use05` is missing or says it is too old, stop and ask the user to install or upgrade it. Do not install it yourself.\n\
         {BLOCK_END}\n"
    )
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

    let ci = match args.ci.as_deref().map(|name| (name, host::by_name(name))) {
        Some((other, None)) => return Report::error("init", "CI_UNSUPPORTED", format!("no CI template for {other:?} yet"), Some("use --ci github, or run `use05 gate --ci` from any CI".into()), 6),
        Some((_, Some(h))) => Some(h),
        None => None,
    };
    // The folder holding the CI workflows, locked in a policy written with them (D94).
    let lock = ci.as_ref().and_then(|h| h.workflows().first().and_then(|(rel, _)| rel.parent().map(|p| format!("{}/**", p.display()))));

    // Policy
    let policy_path = top.join(POLICY_PATH);
    use crate::cmd::setup::{AFTER_EDIT, Outcome, run_on};
    let stopped = || Report::error("init", "SETUP_STOPPED", "Setup stopped; nothing was changed.".into(), Some("run use05 init again when you are ready".into()), 1);
    let no_answer = || Report::error("init", "INIT_NO_ANSWER", crate::prompt::no_answer_message(), Some("use05 init --defaults   sets up with the usual answers and asks nothing".into()), 1);
    let mut after = Vec::new();
    if policy_path.exists() {
        let wanted = if args.interactive {
            let mut a = crate::prompt::on_stdin(crate::ui::Ui::stderr());
            match a.yes("05 is already set up here. Change your settings?", false) {
                None if a.timed_out() => return no_answer(),
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
            Ok((Outcome::NoAnswer, _)) => return no_answer(),
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
        let locked = fs::read_to_string(&policy_path).ok().and_then(|t| use05_core::policy::Policy::parse(&t).ok()).map(|p| p.protect.locked);
        if let (Some(lock), Some(locked)) = (&lock, locked) {
            if !locked.contains(lock) {
                gaps.push(format!("your policy does not lock the CI workflows, so a change could edit the gate that judges it: use05 policy add protect.locked \"{lock}\""));
            }
        }
    } else {
        let mut checks = detect_checks(&top);
        // A monorepo gets a check per package (D97). With questions, the setup offers them; without,
        // they are taken, as the other defaults are.
        if !args.interactive {
            let scan = use05_core::setup::scan_workspaces(&top);
            let per_package = use05_core::setup::workspace_checks(&top, &scan.workspaces);
            if !per_package.is_empty() {
                after.push(use05_core::setup::workspace_note(&scan.workspaces, scan.root_is_package));
                after.push(use05_core::setup::workspace_caveat().to_string());
            }
            after.extend(scan.skipped.iter().map(|n| format!("Monorepo: {n}.")));
            checks = use05_core::setup::with_workspace_checks(checks, per_package, scan.root_is_package);
        }
        let text = policy_template(&checks);
        // A branch must not be able to change the gate that judges it (D94).
        let text = match &lock {
            Some(lock) => lock_in_template(&text, lock),
            None => text,
        };
        let text = if args.interactive || args.flags.any() {
            match run_on(&text, &top, false, args.interactive, &args.flags) {
                Err(e) => return Report::error("init", "SETUP_INVALID", e, None, 6),
                Ok((Outcome::Stopped, _)) => return stopped(),
                Ok((Outcome::NoAnswer, _)) => return no_answer(),
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
    // A person at the terminal makes the approver key now, not as a separate step later (D91).
    let person = args.interactive && std::io::IsTerminal::is_terminal(&std::io::stdin()) && use05_core::tty::has_tty();
    if !keys::approver_exists() && person {
        let made = crate::cmd::approve::key_new(None, true, false, None);
        if made.code == "KEY_CREATED" {
            changed.push(format!("{} (it is how you approve; an agent cannot use it)", made.headline.replacen("Created", "created", 1)));
        } else {
            gaps.push(format!("no approver key: {}", made.headline));
        }
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
        let shown_hook = hook.strip_prefix(&top).unwrap_or(&hook).display().to_string();
        // What to write, and what to say about it; `None` leaves the hook as it is.
        let current = fs::read_to_string(&hook).ok();
        let write: Option<&str> = match &current {
            None => Some("installed the git pre-push hook (advisory: `git push --no-verify` skips it)"),
            Some(t) if t.contains(HOOK_MARK) => {
                // 05's own earlier hook, untouched since init, does not run Git LFS's: update it.
                let untouched = manifest.items.iter().any(|it| matches!(it, Item::File { path, sha256 } if *path == shown_hook && *sha256 == sha(t)));
                if untouched && !t.contains(LFS_CALL) && repo_uses_lfs(&top) {
                    Some("updated the git pre-push hook so it runs Git LFS's upload step before 05's check")
                } else {
                    kept.push("the git pre-push hook is already installed".into());
                    None
                }
            }
            // Git LFS's own hook only uploads LFS files; 05's hook now does that first, then checks.
            Some(t) if is_standard_lfs_hook(t) => Some("replaced Git LFS's own pre-push hook with 05's, which runs it first and then checks the push (`git lfs update` brings Git LFS's back after `use05 uninstall`)"),
            Some(_) => {
                gaps.push(format!("an existing pre-push hook at {} was left alone, so pushes are not checked by 05", hook.display()));
                None
            }
        };
        if let Some(said) = write {
            let script = pre_push_script();
            let written = fs::create_dir_all(hook.parent().expect("has parent")).and_then(|_| fs::write(&hook, &script));
            match written {
                Ok(()) => {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&hook, fs::Permissions::from_mode(0o755));
                    manifest.items.retain(|it| !matches!(it, Item::File { path, .. } if *path == shown_hook));
                    manifest.items.push(Item::File { path: shown_hook, sha256: sha(&script) });
                    changed.push(said.into());
                }
                Err(e) => gaps.push(format!("could not install the pre-push hook: {e}")),
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
    match &ci {
        Some(h) => {
            for (i, (rel, text)) in h.workflows().into_iter().enumerate() {
                let shown = rel.display().to_string();
                let path = top.join(&rel);
                let what = if i == 0 {
                    "the gate: it alone gets the runner key, so keep USE05_RUNNER_KEY where only it can read it (docs/turn-on-the-ci-gate.md)"
                } else {
                    "it starts the gate for every push and pull request, and gets no secret"
                };
                let current = fs::read_to_string(&path).ok();
                // A file an earlier use05 wrote and nobody changed since is brought up to date;
                // anything else that is there is left alone.
                let ours = current.as_ref().and_then(|c| manifest.items.iter().position(|it| matches!(it, Item::File { path, sha256 } if *path == shown && *sha256 == sha(c))));
                if current.as_deref() == Some(text.as_str()) || (current.is_some() && ours.is_none()) {
                    kept.push(format!("{shown} already exists; left as it is"));
                    continue;
                }
                match fs::create_dir_all(path.parent().expect("has parent")).and_then(|_| fs::write(&path, &text)) {
                    Ok(()) => {
                        let item = Item::File { path: shown.clone(), sha256: sha(&text) };
                        match ours {
                            Some(at) => {
                                manifest.items[at] = item;
                                changed.push(format!("replaced {shown}, which an earlier use05 wrote and nobody changed since ({what})"));
                            }
                            None => {
                                manifest.items.push(item);
                                changed.push(format!("wrote {shown} ({what})"));
                            }
                        }
                    }
                    Err(e) => gaps.push(format!("could not write the CI workflow: {e}")),
                }
            }
            for f in h.key_exposed_in(&top) {
                gaps.push(format!("{} still gives the runner key to a run the branch defines, so an agent's push can read it: delete it or remove the key from it, then rotate the key", f.display()));
            }
        }
        None => gaps.push("no merge enforcement yet: add a CI check with `use05 init --ci github`, then make it required in branch protection".into()),
    }

    if let Err(e) = save_manifest(&store, &manifest) {
        return Report::error("init", "IO_ERROR", format!("could not record what was installed: {e}"), None, 4);
    }
    // So bare `use05` can list this repository among the ones on this machine.
    if use05_core::repos::touch(&store.dirs) {
        let file = use05_core::keys::user_dir().map(|d| d.join(use05_core::repos::FILE).display().to_string()).unwrap_or_default();
        changed.push(format!("listed this repository in {file}, so bare `use05` can show every repository on this machine (it stays on this machine)"));
    }

    // The rules count at a push only once committed: offer to do it now (D91).
    if person {
        if let Some(paths) = uncommitted_setup(&top) {
            if crate::cmd::land::Then::Ask.settle(&format!("Commit the setup now ({paths})?")) {
                let list: Vec<&str> = paths.split(' ').collect();
                let added = git::run(&top, &[&["add", "--"][..], &list[..]].concat());
                match added.and_then(|_| git::run(&top, &[&["commit", "-q", "-m", "Set up 05", "--"][..], &list[..]].concat())) {
                    Ok(_) => changed.push(format!("committed {paths} as \"Set up 05\"; your first push of it asks you to approve 05's rules, once")),
                    Err(e) => gaps.push(format!("could not commit the setup: {}", e.message)),
                }
            }
        }
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
    let workflows = host::all().into_iter().flat_map(|h| h.workflows()).map(|(rel, _)| rel.display().to_string());
    let paths: Vec<String> = [".05", ".codex", "AGENTS.md", ".claude/settings.json"]
        .into_iter()
        .map(str::to_string)
        .chain(workflows)
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
                        if full.file_name().is_some_and(|n| n == "pre-push") && repo_uses_lfs(&top) {
                            rows.push(("note".into(), "this repository uses Git LFS: run `git lfs update` so pushes upload its files again".into()));
                        }
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
    if use05_core::repos::forget(&store.dirs) {
        rows.push(("removed".into(), "this repository from the list of repositories on this machine".into()));
    }
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

#[cfg(test)]
mod event_tests {
    use super::*;

    #[test]
    fn the_events_listed_are_the_events_installed() {
        let names = |v: Value| v.as_object().unwrap().keys().cloned().collect::<std::collections::BTreeSet<_>>();
        let listed = |l: &[&str]| l.iter().map(|e| e.to_string()).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names(claude_hook_json()), listed(CLAUDE_EVENTS));
        assert_eq!(names(codex_hook_json()), listed(CODEX_EVENTS));
    }

    #[test]
    fn hooks_missing_events_are_named_per_what_is_installed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(missing_hook_events(dir.path()).is_empty(), "no hooks, nothing to compare");
        let file = dir.path().join(".claude/settings.local.json");
        merge_agent_hooks(&file, &claude_hook_json(), &[]).unwrap();
        assert!(missing_hook_events(dir.path()).is_empty());
        let old = fs::read_to_string(&file).unwrap().replace("claude-code SubagentStart", "claude-code SomethingElse");
        fs::write(&file, old).unwrap();
        assert_eq!(missing_hook_events(dir.path()), ["SubagentStart"]);
    }
}
