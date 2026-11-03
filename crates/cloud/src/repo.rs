//! One repository this machine reports, and the few things the console may ask about it.
//! Every request is checked here, whatever the console says: the console may be compromised.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Result, anyhow, bail};
use base64::Engine;
use serde_json::{Value, json};
use cloud::prepared::Purpose;
use use05_core::policy::{POLICY_PATH, Policy};

use crate::{Api, note_locally};

pub struct Repo {
    pub top: String,
    pub id: String,
    pub name: String,
    pub remote: Option<String>,
    pub landing: String,
    common: PathBuf,
}

pub fn git(dir: &str, args: &[&str]) -> Result<String> {
    git_with(dir, args, &[], None)
}

fn git_with(dir: &str, args: &[&str], env: &[(&str, &str)], input: Option<&[u8]>) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir).args(args).env("GIT_TERMINAL_PROMPT", "0").stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn()?;
    if let Some(bytes) = input {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(bytes)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("git {}: {}", args.first().unwrap_or(&""), String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("failed"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The remote without credentials, so the same repository has the same id on every machine.
fn normalise(remote: &str) -> String {
    let r = remote.trim().trim_end_matches('/').trim_end_matches(".git");
    let r = match r.split_once("://") {
        Some((scheme, rest)) => format!("{scheme}://{}", rest.rsplit_once('@').map_or(rest, |(_, host)| host)),
        None => r.to_string(),
    };
    r.to_lowercase()
}

fn hex_id(text: &str) -> bool {
    (text.len() == 40 || text.len() == 64) && text.chars().all(|c| c.is_ascii_hexdigit())
}

fn temp_path(tag: &str) -> PathBuf {
    let n: u64 = rand::random();
    std::env::temp_dir().join(format!("use05-cloud-{tag}-{n:016x}"))
}

impl Repo {
    pub fn open(path: &str) -> Result<Repo> {
        let dirs = use05_core::git::dirs(Path::new(path)).map_err(|e| anyhow!(e.message))?;
        let top = dirs.top.to_string_lossy().to_string();
        let remote = git(&top, &["remote", "get-url", "origin"]).ok().filter(|r| !r.is_empty());
        let key = remote.as_deref().map(normalise).unwrap_or_else(|| top.clone());
        // An HMAC under the team's id key: the console routes by it but cannot tell which repository it is.
        let id = cloud::seal::hmac_ref(&crate::stored_id_key()?, "repo", &key);
        let name = remote.as_deref().and_then(|r| normalise(r).rsplit(['/', ':']).next().map(str::to_string)).filter(|n| !n.is_empty()).unwrap_or_else(|| Path::new(&top).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
        let landing = Policy::load_at(Path::new(&top), "HEAD").ok().flatten().and_then(|p| p.branches.target).unwrap_or_else(|| "main".into());
        Ok(Repo { top, id, name, remote, landing, common: dirs.common.canonicalize()? })
    }

    /// Is `path` inside this repository (any of its worktrees)?
    pub fn contains(&self, path: &str) -> bool {
        use05_core::git::dirs(Path::new(path)).ok().and_then(|d| d.common.canonicalize().ok()).is_some_and(|c| c == self.common)
    }

    /// The landing branch as origin has it, else as this machine has it.
    fn policy_ref(&self) -> Option<String> {
        [format!("refs/remotes/origin/{}", self.landing), format!("refs/heads/{}", self.landing), "HEAD".into()].into_iter().find(|r| git(&self.top, &["rev-parse", "--verify", "--quiet", &format!("{r}^{{commit}}")]).is_ok())
    }

    /// Whether a task's work is already in the landing branch, so nothing of it waits for a person.
    /// A finished task is its last commit; one still open is where its branch (or this checkout)
    /// is now, and only counts when nothing is left uncommitted. A task that never went past the
    /// commit it started from has no work to have landed.
    pub fn landed(&self, task: &use05_core::task::Task) -> bool {
        let Some(land) = self.policy_ref() else { return false };
        let finished = task.status == use05_core::task::Status::Finished;
        let tip = match (&task.head, finished, &task.branch) {
            (Some(h), true, _) => h.clone(),
            (_, _, Some(b)) => match git(&self.top, &["rev-parse", "--verify", "--quiet", &format!("refs/heads/{b}^{{commit}}")]) {
                Ok(t) => t,
                Err(_) => return false,
            },
            _ => match git(&self.top, &["rev-parse", "HEAD"]) {
                Ok(t) => t,
                Err(_) => return false,
            },
        };
        if task.base_commit.as_deref() == Some(tip.as_str()) {
            return false;
        }
        if !finished && git(&self.top, &["status", "--porcelain"]).map(|s| !s.is_empty()).unwrap_or(true) {
            return false;
        }
        git(&self.top, &["merge-base", "--is-ancestor", &tip, &land]).is_ok()
    }

    fn policy_at(&self, rev: &str) -> Result<(String, Policy)> {
        let text = git(&self.top, &["show", &format!("{rev}:{POLICY_PATH}")]).unwrap_or_default();
        let policy = Policy::parse(&text).map_err(|e| anyhow!(e.message))?;
        Ok((text, policy))
    }

    pub fn describe(&self) -> Value {
        let rev = self.policy_ref();
        let (text, commit) = match &rev {
            Some(r) => (git(&self.top, &["show", &format!("{r}:{POLICY_PATH}")]).ok(), git(&self.top, &["rev-parse", r]).ok()),
            None => (None, None),
        };
        let detected: Vec<Value> = use05_core::policy::detect_checks(Path::new(&self.top)).iter().map(|c| json!({ "name": c.name, "run": c.run, "timeout_secs": c.timeout_secs, "required": c.required, "env": c.env })).collect();
        json!({ "id": self.id, "name": self.name, "remote": self.remote.as_deref().map(normalise), "landing": self.landing, "policy_toml": text, "policy_rev": commit, "detected_checks": detected })
    }

    /// File and folder names only, from the landing branch.
    pub fn send_tree(&self, api: &Api) -> Result<()> {
        let rev = self.policy_ref().ok_or_else(|| anyhow!("no commit yet"))?;
        let listing = git(&self.top, &["ls-tree", "-r", "--name-only", &rev])?;
        let paths: Vec<&str> = listing.lines().take(50_000).collect();
        api.record("tree", &self.id, "", json!({ "paths": paths }))?;
        Ok(())
    }

    fn use05(&self, api: &Api, cwd: &str, args: &[&str]) -> Result<(i32, Value)> {
        let out = Command::new(&api.c.use05).args(args).current_dir(cwd).stdin(Stdio::null()).output()?;
        let v: Value = serde_json::from_slice(&out.stdout).map_err(|_| anyhow!("use05 {} gave no answer: {}", args[0], String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("")))?;
        Ok((out.status.code().unwrap_or(1), v))
    }

    /// 05 says a task waits for a person: have the installed use05 prepare the exact statement.
    /// With `reject`, the person's reason: the statement prepared is a rejection for their passkey to sign.
    pub fn ask_for_approval(&self, api: &Api, task: &str, scope: &str, tree: Option<&str>, cwd: &str, reject: Option<&str>) -> Result<()> {
        let mut args = vec!["approve", "--task", task, "--unsigned", "--json"];
        if scope == "intent" {
            args.push("--intent");
        } else if let Some(t) = tree.filter(|t| hex_id(t)) {
            args.extend(["--tree", t]);
        }
        if let Some(reason) = reject {
            args.extend(["--reject", "--reason", reason]);
        }
        let dir = if self.contains(cwd) { cwd } else { &self.top };
        let (code, v) = self.use05(api, dir, &args)?;
        if code != 0 {
            bail!("{}", v["message"].as_str().unwrap_or("05 could not prepare the approval"));
        }
        let d = &v["details"];
        crate::prepared()?.remember(&self.id, Purpose::Approval, d["payload"].as_str().unwrap_or_default())?;
        // Sealed to the team: the console knows only that this repository asks for something.
        let kind = if reject.is_some() { "|reject" } else { "" };
        let reference = cloud::seal::hmac_ref(&crate::stored_id_key()?, "approval", &format!("{task}|{}|{}{kind}", d["scope"].as_str().unwrap_or(""), d["tree"].as_str().unwrap_or("")));
        let body = json!({ "task": task, "scope": d["scope"], "tree": d["tree"], "unsigned": d });
        let (sealed, sig) = api.sealed("approval", &self.id, &reference, &body)?;
        api.post("/approval", json!({ "repo": self.id, "ref": reference, "sealed": sealed, "sig": sig }))?;
        Ok(())
    }

    /// The driver typed a testing note on their phone (D87): prepare the statement for their
    /// passkey, co-signed here, as the terminal command would print it unsigned.
    fn prepare_testing(&self, api: &Api, payload: &Value) -> Result<Value> {
        let tree = payload["tree"].as_str().filter(|t| hex_id(t)).ok_or_else(|| anyhow!("no tree to sign off"))?;
        let note = payload["note"].as_str().map(str::trim).filter(|n| !n.is_empty()).ok_or_else(|| anyhow!("no note"))?;
        let skipped = payload["outcome"] == "skipped";
        let mut args = vec!["approve", if skipped { "--skip-testing" } else { "--tested" }, if skipped { "--reason" } else { "--note" }, note, "--tree", tree, "--unsigned", "--json"];
        if let Some(task) = payload["task"].as_str().filter(|t| !t.is_empty() && *t != "-") {
            args.extend(["--task", task]);
        }
        let (code, v) = self.use05(api, &self.top, &args)?;
        if code != 0 {
            bail!("{}", v["message"].as_str().unwrap_or("05 could not prepare the sign-off"));
        }
        let d = &v["details"];
        crate::prepared()?.remember(&self.id, Purpose::Testing, d["payload"].as_str().unwrap_or_default())?;
        Ok(json!({ "unsigned": d }))
    }

    /// The person asks, from the console, to throw a task's work away (D89): what would go, and what
    /// would be lost, in a statement this machine co-signs and remembers for their passkey to sign.
    fn prepare_discard(&self, api: &Api, payload: &Value) -> Result<Value> {
        let task = payload["task"].as_str().filter(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric())).ok_or_else(|| anyhow!("no task to discard"))?;
        let (code, v) = self.use05(api, &self.top, &["discard", task, "--unsigned", "--json"])?;
        if code != 0 {
            bail!("{}", v["message"].as_str().unwrap_or("05 could not prepare the discard"));
        }
        let d = &v["details"];
        crate::prepared()?.remember(&self.id, Purpose::Discard, d["payload"].as_str().unwrap_or_default())?;
        Ok(json!({ "unsigned": d, "plan": d["plan"], "rows": d["rows"] }))
    }

    /// Discard as the person signed: only a statement this machine prepared, and 05 checks the
    /// passkey and that the work has not moved since.
    fn discard(&self, api: &Api, envelope: &Value) -> Result<Value> {
        let payload = envelope["payload"].as_str().unwrap_or_default();
        let prepared = crate::prepared()?;
        if !prepared.knows(&self.id, Purpose::Discard, payload) {
            return Err(self.refuse(api, "a discard", "this machine did not prepare what was signed, or did it already"));
        }
        let path = temp_path("discard").with_extension("json");
        std::fs::write(&path, serde_json::to_vec(envelope)?)?;
        let file = path.to_string_lossy().to_string();
        let result = self.use05(api, &self.top, &["discard", "--signed", file.as_str(), "--json"]);
        let _ = std::fs::remove_file(&path);
        let (code, v) = result?;
        if code != 0 {
            let why = v["message"].as_str().unwrap_or("05 refused it").to_string();
            if v["code"] == "DISCARD_NOT_TRUSTED" {
                return Err(self.refuse(api, "a discard", &why));
            }
            bail!("{why}");
        }
        prepared.forget(&self.id, Purpose::Discard, payload)?;
        Ok(json!({ "code": v["code"], "branch": v["details"]["branch"], "worktree": v["details"]["worktree"], "remote": v["details"]["remote"], "notes": v["notes"] }))
    }

    /// CI holds this tree for a person (D86): prepare the approval for them, co-signed by the
    /// runner key, and ask on the console. Nothing is remembered: the co-signature is the proof.
    pub fn ask_from_ci(&self, api: &Api, task: &str, tree: &str, person: &str) -> Result<()> {
        if !hex_id(tree) {
            bail!("no tree to ask about");
        }
        let mut args = vec!["approve", "--unsigned", "--tree", tree, "--approver", person, "--json"];
        if task != "-" && !task.is_empty() {
            args.extend(["--task", task]);
        }
        let (code, v) = self.use05(api, &self.top, &args)?;
        if code != 0 {
            bail!("{}", v["message"].as_str().unwrap_or("05 could not prepare the approval"));
        }
        let d = &v["details"];
        let reference = cloud::seal::hmac_ref(&crate::stored_id_key()?, "approval", &format!("{task}|{}|{}", d["scope"].as_str().unwrap_or(""), d["tree"].as_str().unwrap_or("")));
        let body = json!({ "task": task, "scope": d["scope"], "tree": d["tree"], "unsigned": d, "from": "ci" });
        let (sealed, sig) = api.sealed("approval", &self.id, &reference, &body)?;
        api.post("/approval", json!({ "repo": self.id, "ref": reference, "sealed": sealed, "sig": sig }))?;
        Ok(())
    }

    /// File an envelope a caller already checked (CI: the runner key co-signed it), and push it.
    pub fn file_signed(&self, api: &Api, envelope: &[u8]) -> Result<Value> {
        let path = temp_path("approval").with_extension("json");
        std::fs::write(&path, envelope)?;
        let file = path.to_string_lossy().to_string();
        let result = self.use05(api, &self.top, &["approve", "--signed", file.as_str(), "--push", "--json"]);
        let _ = std::fs::remove_file(&path);
        let (code, v) = result?;
        if code != 0 {
            bail!("{}", v["message"].as_str().unwrap_or("05 refused it"));
        }
        Ok(json!({ "code": v["code"], "counts": v["details"]["counts"], "void": v["details"]["void"], "branch": v["details"]["branch"] }))
    }

    fn refuse(&self, api: &Api, what: &str, why: &str) -> anyhow::Error {
        note_locally(&format!("{}: refused {what}: {why}", self.name));
        let reference = hex::encode(rand::random::<[u8; 16]>());
        let _ = api.record("refusal", &self.id, &reference, json!({ "what": format!("{what} in {}", self.name), "why": why }));
        anyhow!("refused: {why}")
    }

    /// File a signed approval, but only of a statement this machine prepared for this purpose.
    fn file(&self, api: &Api, envelope: &Value, purpose: Purpose, push: bool) -> Result<Value> {
        self.file_in(api, &self.top, envelope, purpose, push)
    }

    /// [`Repo::file`], judged by the rules in `dir`: a checkout of origin's tip for a policy
    /// edit, so a machine whose own checkout is behind still counts it as the gate will.
    fn file_in(&self, api: &Api, dir: &str, envelope: &Value, purpose: Purpose, push: bool) -> Result<Value> {
        let payload = envelope["payload"].as_str().unwrap_or_default();
        let prepared = crate::prepared()?;
        if !prepared.knows(&self.id, purpose, payload) {
            return Err(self.refuse(api, "an approval", "this machine did not prepare what was signed, or already filed it"));
        }
        let path = temp_path("approval").with_extension("json");
        std::fs::write(&path, serde_json::to_vec(envelope)?)?;
        let file = path.to_string_lossy().to_string();
        let mut args = vec!["approve", "--signed", file.as_str(), "--json"];
        if push {
            args.push("--push");
        }
        let result = self.use05(api, dir, &args);
        let _ = std::fs::remove_file(&path);
        let (code, v) = result?;
        if code != 0 {
            let why = v["message"].as_str().unwrap_or("05 refused it").to_string();
            if v["code"] == "APPROVAL_NOT_TRUSTED" {
                return Err(self.refuse(api, "an approval", &format!("{why} (pin your passkey here: use05 cloud enrol)")));
            }
            bail!("{why}");
        }
        prepared.forget(&self.id, purpose, payload)?;
        Ok(json!({ "code": v["code"], "counts": v["details"]["counts"], "void": v["details"]["void"], "branch": v["details"]["branch"], "notes": v["notes"] }))
    }

    fn fetch_landing(&self) -> Result<String> {
        if self.remote.is_none() {
            bail!("this repository has no origin remote to land the edit on");
        }
        git(&self.top, &["fetch", "--quiet", "origin", &format!("+refs/heads/{0}:refs/remotes/origin/{0}", self.landing)])?;
        git(&self.top, &["rev-parse", &format!("refs/remotes/origin/{}^{{commit}}", self.landing)])
    }

    /// Build the edit as a commit on origin's tip, check it, and have use05 prepare its approval.
    fn prepare(&self, api: &Api, toml: &str) -> Result<Value> {
        let base = self.fetch_landing()?;
        let (_, old) = self.policy_at(&base)?;
        let new = Policy::parse(toml).map_err(|e| anyhow!(e.message))?;
        let detected = use05_core::policy::detect_checks(Path::new(&self.top));
        let bad = cloud::guard::terminal_only(&old, &new, &detected);
        if !bad.is_empty() {
            return Err(self.refuse(api, "a policy edit", &format!("it changes what only a terminal may change: {}", bad.join(", "))));
        }
        let looser = cloud::guard::loosens(&old, &new);
        if !looser.is_empty() {
            return Err(self.refuse(api, "a policy edit", &format!("it loosens what only a terminal may loosen: {}", looser.join(", "))));
        }
        let changed = cloud::guard::changed(&old, &new);
        let index = temp_path("index");
        let index_s = index.to_string_lossy().to_string();
        let env = [("GIT_INDEX_FILE", index_s.as_str())];
        let commit = (|| -> Result<String> {
            git_with(&self.top, &["read-tree", &base], &env, None)?;
            let blob = git_with(&self.top, &["hash-object", "-w", "--stdin"], &[], Some(toml.as_bytes()))?;
            git_with(&self.top, &["update-index", "--add", "--cacheinfo", &format!("100644,{blob},{POLICY_PATH}")], &env, None)?;
            let tree = git_with(&self.top, &["write-tree"], &env, None)?;
            let name = git(&self.top, &["config", "user.name"]).unwrap_or_else(|_| "05 console".into());
            let email = git(&self.top, &["config", "user.email"]).unwrap_or_else(|_| "console@use05.dev".into());
            let who = [("GIT_AUTHOR_NAME", name.as_str()), ("GIT_AUTHOR_EMAIL", email.as_str()), ("GIT_COMMITTER_NAME", name.as_str()), ("GIT_COMMITTER_EMAIL", email.as_str())];
            let message = format!("policy: edit from the 05 console\n\nChanged: {}\n", changed.join(", "));
            git_with(&self.top, &["commit-tree", &tree, "-p", &base, "-m", &message], &who, None)
        })();
        let _ = std::fs::remove_file(&index);
        let commit = commit?;
        // Prepare the approval where the rules in force are origin's, as the push gate reads them.
        let wt = temp_path("worktree");
        let wt_s = wt.to_string_lossy().to_string();
        git(&self.top, &["worktree", "add", "--detach", "--quiet", &wt_s, &base])?;
        let prepared = self.use05(api, &wt_s, &["approve", "--unsigned", "--tree", &commit, "--reason", "policy edit from the 05 console", "--json"]);
        let _ = git(&self.top, &["worktree", "remove", "--force", &wt_s]);
        let (code, v) = prepared?;
        if code != 0 {
            bail!("{}", v["message"].as_str().unwrap_or("05 could not prepare the approval"));
        }
        crate::prepared()?.remember(&self.id, Purpose::PolicyEdit, v["details"]["payload"].as_str().unwrap_or_default())?;
        Ok(json!({ "commit": commit, "base": base, "changed": changed, "toml": toml, "unsigned": v["details"] }))
    }

    /// Re-check everything about the prepared commit, file the signed approval, and push.
    fn apply(&self, api: &Api, envelope: &Value, commit: &str, base: &str) -> Result<Value> {
        if !hex_id(commit) || !hex_id(base) {
            return Err(self.refuse(api, "a policy edit", "the commit ids are not commit ids"));
        }
        let now = self.fetch_landing()?;
        if now != base {
            bail!("origin's {} moved since the edit was prepared; save it again", self.landing);
        }
        let parents = git(&self.top, &["rev-list", "--parents", "-n", "1", commit])?;
        if parents.split_whitespace().skip(1).collect::<Vec<_>>() != [base] {
            return Err(self.refuse(api, "a policy edit", "the commit is not the one prepared on origin's tip"));
        }
        if git(&self.top, &["diff", "--name-only", base, commit])? != POLICY_PATH {
            return Err(self.refuse(api, "a policy edit", "the commit changes more than the policy file"));
        }
        let (_, old) = self.policy_at(base)?;
        let (_, new) = self.policy_at(commit)?;
        let bad = cloud::guard::terminal_only(&old, &new, &use05_core::policy::detect_checks(Path::new(&self.top)));
        if !bad.is_empty() {
            return Err(self.refuse(api, "a policy edit", &format!("it changes what only a terminal may change: {}", bad.join(", "))));
        }
        let looser = cloud::guard::loosens(&old, &new);
        if !looser.is_empty() {
            return Err(self.refuse(api, "a policy edit", &format!("it loosens what only a terminal may loosen: {}", looser.join(", "))));
        }
        let tree = git(&self.top, &["rev-parse", &format!("{commit}^{{tree}}")])?;
        let statement: Value = envelope["payload"].as_str().and_then(|p| base64::engine::general_purpose::STANDARD.decode(p).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        if statement["subject"][0]["digest"]["gitTree"] != tree.as_str() {
            return Err(self.refuse(api, "a policy edit", "the signed approval is for something else"));
        }
        // File it where the rules in force are origin's, as the approval was prepared.
        let wt = temp_path("worktree");
        let wt_s = wt.to_string_lossy().to_string();
        git(&self.top, &["worktree", "add", "--detach", "--quiet", &wt_s, base])?;
        let filed = self.file_in(api, &wt_s, envelope, Purpose::PolicyEdit, true);
        let _ = git(&self.top, &["worktree", "remove", "--force", &wt_s]);
        let filed = filed?;
        // Push only what the gate will count: an approval, not void.
        if filed["code"] != "APPROVED" || filed["counts"] != true {
            bail!("the signed approval will not count ({}); save the edit again", filed["void"].as_str().unwrap_or("it is not an approval"));
        }
        git(&self.top, &["push", "--quiet", "origin", &format!("{commit}:refs/heads/{}", self.landing)])?;
        Ok(json!({ "pushed": true, "approval": filed, "local": self.catch_up(base, commit) }))
    }

    /// Move this machine's landing branch to the edit when nothing would be lost.
    fn catch_up(&self, base: &str, commit: &str) -> &'static str {
        let branch = format!("refs/heads/{}", self.landing);
        let listing = git(&self.top, &["worktree", "list", "--porcelain"]).unwrap_or_default();
        let checked_out = listing.split("\n\n").find(|w| w.lines().any(|l| l == format!("branch {branch}"))).and_then(|w| w.lines().next()).and_then(|l| l.strip_prefix("worktree ")).map(str::to_string);
        let local = git(&self.top, &["rev-parse", "--verify", "--quiet", &branch]).ok();
        if local.as_deref().is_some_and(|l| l != base) {
            return "left: this machine's branch has commits of its own; pull when ready";
        }
        match checked_out {
            None => {
                if git(&self.top, &["update-ref", &branch, commit, local.as_deref().unwrap_or("")]).is_ok() { "updated" } else { "left" }
            }
            Some(dir) => {
                if git(&dir, &["status", "--porcelain"]).is_ok_and(|s| s.is_empty()) && git(&dir, &["merge", "--ff-only", "--quiet", commit]).is_ok() {
                    "updated"
                } else {
                    "left: the branch is checked out with changes; pull when ready"
                }
            }
        }
    }
}

fn find(api: &Api, id: &str) -> Result<Repo> {
    api.c.repos.iter().filter_map(|p| Repo::open(p).ok()).find(|r| r.id == id).ok_or_else(|| {
        note_locally(&format!("refused a request for a repository this machine does not report ({id})"));
        anyhow!("this machine does not report that repository")
    })
}

/// The only things the console can ask for. Anything else is refused.
pub fn handle(api: &Api, kind: &str, payload: &Value) -> Result<Value> {
    let repo = find(api, payload["repo"].as_str().unwrap_or(""))?;
    match kind {
        "send_tree" => repo.send_tree(api).map(|_| json!({})),
        "file_approval" => {
            let filed = repo.file(api, &payload["envelope"], Purpose::Approval, false);
            // The approval changes the task's verdict without touching the task: report it again.
            if filed.is_ok() {
                let _ = crate::report::send_repo(api, &repo, true);
            }
            filed
        }
        "prepare_policy_edit" => repo.prepare(api, payload["toml"].as_str().ok_or_else(|| anyhow!("no policy"))?),
        "prepare_testing" => repo.prepare_testing(api, payload),
        "file_testing" => repo.file(api, &payload["envelope"], Purpose::Testing, false),
        "ask_approval" => {
            let task = payload["task"].as_str().filter(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric())).ok_or_else(|| anyhow!("no task to ask about"))?;
            let scope = if payload["scope"] == "intent" { "intent" } else { "outcome" };
            let reject = payload["reject"].as_bool().unwrap_or(false);
            let reason = payload["reason"].as_str().map(str::trim).filter(|r| !r.is_empty());
            if reject && reason.is_none() {
                bail!("say why you are rejecting it");
            }
            repo.ask_for_approval(api, task, scope, None, &repo.top, reason.filter(|_| reject)).map(|_| json!({}))
        }
        "prepare_discard" => repo.prepare_discard(api, payload),
        "discard" => {
            let done = repo.discard(api, &payload["envelope"]);
            // The task is gone from here: say so to the console now.
            if done.is_ok() {
                let _ = crate::report::send_repo(api, &repo, true);
            }
            done
        }
        "apply_policy_edit" => repo.apply(api, &payload["envelope"], payload["commit"].as_str().unwrap_or(""), payload["base"].as_str().unwrap_or("")),
        other => Err(repo.refuse(api, &format!("an unknown request ({})", other.chars().take(40).collect::<String>()), "it is not one of the things the console may ask")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(dir: &str, args: &[&str]) -> String {
        git(dir, args).unwrap_or_else(|e| panic!("git {args:?}: {e}"))
    }

    fn task(base: &str, status: &str, head: Option<&str>) -> use05_core::task::Task {
        serde_json::from_value(json!({
            "id": "t1", "title": "x", "author": "agent:claude-code", "created": "2026-11-01T00:00:00Z",
            "base_commit": base, "base_tree": "", "status": status, "head": head,
        }))
        .unwrap()
    }

    #[test]
    fn work_counts_as_landed_only_once_the_landing_branch_has_it_and_nothing_is_left_over() {
        let dir = tempfile::tempdir().unwrap();
        let top = std::fs::canonicalize(dir.path()).unwrap().to_string_lossy().to_string();
        run(&top, &["init", "-q", "-b", "main"]);
        run(&top, &["config", "user.name", "t"]);
        run(&top, &["config", "user.email", "t@t"]);
        std::fs::write(dir.path().join("a"), "1").unwrap();
        run(&top, &["add", "-A"]);
        run(&top, &["commit", "-q", "-m", "a"]);
        let a = run(&top, &["rev-parse", "HEAD"]);
        run(&top, &["update-ref", "refs/remotes/origin/main", &a]);
        let repo = Repo { top: top.clone(), id: "r".into(), name: "r".into(), remote: None, landing: "main".into(), common: std::path::PathBuf::from(&top) };

        let open = task(&a, "active", None);
        assert!(!repo.landed(&open), "nothing was done past where it started");

        std::fs::write(dir.path().join("b"), "2").unwrap();
        run(&top, &["add", "-A"]);
        run(&top, &["commit", "-q", "-m", "b"]);
        let b = run(&top, &["rev-parse", "HEAD"]);
        assert!(!repo.landed(&open), "committed here, not on the landing branch yet");

        run(&top, &["update-ref", "refs/remotes/origin/main", &b]);
        assert!(repo.landed(&open), "pushed, and nothing left over");

        std::fs::write(dir.path().join("c"), "3").unwrap();
        assert!(!repo.landed(&open), "an open task with uncommitted work is not done");
        assert!(repo.landed(&task(&a, "finished", Some(&b))), "a finished task is its last commit");
        assert!(!repo.landed(&task(&a, "finished", Some(&a))), "finished with nothing new");
    }
}
