//! The GitHub adapter: GitHub Actions' environment, the statuses API and the workflows `init --ci
//! github` writes. Everything in the CLI that is GitHub-specific is here.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{CiEvent, EventKind, Host, PushRemote, Verdict};

type Env = Box<dyn Fn(&str) -> Option<String>>;

pub struct GitHub {
    env: Env,
}

pub fn new() -> Box<dyn Host> {
    Box::new(GitHub { env: Box::new(|k| std::env::var(k).ok().filter(|v| !v.is_empty())) })
}

impl GitHub {
    fn var(&self, k: &str) -> Option<String> {
        (self.env)(k)
    }

    /// The webhook payload Actions leaves on disk for the run.
    fn payload(&self) -> serde_json::Value {
        self.var("GITHUB_EVENT_PATH").and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }
}

fn kind_of(name: &str) -> EventKind {
    match name {
        "push" => EventKind::Push,
        "pull_request" | "pull_request_target" => EventKind::PullRequest,
        "merge_group" => EventKind::MergeGroup,
        "workflow_run" => EventKind::WorkflowRun,
        _ => EventKind::Other,
    }
}

fn text(v: &serde_json::Value) -> Option<String> {
    v.as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

/// A merge queue's branch is `gh-readonly-queue/<base>/pr-<n>-<sha>`; the base may hold slashes.
fn queue_base(branch: &str) -> Option<String> {
    branch.strip_prefix("gh-readonly-queue/")?.rsplit_once("/pr-").map(|(base, _)| base.to_string())
}

/// The run the 05 workflow made, which started this one. Its definition is the default branch's,
/// so everything about the change comes from the event, never from this run's own `GITHUB_SHA`
/// or `GITHUB_REF` (the default branch's).
fn workflow_run(event: &serde_json::Value) -> CiEvent {
    let run = &event["workflow_run"];
    let triggered_by = text(&run["event"]).map(|e| kind_of(&e));
    let head_branch = text(&run["head_branch"]);
    // GitHub names the pull requests of the same repository only; a fork's are left out.
    let head_repo = text(&run["head_repository"]["full_name"]);
    let fork = head_repo.clone().filter(|head| text(&event["repository"]["full_name"]).as_ref() != Some(head));
    let pr_base = text(&run["pull_requests"][0]["base"]["ref"]);
    // A pull request's run that names no pull request (closed, or its head moved on) or no head
    // repository (a deleted fork) cannot say where the change goes.
    let unplaced = triggered_by == Some(EventKind::PullRequest) && (pr_base.is_none() || head_repo.is_none());
    let base_branch = pr_base.or_else(|| head_branch.as_deref().filter(|_| triggered_by == Some(EventKind::MergeGroup)).and_then(queue_base));
    CiEvent {
        kind: EventKind::WorkflowRun,
        // It goes to `git fetch` and into the statuses address: a commit id, or nothing.
        head_sha: text(&run["head_sha"]).filter(|s| s.chars().all(|c| c.is_ascii_hexdigit())).unwrap_or_default(),
        // A fork's branch name is a name in another repository, and an unplaced pull request's
        // is the agent's own branch: neither says where the change goes here, so the gate holds
        // it as if it went to the landing branch.
        branch: head_branch.filter(|_| fork.is_none() && !unplaced).unwrap_or_default(),
        base_branch,
        triggered_by,
        default_branch: text(&event["repository"]["default_branch"]),
        fork,
    }
}

impl Host for GitHub {
    fn name(&self) -> &'static str {
        "github"
    }

    /// A pull request's base, a merge queue's base (its own branch is named for the queue), else
    /// the branch pushed.
    fn event(&self) -> CiEvent {
        let event = self.payload();
        let kind = self.var("GITHUB_EVENT_NAME").map(|n| kind_of(&n)).unwrap_or(EventKind::Other);
        if kind == EventKind::WorkflowRun {
            return workflow_run(&event);
        }
        let queued = text(&event["merge_group"]["base_ref"]).filter(|_| kind == EventKind::MergeGroup).map(|r| r.strip_prefix("refs/heads/").unwrap_or(&r).to_string());
        let base_branch = self.var("GITHUB_BASE_REF").or(queued);
        let branch = match kind {
            EventKind::PullRequest => self.var("GITHUB_HEAD_REF"),
            _ => self.var("GITHUB_REF_NAME").filter(|_| self.var("GITHUB_REF_TYPE").as_deref() == Some("branch")),
        };
        let head_sha = match kind {
            EventKind::PullRequest => text(&event["pull_request"]["head"]["sha"]),
            EventKind::MergeGroup => text(&event["merge_group"]["head_sha"]),
            _ => None,
        }
        .or_else(|| self.var("GITHUB_SHA"))
        .unwrap_or_default();
        CiEvent { kind, head_sha, branch: branch.unwrap_or_default(), base_branch, triggered_by: None, default_branch: text(&event["repository"]["default_branch"]), fork: None }
    }

    /// The token comes by name (`USE05_PUSH_TOKEN`), never from `.git/config`, so the code under
    /// test cannot find it there. git gets it as a header set only in its own environment, scoped
    /// to the server, as actions/checkout does.
    fn push_remote(&self) -> Option<PushRemote> {
        let (token, repo) = (self.var("USE05_PUSH_TOKEN")?, self.var("GITHUB_REPOSITORY")?);
        let server = self.var("GITHUB_SERVER_URL").unwrap_or_else(|| "https://github.com".into());
        let server = format!("https://{}", server.trim_start_matches("https://").trim_end_matches('/'));
        let basic = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("x-access-token:{token}"));
        let envs = vec![
            ("GIT_CONFIG_COUNT".to_string(), "1".to_string()),
            ("GIT_CONFIG_KEY_0".to_string(), format!("http.{server}/.extraheader")),
            ("GIT_CONFIG_VALUE_0".to_string(), format!("AUTHORIZATION: basic {basic}")),
        ];
        Some(PushRemote { url: format!("{server}/{repo}.git"), token, envs })
    }

    fn status_from_app(&self) -> bool {
        self.var("USE05_STATUS_TOKEN").is_some()
    }

    /// `USE05_STATUS_TOKEN`, else the push token, else `GITHUB_TOKEN`: the workflow's own token
    /// with `statuses: write`. `GITHUB_API_URL` is the API (GitHub Enterprise sets it).
    fn post_status(&self, sha: &str, state: Verdict, description: &str) -> Result<(), String> {
        let token = ["USE05_STATUS_TOKEN", "USE05_PUSH_TOKEN", "GITHUB_TOKEN"].iter().find_map(|k| self.var(k));
        let (token, repo) = match (token, self.var("GITHUB_REPOSITORY")) {
            (Some(t), Some(r)) => (t, r),
            _ => return Err("no token or repository to post the status with".into()),
        };
        let api = self.var("GITHUB_API_URL").unwrap_or_else(|| "https://api.github.com".into());
        let url = format!("{}/repos/{repo}/statuses/{sha}", api.trim_end_matches('/'));
        // The token and body go to curl on stdin, so neither shows in the process list.
        let mut curl = Command::new("curl")
            .args(["--silent", "--show-error", "--fail", "--max-time", "30", "--config", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("could not run curl: {e}"))?;
        let config = curl_config(&url, &token, &status_body(state, description));
        curl.stdin.take().expect("piped").write_all(config.as_bytes()).map_err(|e| e.to_string())?;
        let out = curl.wait_with_output().map_err(|e| e.to_string())?;
        if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).trim().replace(&token, "***")) }
    }

    fn summary(&self, markdown: &str) {
        if let Some(path) = self.var("GITHUB_STEP_SUMMARY") {
            let _ = std::fs::OpenOptions::new().create(true).append(true).open(path).and_then(|mut f| f.write_all(markdown.as_bytes()));
        }
    }

    fn workflows(&self) -> Vec<(PathBuf, String)> {
        vec![(PathBuf::from(".github/workflows/05-gate.yml"), GATE_WORKFLOW.to_string()), (PathBuf::from(".github/workflows/05.yml"), EVENT_WORKFLOW.to_string())]
    }

    fn key_exposed_in(&self, top: &Path) -> Vec<PathBuf> {
        let dir = top.join(".github/workflows");
        let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
            .filter(|p| std::fs::read_to_string(p).is_ok_and(|t| names_the_key(&t) && triggers(&t).iter().any(|e| kind_of(e).branch_defined())))
            .map(|p| p.strip_prefix(top).map(Path::to_path_buf).unwrap_or(p))
            .collect();
        found.sort();
        found
    }

    fn key_custody(&self) -> Vec<&'static str> {
        vec![
            "keep USE05_RUNNER_KEY only as a secret of the `use05` environment, whose deployment branches are the default branch alone, and delete any repository or organisation secret of that name. A private repository needs GitHub Pro, Team or Enterprise for that; without it the key is a repository secret any branch's workflow can read. 05 cannot read these settings from here: check them on GitHub, in Settings, Environments and Secrets",
            "post the `05` status with your own GitHub App (USE05_APP_CLIENT_ID and USE05_APP_PRIVATE_KEY) and require it from that app: with the workflow token a branch can forge the `05` status, and only the signed receipts hold (use05 land, use05 verify, the brief)",
        ]
    }
}

/// Whether a workflow file reaches the runner key: by name in any of the expression's spellings
/// (names are not case-sensitive there), or every secret at once. Backslashes are dropped first,
/// for the quotes a YAML double-quoted string escapes.
fn names_the_key(text: &str) -> bool {
    let t = text.to_ascii_lowercase().replace('\\', "");
    ["secrets.use05_runner_key", "secrets['use05_runner_key']", "secrets[\"use05_runner_key\"]", "tojson(secrets)"].iter().any(|s| t.contains(s))
}

/// The events a workflow file starts on, from its top-level `on:` key, without a YAML parser:
/// the inline form (`on: push`, `on: [push, pull_request]`) and the block form. Comments are
/// left out. (A YAML 1.1 reader takes the key `on` for `true`, so that spelling counts too.)
fn triggers(text: &str) -> Vec<String> {
    let code = |l: &str| if l.trim_start().starts_with('#') { "" } else { l.split(" #").next().unwrap_or_default() }.to_string();
    let mut lines = text.lines();
    let mut section = String::new();
    while let Some(line) = lines.next() {
        let Some(rest) = ["on:", "\"on\":", "'on':", "true:"].iter().find_map(|k| line.trim_end().strip_prefix(k)) else { continue };
        section.push_str(&code(rest));
        for l in lines.by_ref() {
            // The next top-level key ends it.
            if !l.trim().is_empty() && !l.starts_with([' ', '\t', '#']) {
                break;
            }
            section.push('\n');
            section.push_str(&code(l));
        }
        break;
    }
    section.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).filter(|w| !w.is_empty()).map(str::to_string).collect()
}

fn status_body(state: Verdict, description: &str) -> String {
    let state = match state {
        Verdict::Pending => "pending",
        Verdict::Success => "success",
        Verdict::Failure => "failure",
    };
    // GitHub refuses a description over 140 characters.
    let description: String = description.chars().take(140).collect();
    serde_json::json!({ "state": state, "context": "05", "description": description }).to_string()
}

/// A curl config file: the request, with the token and body inside quotes curl unescapes.
fn curl_config(url: &str, token: &str, body: &str) -> String {
    let q = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "url = \"{}\"\nrequest = \"POST\"\nheader = \"Authorization: Bearer {}\"\nheader = \"Accept: application/vnd.github+json\"\nheader = \"Content-Type: application/json\"\ndata = \"{}\"\n",
        q(url),
        q(token),
        q(body)
    )
}

/// Runs on every pushed branch and pull request, from the branch's own copy, so it is given
/// nothing: no secret, a read-only token. Its only job is to start the gate.
const EVENT_WORKFLOW: &str = r#"name: "05"   # quoted: YAML reads a bare 05 as the number 5, and 05-gate.yml waits for "05"

# Starts the 05 gate (05-gate.yml) for every pushed branch, pull request and merge queue.
# This file runs from the branch's own copy, which the branch can change, so it holds no
# secret, asks only for a read-only token and runs nothing of the change. The gate runs when
# this finishes and posts the commit status `05`. 05's own receipts branches are not changes.
on:
  pull_request:
  push:
    branches-ignore: ["05-receipts/**"]
  merge_group:

permissions:
  contents: read

jobs:
  start-gate:
    runs-on: ubuntu-latest
    steps:
      - run: echo "05 gates $GITHUB_SHA ($GITHUB_EVENT_NAME) when this finishes; see the 05 status"
"#;

/// Runs when the 05 workflow finishes, from the default branch's copy, which a branch cannot
/// change. It alone gets the runner key.
const GATE_WORKFLOW: &str = r#"name: 05 gate

# GitHub runs this from the default branch's copy of this file when the 05 workflow finishes,
# so a branch cannot change what runs here. It alone gets the runner key, from the `use05`
# environment, which only the default branch may use. It checks out the exact commit the 05
# workflow ran for, runs the change's checks as another user that cannot read the key, and
# posts the verdict as the commit status `05` on that commit. Require `05` in branch protection.
on:
  workflow_run:
    workflows: ["05"]
    types: [completed]

# contents: the runner pushes its own receipts branch (05-receipts/<runner key>), so what it
# sealed outlives the job; nothing else is pushed. statuses: the `05` verdict.
permissions:
  contents: write
  statuses: write

jobs:
  gate:
    runs-on: ubuntu-latest
    environment: use05
    # Everything up to the checkout runs as the key holder, with sudo, before anything of the
    # change is on disk. Keep it that way: nothing of the change may run before the gate.
    steps:
      # The change's checks run as this user: it cannot read the runner key or 05's process,
      # and it may not leave a job behind for later.
      - name: Make the check user
        run: |
          sudo useradd --create-home --shell /bin/bash use05-check
          echo use05-check | sudo tee -a /etc/cron.deny /etc/at.deny >/dev/null

      # PLACEHOLDER: install the toolchains your checks need here, system-wide, with versions
      # pinned in this file, never read from the change's files. They run as use05-check,
      # which cannot read this runner's home (~/.cargo, for one); the setup-* actions install
      # under /opt/hostedtoolcache, which it can. The change's own dependencies (npm ci, pip
      # install -r ...) belong inside the check command, which runs as use05-check.
      - name: Install the toolchains (system-wide, pinned here)
        run: echo "Nothing to install yet; see the comment above this step in 05-gate.yml."

      # Installs a checksum-verified release. It fails loudly if no release can be fetched,
      # instead of passing without checking anything.
      - name: Install use05
        run: |
          curl -fsSL https://use05.dev/install.sh | sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      # The exact commit. The token is not left in .git/config, where the code under test
      # could read it.
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
          fetch-depth: 0
          persist-credentials: false

      # Recommended: post the `05` status as your own GitHub App, so no branch can forge it
      # (any workflow's own token can post a status). Set the repository variable
      # USE05_APP_CLIENT_ID and, in the use05 environment, the secret USE05_APP_PRIVATE_KEY.
      - name: Status token from your 05 app
        id: app
        if: vars.USE05_APP_CLIENT_ID != ''
        uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0
        with:
          client-id: ${{ vars.USE05_APP_CLIENT_ID }}
          private-key: ${{ secrets.USE05_APP_PRIVATE_KEY }}
          permission-statuses: write

      # Proves the policy's required checks with the runner key, gates the change and posts
      # the `05` status.
      - name: Prove and gate
        env:
          USE05_RUNNER_KEY: ${{ secrets.USE05_RUNNER_KEY }}
          USE05_PUSH_TOKEN: ${{ github.token }}
          USE05_STATUS_TOKEN: ${{ steps.app.outputs.token }}
          USE05_CHECK_USER: use05-check
        run: use05 gate --ci --push
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Read;

    fn host(vars: &[(&str, &str)]) -> GitHub {
        let map: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        GitHub { env: Box::new(move |k| map.get(k).cloned().filter(|v| !v.is_empty())) }
    }

    fn event_file(dir: &Path, name: &str, json: &str) -> String {
        let p = dir.join(name);
        std::fs::write(&p, json).unwrap();
        p.display().to_string()
    }

    #[test]
    fn github_event_reads_push_pull_request_and_merge_group() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, json: &str| event_file(dir.path(), name, json);

        let push = write("push.json", r#"{"repository":{"default_branch":"main"}}"#);
        let e = host(&[("GITHUB_EVENT_NAME", "push"), ("GITHUB_EVENT_PATH", &push), ("GITHUB_REF_NAME", "agent/login"), ("GITHUB_REF_TYPE", "branch"), ("GITHUB_SHA", "aaa111")]).event();
        assert_eq!(e, CiEvent { kind: EventKind::Push, head_sha: "aaa111".into(), branch: "agent/login".into(), base_branch: None, triggered_by: None, default_branch: Some("main".into()), fork: None });
        assert_eq!(e.lands_on(), "agent/login");

        let pr = write("pr.json", r#"{"pull_request":{"head":{"sha":"bbb222"}},"repository":{"default_branch":"trunk"}}"#);
        let e = host(&[
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_EVENT_PATH", &pr),
            ("GITHUB_BASE_REF", "trunk"),
            ("GITHUB_HEAD_REF", "agent/login"),
            ("GITHUB_REF_NAME", "7/merge"),
            ("GITHUB_REF_TYPE", "branch"),
            ("GITHUB_SHA", "merge999"),
        ])
        .event();
        assert_eq!(e, CiEvent { kind: EventKind::PullRequest, head_sha: "bbb222".into(), branch: "agent/login".into(), base_branch: Some("trunk".into()), triggered_by: None, default_branch: Some("trunk".into()), fork: None });
        assert_eq!(e.lands_on(), "trunk");

        let queue = write("queue.json", r#"{"merge_group":{"base_ref":"refs/heads/main","head_sha":"ccc333"}}"#);
        let e = host(&[("GITHUB_EVENT_NAME", "merge_group"), ("GITHUB_EVENT_PATH", &queue), ("GITHUB_REF_NAME", "gh-readonly-queue/main/pr-1-abc"), ("GITHUB_REF_TYPE", "branch")]).event();
        assert_eq!(e.kind, EventKind::MergeGroup);
        assert_eq!(e.head_sha, "ccc333");
        assert_eq!(e.branch, "gh-readonly-queue/main/pr-1-abc");
        assert_eq!(e.base_branch.as_deref(), Some("main"));
        assert_eq!(e.default_branch, None);
        assert_eq!(e.lands_on(), "main");

        // Nothing named: a tag, or no event at all, lands nowhere.
        let e = host(&[("GITHUB_EVENT_NAME", "push"), ("GITHUB_REF_NAME", "v1"), ("GITHUB_REF_TYPE", "tag")]).event();
        assert_eq!(e.lands_on(), "");
        assert_eq!(host(&[]).event().kind, EventKind::Other);
    }

    #[test]
    fn github_workflow_run_takes_the_change_from_the_run_that_started_it() {
        let dir = tempfile::tempdir().unwrap();
        // This run's own GITHUB_SHA and GITHUB_REF_NAME are the default branch's: never the change.
        let gate = |name: &str, json: &str| {
            let path = event_file(dir.path(), name, json);
            host(&[("GITHUB_EVENT_NAME", "workflow_run"), ("GITHUB_EVENT_PATH", &path), ("GITHUB_SHA", "main000"), ("GITHUB_REF_NAME", "main"), ("GITHUB_REF_TYPE", "branch")]).event()
        };
        let repo = r#""repository":{"full_name":"acme/app","default_branch":"main"}"#;

        let pr = gate("pr.json", &format!(r#"{{"workflow_run":{{"event":"pull_request","head_sha":"bbb222","head_branch":"agent/login","head_repository":{{"full_name":"acme/app"}},"pull_requests":[{{"base":{{"ref":"release"}}}}]}},{repo}}}"#));
        assert_eq!(pr, CiEvent { kind: EventKind::WorkflowRun, head_sha: "bbb222".into(), branch: "agent/login".into(), base_branch: Some("release".into()), triggered_by: Some(EventKind::PullRequest), default_branch: Some("main".into()), fork: None });
        assert_eq!((pr.lands_on(), pr.origin()), ("release", EventKind::PullRequest));

        let push = gate("push.json", &format!(r#"{{"workflow_run":{{"event":"push","head_sha":"aaa111","head_branch":"agent/x","head_repository":{{"full_name":"acme/app"}},"pull_requests":[]}},{repo}}}"#));
        assert_eq!((push.head_sha.as_str(), push.branch.as_str(), push.base_branch.as_deref(), push.lands_on()), ("aaa111", "agent/x", None, "agent/x"));

        let queue = gate("queue.json", &format!(r#"{{"workflow_run":{{"event":"merge_group","head_sha":"ccc333","head_branch":"gh-readonly-queue/release/1.x/pr-12-abc","head_repository":{{"full_name":"acme/app"}}}},{repo}}}"#));
        assert_eq!((queue.lands_on(), queue.origin()), ("release/1.x", EventKind::MergeGroup));

        // A fork: GitHub names no pull request, and the fork's branch name says nothing here.
        let fork = gate("fork.json", &format!(r#"{{"workflow_run":{{"event":"pull_request","head_sha":"ddd444","head_branch":"main","head_repository":{{"full_name":"someone/app"}},"pull_requests":[]}},{repo}}}"#));
        assert_eq!((fork.fork.as_deref(), fork.head_sha.as_str(), fork.lands_on()), (Some("someone/app"), "ddd444", ""));

        // A pull request run that names no pull request (it closed, its head moved) or no head
        // repository (a deleted fork) cannot be placed either: never its own branch's name.
        let closed = gate("closed.json", &format!(r#"{{"workflow_run":{{"event":"pull_request","head_sha":"eee555","head_branch":"agent/x","head_repository":{{"full_name":"acme/app"}},"pull_requests":[]}},{repo}}}"#));
        assert_eq!((closed.branch.as_str(), closed.lands_on()), ("", ""));
        let gone = gate("gone.json", &format!(r#"{{"workflow_run":{{"event":"pull_request","head_sha":"fff666","head_branch":"agent/x","head_repository":null,"pull_requests":[{{"base":{{"ref":"release"}}}}]}},{repo}}}"#));
        assert_eq!((gone.branch.as_str(), gone.lands_on()), ("", "release"));

        // No head named, or not a commit id: nothing to gate, never the default branch instead.
        assert_eq!(gate("empty.json", "{}").head_sha, "");
        assert_eq!(gate("odd.json", r#"{"workflow_run":{"head_sha":"--upload-pack=x"}}"#).head_sha, "");
    }

    #[test]
    fn github_push_remote_needs_a_token_and_a_repository() {
        assert!(host(&[("USE05_PUSH_TOKEN", "t0ken")]).push_remote().is_none());
        assert!(host(&[("GITHUB_REPOSITORY", "o/r")]).push_remote().is_none());
        // The token is in neither the address nor the command line: git gets it as an
        // environment-only setting, scoped to the server.
        let r = host(&[("USE05_PUSH_TOKEN", "t0ken"), ("GITHUB_REPOSITORY", "o/r")]).push_remote().unwrap();
        assert_eq!((r.url.as_str(), r.token.as_str()), ("https://github.com/o/r.git", "t0ken"));
        let basic = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "x-access-token:t0ken");
        assert_eq!(r.envs, [("GIT_CONFIG_COUNT".to_string(), "1".to_string()), ("GIT_CONFIG_KEY_0".into(), "http.https://github.com/.extraheader".into()), ("GIT_CONFIG_VALUE_0".into(), format!("AUTHORIZATION: basic {basic}"))]);
        assert_eq!(r.redact(&format!("header {basic} and t0ken")), "header *** and ***");
        let ghe = host(&[("USE05_PUSH_TOKEN", "t0ken"), ("GITHUB_REPOSITORY", "o/r"), ("GITHUB_SERVER_URL", "https://git.example.com/")]).push_remote().unwrap();
        assert_eq!((ghe.url.as_str(), ghe.envs[1].1.as_str()), ("https://git.example.com/o/r.git", "http.https://git.example.com/.extraheader"));
    }

    #[test]
    fn github_says_whether_the_status_comes_from_your_app() {
        assert!(host(&[("USE05_STATUS_TOKEN", "ghs_app")]).status_from_app());
        assert!(!host(&[("USE05_PUSH_TOKEN", "t0ken"), ("GITHUB_TOKEN", "t")]).status_from_app());
        let custody = host(&[]).key_custody().join("\n");
        for said in ["`use05` environment", "cannot read these settings from here", "GitHub Pro, Team or Enterprise", "a branch can forge the `05` status", "use05 verify"] {
            assert!(custody.contains(said), "{said}: {custody}");
        }
    }

    #[test]
    fn github_status_request_keeps_the_token_out_of_the_command_line() {
        let body = status_body(Verdict::Failure, &"x".repeat(200));
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!((v["state"].as_str(), v["context"].as_str(), v["description"].as_str().map(str::len)), (Some("failure"), Some("05"), Some(140)));
        let config = curl_config("https://api.github.com/repos/o/r/statuses/abc", "t0ken", &body);
        assert!(config.contains("header = \"Authorization: Bearer t0ken\"") && config.contains("data = \"{\\\"context\\\":\\\"05\\\""), "{config}");
        assert!(host(&[]).post_status("abc", Verdict::Success, "ok").is_err(), "without a token there is nothing to post with");
    }

    /// One HTTP exchange on a local port: what was asked, answered with `status`.
    fn serve_once(status: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
            let mut got = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                got.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&got).to_string();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
            String::from_utf8_lossy(&got).to_string()
        });
        (url, handle)
    }

    #[test]
    fn github_posts_the_status_to_the_statuses_api() {
        let (api, server) = serve_once("201 Created");
        let h = host(&[("GITHUB_API_URL", &api), ("GITHUB_REPOSITORY", "acme/app"), ("USE05_PUSH_TOKEN", "t0ken"), ("GITHUB_TOKEN", "not-this-one")]);
        h.post_status("abc123", Verdict::Failure, "denied: the check \"test\" failed").unwrap();
        let request = server.join().unwrap();
        let (head, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("POST /repos/acme/app/statuses/abc123 HTTP/1.1\r\n"), "{head}");
        assert!(head.lines().any(|l| l == "Authorization: Bearer t0ken"), "{head}");
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v, serde_json::json!({ "state": "failure", "context": "05", "description": "denied: the check \"test\" failed" }));

        // A status token of its own wins; a refusal is an error that does not quote the token.
        let (api, server) = serve_once("403 Forbidden");
        let h = host(&[("GITHUB_API_URL", &api), ("GITHUB_REPOSITORY", "acme/app"), ("USE05_STATUS_TOKEN", "st4tus"), ("USE05_PUSH_TOKEN", "t0ken")]);
        let err = h.post_status("abc123", Verdict::Pending, "checking").unwrap_err();
        assert!(server.join().unwrap().contains("Authorization: Bearer st4tus\r\n"));
        assert!(err.contains("403") && !err.contains("st4tus"), "{err}");
    }

    #[test]
    fn github_writes_the_gate_and_the_workflow_that_starts_it() {
        let files = host(&[]).workflows();
        let names: Vec<_> = files.iter().map(|(p, _)| p.display().to_string()).collect();
        assert_eq!(names, [".github/workflows/05-gate.yml", ".github/workflows/05.yml"]);
        let gate = &files[0].1;
        assert!(gate.contains("use05 gate --ci --push") && gate.contains("environment: use05"));
        assert!(!files[1].1.contains("secrets."));
        // The status token from your own app, when there is one; the action pinned by commit.
        assert!(gate.contains("if: vars.USE05_APP_CLIENT_ID != ''") && gate.contains("uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0"), "{gate}");
        assert!(gate.contains("client-id: ${{ vars.USE05_APP_CLIENT_ID }}") && !gate.contains("app-id:") && !gate.contains("USE05_APP_ID"), "{gate}");
        assert!(gate.contains("private-key: ${{ secrets.USE05_APP_PRIVATE_KEY }}") && gate.contains("USE05_STATUS_TOKEN: ${{ steps.app.outputs.token }}"), "{gate}");
        // The check user schedules nothing, and toolchains are installed system-wide.
        assert!(gate.contains("/etc/cron.deny /etc/at.deny") && gate.contains("install the toolchains your checks need here, system-wide"), "{gate}");
        // Nothing of the change is on disk while anything runs as the key holder with sudo: the
        // user and the toolchains come before the checkout, and the gate after it.
        let at = |s: &str| gate.find(s).unwrap_or_else(|| panic!("{s} missing: {gate}"));
        let checkout = at("uses: actions/checkout@");
        assert!(at("name: Make the check user") < checkout && at("name: Install the toolchains") < checkout && at("name: Install use05") < checkout, "{gate}");
        assert!(checkout < at("use05 gate --ci --push"));
    }

    #[test]
    fn github_finds_workflows_that_give_the_key_to_a_branch() {
        let dir = tempfile::tempdir().unwrap();
        let wf = dir.path().join(".github/workflows");
        std::fs::create_dir_all(&wf).unwrap();
        let old = "name: 05\non:\n  pull_request:\n  push:\n    branches-ignore: [\"05-receipts/**\"]\npermissions:\n  contents: write\njobs:\n  a:\n    env:\n      USE05_RUNNER_KEY: ${{ secrets.USE05_RUNNER_KEY }}\n";
        std::fs::write(wf.join("acceptance.yml"), old).unwrap();
        std::fs::write(wf.join("inline.yaml"), "on: [push]\njobs: {a: {env: {K: \"${{ secrets.USE05_RUNNER_KEY }}\"}}}\n").unwrap();
        // The gate and its starter, a workflow without the key, and one that mentions push only
        // in comments.
        for (name, text) in host(&[]).workflows() {
            std::fs::write(dir.path().join(name), text).unwrap();
        }
        std::fs::write(wf.join("other.yml"), "on:\n  workflow_dispatch:   # not on push\n# push\njobs:\n  a:\n    env: { K: \"${{ secrets.USE05_RUNNER_KEY }}\" }\n").unwrap();
        std::fs::write(wf.join("ci.yml"), "on: push\njobs: {}\n").unwrap();
        // Other spellings of the same secret, every secret at once, and a pull_request_target run.
        std::fs::write(wf.join("index.yml"), "on: [pull_request]\njobs: {a: {env: {K: \"${{ secrets['USE05_RUNNER_KEY'] }}\"}}}\n").unwrap();
        std::fs::write(wf.join("quoted.yml"), "on: merge_group\njobs: {a: {env: {K: \"${{ secrets[\\\"use05_runner_key\\\"] }}\"}}}\n").unwrap();
        std::fs::write(wf.join("all.yml"), "on: push\njobs: {a: {env: {ALL: \"${{ toJSON(secrets) }}\"}}}\n").unwrap();
        std::fs::write(wf.join("target.yml"), "on: pull_request_target\njobs: {a: {env: {K: \"${{ secrets.USE05_RUNNER_KEY }}\"}}}\n").unwrap();
        let found: Vec<String> = host(&[]).key_exposed_in(dir.path()).iter().map(|p| p.display().to_string()).collect();
        let named = |n: &str| format!(".github/workflows/{n}");
        assert_eq!(found, [named("acceptance.yml"), named("all.yml"), named("index.yml"), named("inline.yaml"), named("quoted.yml"), named("target.yml")]);
        assert!(host(&[]).key_exposed_in(&dir.path().join("nowhere")).is_empty());
    }
}
