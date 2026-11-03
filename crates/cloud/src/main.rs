//! `use05-cloud`, run as `use05 cloud <command>`: connects this machine's 05 to your own 05
//! console, which you host yourself.
//!
//! It only ever connects out. It sends metadata (plans, file names, verdicts, the policy file),
//! never code, diffs, prompts or transcripts. From the console it accepts exactly four things,
//! and checks each itself: file an approval (only if a passkey pinned here signed it), prepare
//! and apply a policy edit (only fields the console may change, never a command or a key), and
//! send the folder tree (names only). It runs no command, script or program it is sent.

mod keys;
mod repo;
mod report;

use std::fs;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Config {
    pub url: String,
    pub token: String,
    pub machine: String,
    /// The `use05` this helper runs: found when it was installed, so launchd needs no PATH.
    pub use05: String,
    #[serde(default)]
    pub repos: Vec<String>,
    /// The team's public key, pinned at pairing after a person compared the code (D86).
    #[serde(default)]
    pub team_pub: String,
    #[serde(default)]
    pub team_version: i64,
    /// `machine` (paired at a terminal), `session` or `ci` (from a token a member made).
    #[serde(default = "machine_kind")]
    pub kind: String,
}

fn machine_kind() -> String {
    "machine".into()
}

pub fn home() -> Result<PathBuf> {
    use05_core::keys::user_dir().map_err(|e| anyhow!(e.message))
}

fn config_path() -> Result<PathBuf> {
    Ok(home()?.join("cloud.toml"))
}

pub fn load() -> Result<Config> {
    let text = fs::read_to_string(config_path()?).context("this machine is not paired with a console; run: use05 cloud login <url>")?;
    toml::from_str(&text).context("cloud.toml cannot be read")
}

fn save(c: &Config) -> Result<()> {
    let path = config_path()?;
    fs::create_dir_all(path.parent().unwrap())?;
    cloud::prepared::write_private(&path, toml::to_string(c)?.as_bytes())
}

/// The team's id key (D86): repository and task references are HMACs under it, so the console
/// can route by them without reading them. The owner's browser sealed it to this machine when
/// pairing; it is opened once and kept here, readable by you only.
pub fn id_key(api: &Api) -> Result<[u8; 32]> {
    if let Ok(key) = stored_id_key() {
        return Ok(key);
    }
    let path = home()?.join("cloud-id.key");
    let hello = api.post("/hello", json!({ "use05_version": report::use05_version(&api.c) }))?;
    let sealed = hello["sealed_id_key"].as_str().and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok()).ok_or_else(|| anyhow!("the console has no team key for this machine yet; pair it again"))?;
    let keys = keys::load()?;
    let team_pub: [u8; 32] = base64::engine::general_purpose::STANDARD.decode(&api.c.team_pub).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("this machine has no team key; pair it again"))?;
    // Only the team (a browser holding its key) can wrap it so it opens here: not the console.
    let key = cloud::seal::open_id_key(&keys.x_secret, &team_pub, &sealed).map_err(|_| anyhow!("the team's id key did not come from the team; pair this machine again"))?;
    cloud::prepared::write_private(&path, hex::encode(key).as_bytes())?;
    Ok(key)
}

/// The team's id key as kept on this machine, once fetched.
pub fn stored_id_key() -> Result<[u8; 32]> {
    let path = home()?.join("cloud-id.key");
    let text = fs::read_to_string(&path).map_err(|_| anyhow!("this machine has not fetched the team's id key yet; run use05 cloud sync"))?;
    hex::decode(text.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("{} is damaged", path.display()))
}

/// An instruction's payload, with its sealed part (an envelope, a commit to apply) opened with this
/// machine's key, under the kind it was sealed for. What was sealed decides; the console's routing
/// must agree with it.
fn open_instruction(kind: &str, payload: &Value) -> Result<Value> {
    let opened = match payload["sealed"].as_str() {
        Some(sealed) => {
            let bytes = base64::engine::general_purpose::STANDARD.decode(sealed)?;
            let aad = format!("use05 instruction {kind}");
            let plain = cloud::seal::open(&keys::load()?.x_secret, &bytes, aad.as_bytes()).map_err(|_| anyhow!("an instruction that does not open with this machine's key, or was sealed for something else"))?;
            Some(serde_json::from_slice::<Value>(&plain)?)
        }
        None => None,
    };
    cloud::checks::bind_instruction(kind, payload, opened).map_err(|why| {
        note_locally(&format!("refused an instruction: {why}"));
        anyhow!(why)
    })
}

/// Someone left the team and its key changed: seal to the new key from now on, but only on the
/// word of a passkey pinned here (the console cannot make one).
fn take_team_key(api: &mut Api, payload: &Value) -> Result<Value> {
    use base64::Engine;
    let me = base64::engine::general_purpose::STANDARD.encode(keys::load()?.ed.verifying_key().as_bytes());
    let envelope = serde_json::to_vec(&payload["envelope"])?;
    let change = cloud::checks::team_key_change(&envelope, &use05_core::keys::pinned_passkeys(), &me, api.c.team_version).map_err(|why| {
        note_locally(&format!("refused a new team key: {why}"));
        anyhow!(why)
    })?;
    let mut c = load()?;
    c.team_pub = change.public.clone();
    c.team_version = change.version;
    save(&c)?;
    api.c.team_pub = change.public;
    api.c.team_version = change.version;
    note_locally(&format!("took the team's new key (version {}), confirmed by the passkey \"{}\"", change.version, change.by));
    Ok(json!({ "version": change.version }))
}

/// The statements this machine prepared and has not filed yet.
pub fn prepared() -> Result<cloud::prepared::Prepared> {
    Ok(cloud::prepared::Prepared::at(&home()?.join("cloud-prepared.json")))
}

/// What this machine refused, kept here as well as reported: the console may be the one lying.
pub fn note_locally(what: &str) {
    if let Ok(h) = home() {
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(h.join("cloud-refusals.log")) {
            let _ = writeln!(f, "{} {what}", use05_core::time::now_rfc3339());
        }
    }
}

/// A counter that only goes up, on this machine: microseconds since 1970 (exact in JavaScript),
/// and past the last one given, kept on disk, so that a clock set back (or the next process) does
/// not make newer records look older to the team's browsers.
fn next_seq() -> u64 {
    home().map(|h| next_seq_in(&h.join("cloud-seq"))).unwrap_or(0)
}

fn next_seq_in(file: &Path) -> u64 {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0);
    let last = fs::read_to_string(file).ok().and_then(|t| t.trim().parse::<u64>().ok()).unwrap_or(0);
    let next = now.max(last + 1);
    let _ = fs::write(file, next.to_string());
    next
}

pub struct Api {
    pub c: Config,
    agent: ureq::Agent,
}

impl Api {
    pub fn new(c: Config) -> Api {
        Api { agent: ureq::AgentBuilder::new().timeout_read(Duration::from_secs(40)).timeout_write(Duration::from_secs(20)).build(), c }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/agent{path}", self.c.url.trim_end_matches('/'))
    }

    pub fn post(&self, path: &str, body: Value) -> Result<Value> {
        let r = self.agent.post(&self.url(path)).set("authorization", &format!("Bearer {}", self.c.token)).send_json(body);
        read(r)
    }

    /// Seal a report to the team's key and sign it with this machine's: what the console keeps of it.
    pub fn sealed(&self, kind: &str, repo: &str, reference: &str, body: &Value) -> Result<(String, String)> {
        use ed25519_dalek::Signer as _;
        // The file, not this copy: the team's key may have changed since this Api was made.
        let team_pub = load().map(|c| c.team_pub).unwrap_or_else(|_| self.c.team_pub.clone());
        let team: [u8; 32] = base64::engine::general_purpose::STANDARD.decode(&team_pub).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("this machine has no team key; pair it again"))?;
        let sealed = cloud::seal::seal(&team, &serde_json::to_vec(body)?, format!("use05 record {kind}").as_bytes());
        let keys = keys::load()?;
        let mut signed = b"use05 record v1".to_vec();
        for part in [kind.as_bytes(), &[0], repo.as_bytes(), &[0], reference.as_bytes(), &[0]] {
            signed.extend_from_slice(part);
        }
        signed.extend_from_slice(&sealed);
        let sig = keys.ed.sign(&signed);
        let b64 = base64::engine::general_purpose::STANDARD;
        Ok((b64.encode(&sealed), b64.encode(sig.to_bytes())))
    }

    /// Send a sealed, signed record.
    pub fn record(&self, kind: &str, repo: &str, reference: &str, mut body: Value) -> Result<Value> {
        // When it was made, by this machine's clock and inside what it signs: the console cannot
        // reorder records, and a browser that saw a newer copy refuses an older one.
        if let Some(o) = body.as_object_mut() {
            o.insert("_at".into(), json!(use05_core::time::now_rfc3339()));
            o.insert("_seq".into(), json!(next_seq()));
        }
        let (sealed, sig) = self.sealed(kind, repo, reference, &body)?;
        self.post("/record", json!({ "kind": kind, "repo": repo, "ref": reference, "sealed": sealed, "sig": sig }))
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        read(self.agent.get(&self.url(path)).set("authorization", &format!("Bearer {}", self.c.token)).call())
    }
}

/// The most the helper reads of one answer: a compromised console cannot exhaust its memory.
const MAX_ANSWER: u64 = 16 * 1024 * 1024;

fn json_of(resp: ureq::Response) -> Result<Value> {
    Ok(serde_json::from_reader(resp.into_reader().take(MAX_ANSWER))?)
}

fn read(r: std::result::Result<ureq::Response, ureq::Error>) -> Result<Value> {
    match r {
        Ok(resp) => json_of(resp),
        Err(ureq::Error::Status(code, resp)) => {
            let body: Value = json_of(resp).unwrap_or_default();
            bail!("the console said {code}: {}", body["error"].as_str().unwrap_or("no reason"))
        }
        Err(e) => bail!("cannot reach the console: {e}"),
    }
}

const USAGE: &str = "use05 cloud: connect this machine to your own 05 console.\n\n  login <url> [--name NAME]  claim a new console, or pair this machine (its word, then two codes);\n                             in a repository, also add, enrol and install\n  add [PATH]                 report this repository (default: the one you are in)\n  enrol                      pin your console passkeys as approvers on this machine\n  install                    run in the background and hear 05's events\n  status                     what is set up\n  sync                       send everything once, now\n  session [--background]     in a cloud agent session, report with the token in USE05_SESSION\n  ci collect | ci report F   in CI, with the token in USE05_CI: file phone approvals; send the verdict\n\nIt connects out only, sends what it reports sealed to your console's key, and runs nothing it is sent.";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Help is asked for, never acted on: a command with --help pairs, installs or sends nothing.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return;
    }
    let result = match args.first().map(String::as_str) {
        Some("login") => login(&args[1..]),
        Some("add") => add(args.get(1).map(PathBuf::from)),
        Some("enrol") | Some("enroll") => enrol(),
        Some("install") => install(),
        Some("run") => run(),
        Some("event") => event(),
        Some("sync") => load().map(Api::new).and_then(|api| {
            id_key(&api)?;
            report::sync_all(&api, true)
        }),
        Some("status") => status(),
        Some("session") => session(&args[1..]),
        Some("session-run") => session_run(),
        Some("ci") => ci(&args[1..]),
        _ => {
            println!("{USAGE}");
            Ok(())
        }
    };
    if let Err(e) = result {
        eprintln!("use05 cloud: {e:#}");
        std::process::exit(1);
    }
}

fn hostname() -> String {
    let ask = |cmd: &str, args: &[&str]| std::process::Command::new(cmd).args(args).output().ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s| !s.is_empty());
    ask("scutil", &["--get", "ComputerName"]).or_else(|| ask("hostname", &[])).unwrap_or_else(|| "this machine".into())
}

/// Take on a token a member made in the console for a cloud session or a CI job (D86): its keys,
/// the team's key as their browser held it, the one repository it reports. Never over a machine
/// paired at a terminal.
fn adopt(var: &str) -> Result<Config> {
    let text = std::env::var(var).map_err(|_| anyhow!("{var} is not set: make a token on the console's Machines page and store it as {var}"))?;
    let r = cloud::token::Reporter::parse(&text).map_err(|e| anyhow!(e))?;
    let home = home()?;
    if paired_here(&home) {
        bail!("this machine is paired at a terminal; a {} token is for a cloud session or CI, not here", r.kind);
    }
    let dir = std::env::current_dir()?;
    let top = use05_core::git::dirs(&dir).map_err(|e| anyhow!(e.message))?.top.canonicalize()?.to_string_lossy().to_string();
    fs::create_dir_all(&home)?;
    cloud::prepared::write_private(&home.join("cloud-x25519.key"), hex::encode(r.x).as_bytes())?;
    cloud::prepared::write_private(&home.join("cloud-ed25519.key"), hex::encode(r.ed).as_bytes())?;
    let _ = fs::remove_file(home.join("cloud-id.key"));
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let c = Config { url: r.url, token: r.bearer, machine: r.name, use05: which("use05").unwrap_or_else(|| "use05".into()), repos: vec![top], team_pub: b64(&r.team), team_version: r.version, kind: r.kind };
    save(&c)?;
    let api = Api::new(c.clone());
    id_key(&api)?;
    let repo = repo::Repo::open(&c.repos[0])?;
    if repo.id != r.repo {
        bail!("this token is for another repository than the one here ({})", repo.name);
    }
    Ok(c)
}

/// Whether this per-user directory holds a machine paired at a terminal: its keys are there and
/// its settings do not say it is a session's or CI's (or cannot be read). A token never replaces
/// those keys.
fn paired_here(home: &Path) -> bool {
    let keys = ["cloud-x25519.key", "cloud-ed25519.key", "cloud-id.key"].iter().any(|k| home.join(k).exists());
    let kind = fs::read_to_string(home.join("cloud.toml")).ok().and_then(|t| toml::from_str::<Config>(&t).ok()).map(|c| c.kind);
    keys && !matches!(kind.as_deref(), Some("session" | "ci"))
}

/// In a cloud agent session (Claude Code, Codex): report this repository as the token's member,
/// from a SessionStart hook or a setup script. `--background` returns at once.
fn session(args: &[String]) -> Result<()> {
    let c = adopt("USE05_SESSION")?;
    let me = std::env::current_exe()?.canonicalize()?.to_string_lossy().to_string();
    listen(&me)?;
    if args.iter().any(|a| a == "--background") {
        let log = fs::OpenOptions::new().create(true).append(true).open(home()?.join("cloud.log"))?;
        std::process::Command::new(&me).arg("session-run").stdin(std::process::Stdio::null()).stdout(log.try_clone()?).stderr(log).spawn()?;
        println!("05: reporting {} to {} from this session, as {}.", c.repos[0], c.url, c.machine);
        return Ok(());
    }
    session_run()
}

/// The session's loop: what 05 heard, sent sealed; the repository now and then. Nothing is polled
/// for: a session runs nothing it is sent.
fn session_run() -> Result<()> {
    let api = Api::new(load()?);
    if let Err(e) = report::sync_all(&api, true) {
        eprintln!("sync: {e:#}");
    }
    let mut tick = 0u32;
    loop {
        if let Err(e) = report::drain(&api, &spool()?) {
            eprintln!("events: {e:#}");
        }
        tick += 1;
        if tick % 20 == 0 {
            if let Err(e) = report::sync_all(&api, false) {
                eprintln!("sync: {e:#}");
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// In CI (D86), with the token in USE05_CI. `collect` before the gate files approvals signed on a
/// phone since the last run; `report gate.json` after it (`use05 gate --ci --json > gate.json`)
/// sends the verdict, sealed to the team, and when CI holds the work for a person, prepares the
/// statement for the token's person to sign, co-signed by the runner key.
fn ci(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("collect") => ci_collect(),
        Some("report") => ci_report(args.get(1).ok_or_else(|| anyhow!("say which file holds the gate's JSON: use05-cloud ci report gate.json"))?),
        _ => bail!("use05-cloud ci collect | ci report <gate.json>"),
    }
}

fn ci_report(file: &str) -> Result<()> {
    let gate: Value = serde_json::from_str(&fs::read_to_string(file)?)?;
    let c = adopt("USE05_CI")?;
    let person = std::env::var("USE05_CI").ok().and_then(|t| cloud::token::Reporter::parse(&t).ok()).map(|r| r.person).unwrap_or_default();
    let api = Api::new(c.clone());
    let repo = repo::Repo::open(&c.repos[0])?;
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let branch = env("GITHUB_BASE_REF").or_else(|| env("GITHUB_REF_NAME"));
    let run = match (env("GITHUB_SERVER_URL"), env("GITHUB_REPOSITORY"), env("GITHUB_RUN_ID")) {
        (Some(s), Some(r), Some(id)) => Some(format!("{s}/{r}/actions/runs/{id}")),
        _ => None,
    };
    let summary = report::summary(&gate);
    let tree = summary["tree"].as_str().unwrap_or_default().to_string();
    let reference = cloud::seal::hmac_ref(&stored_id_key()?, "ci", &format!("{tree}|{}", branch.clone().unwrap_or_default()));
    api.record("ci", &repo.id, &reference, json!({ "decision": gate["decision"], "branch": branch, "run": run, "tree": tree, "summary": summary }))?;
    println!("05: the CI verdict ({}) is on the console.", gate["decision"].as_str().unwrap_or("?"));
    if report::approval_could_clear(&gate) && !person.is_empty() && std::env::var("USE05_RUNNER_KEY").is_ok() {
        let task = gate["brief"]["task_id"].as_str().unwrap_or("-");
        repo.ask_from_ci(&api, task, &tree, &person)?;
        println!("05: asked {person} to approve it on the console; the next CI run collects the approval.");
    }
    Ok(())
}

/// File what was signed on a phone for work CI prepared: only a statement the runner key
/// co-signed (CI keeps nothing between runs, so that signature is its memory), then push it.
fn ci_collect() -> Result<()> {
    let c = adopt("USE05_CI")?;
    let api = Api::new(c.clone());
    let runner = std::env::var("USE05_RUNNER_KEY").ok().and_then(|k| use05_receipt::parse_secret_key(&k).ok()).ok_or_else(|| anyhow!("USE05_RUNNER_KEY is not set"))?;
    let found = api.get("/poll?once=true")?;
    let mut filed = 0;
    for i in found["instructions"].as_array().into_iter().flatten() {
        let id = i["id"].as_str().unwrap_or_default();
        let kind = i["kind"].as_str().unwrap_or("");
        let outcome = (|| -> Result<Value> {
            if kind != "file_approval" {
                bail!("CI collects approvals only");
            }
            let payload = open_instruction(kind, &i["payload"])?;
            let envelope = serde_json::to_vec(&payload["envelope"])?;
            use05_receipt::verify_bytes_with(&envelope, &use05_receipt::PublicKey::Ed25519(runner.verifying_key())).map_err(|_| anyhow!("CI did not prepare what was signed"))?;
            let repo = repo::Repo::open(&c.repos[0])?;
            repo.file_signed(&api, &envelope)
        })();
        let (ok, result) = match outcome {
            Ok(r) => {
                filed += 1;
                (true, r)
            }
            Err(e) => {
                eprintln!("{kind}: {e:#}");
                (false, json!({ "reason": format!("{e:#}") }))
            }
        };
        let payload = open_instruction(kind, &i["payload"]).unwrap_or_default();
        let reference = payload["request"].as_str().unwrap_or("");
        let sealed = api.sealed("result", payload["repo"].as_str().unwrap_or(""), reference, &json!({ "ok": ok, "result": result })).map(|(s, g)| json!({ "sealed": s, "sig": g })).unwrap_or_else(|_| json!({}));
        let _ = api.post(&format!("/done/{id}"), json!({ "ok": ok, "result": sealed }));
    }
    println!("05: filed {filed} approval(s) signed since the last run.");
    Ok(())
}

fn login(args: &[String]) -> Result<()> {
    let url = args.first().ok_or_else(|| anyhow!("say which console: use05 cloud login https://…"))?.trim_end_matches('/').to_string();
    if !cloud::checks::console_url_ok(&url) {
        bail!("the console must be on https:// (plain http only for localhost)");
    }
    let name = args.windows(2).find(|w| w[0] == "--name").map(|w| w[1].clone()).unwrap_or_else(hostname);
    let use05 = which("use05").unwrap_or_else(|| "use05".into());
    let mut api = Api::new(Config { url: url.clone(), machine: name.clone(), use05, kind: machine_kind(), ..Config::default() });
    let keys = keys::load()?;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let (x_pub, ed_pub) = (keys.x_public, keys.ed.verifying_key().to_bytes());
    // Commit to this machine's keys and a nonce now; reveal them only once someone has typed the
    // word and their browser has sent its own nonce. Neither the console nor anyone else can then
    // pick keys that make the two codes agree.
    let nonce: [u8; 16] = rand::random();
    let word = cloud::seal::pairing_word();
    let commit = cloud::seal::pair_commit(&x_pub, &ed_pub, &nonce);
    let at_terminal = std::io::stdin().is_terminal();
    // A fresh console has no owner: claim it here with the code from its log, and sign up in the
    // browser by the link it gives back.
    let me = read(api.agent.get(&format!("{url}/api/me")).call())?;
    if me["setup_needed"] == true {
        claim(&api, &url, at_terminal)?;
    }
    let start = json!({ "name": name, "commit": b64(&commit), "word_hash": hex::encode(<sha2::Sha256 as sha2::Digest>::digest(word.as_bytes())) });
    let mut waited = false;
    let started = loop {
        match read(api.agent.post(&format!("{url}/agent/pair/start")).send_json(&start)) {
            // The owner is still making their passkey; the team's keys come with it.
            Err(e) if e.to_string().contains("no team keys yet") && me["setup_needed"] == true => {
                if !waited {
                    println!("Waiting for you to finish in the browser…");
                    waited = true;
                }
                std::thread::sleep(Duration::from_secs(3));
            }
            other => break other?,
        }
    };
    let team_pub: [u8; 32] = started["team_pub"].as_str().and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok()).and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("the console sent no team key; sign in to it once so its keys exist"))?;
    let team_version = started["team_version"].as_i64().and_then(|v| u32::try_from(v).ok()).ok_or_else(|| anyhow!("the console sent no team version"))?;
    let pair = json!({ "pair_id": started["pair_id"], "poll_secret": started["poll_secret"] });
    println!("Pairing \"{name}\" with {url}.\n\n  Word: {word}\n\nOpen the console, choose Pair this machine, and type this word. Waiting…");
    // A new pairing means a new team, perhaps: fetch its id key again.
    let _ = fs::remove_file(home()?.join("cloud-id.key"));
    let mut revealed = false;
    for _ in 0..300 {
        std::thread::sleep(Duration::from_secs(2));
        let polled = read(api.agent.post(&format!("{url}/agent/pair/poll")).send_json(&pair))?;
        if let (false, Some(theirs)) = (revealed, polled["browser_nonce"].as_str()) {
            let theirs: [u8; 16] = base64::engine::general_purpose::STANDARD.decode(theirs).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("the console sent a malformed nonce"))?;
            let mut reveal = pair.clone();
            reveal["x_pub"] = json!(b64(&x_pub));
            reveal["ed_pub"] = json!(b64(&ed_pub));
            reveal["nonce"] = json!(b64(&nonce));
            read(api.agent.post(&format!("{url}/agent/pair/reveal")).send_json(&reveal))?;
            revealed = true;
            let code = cloud::seal::pairing_code(&team_pub, team_version, &x_pub, &ed_pub, &nonce, &theirs);
            println!("\n  Code: {code}\n\nThe console now shows a code. Approve there only if it is this one. Waiting…");
        }
        if let Some(token) = polled["token"].as_str() {
            api.c.token = token.to_string();
            api.c.team_pub = b64(&team_pub);
            api.c.team_version = team_version.into();
            if let Ok(old) = load() {
                api.c.repos = old.repos;
            }
            save(&api.c)?;
            api.post("/hello", json!({ "use05_version": report::use05_version(&api.c) }))?;
            id_key(&api)?;
            println!("Paired.");
            after_pairing(at_terminal);
            return Ok(());
        }
    }
    bail!("nobody approved the pairing in 9 minutes; run it again")
}

/// Claim a console nobody owns yet: the code from its log, typed here, for a one-time sign-up link.
fn claim(api: &Api, url: &str, at_terminal: bool) -> Result<()> {
    println!("{url} has no owner yet. When it starts, it writes a claim code to its log (on Railway, the service's Deploy Logs; with Docker, docker logs).");
    print!("Claim code: ");
    std::io::stdout().flush()?;
    let mut code = String::new();
    std::io::stdin().read_line(&mut code)?;
    let claimed = read(api.agent.post(&format!("{url}/agent/claim")).send_json(json!({ "code": code.trim() })))?;
    let link = claimed["url"].as_str().filter(|l| l.starts_with(url)).ok_or_else(|| anyhow!("the console sent no link to sign up with"))?;
    println!("\nClaimed. Open this link to make your passkey (it works once, for 15 minutes):\n\n  {link}\n");
    if at_terminal {
        let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
        let _ = std::process::Command::new(opener).arg(link).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    }
    Ok(())
}

/// After pairing, inside a repository and with a person at the terminal: report it, pin their
/// passkeys and keep running, each said as it happens. Elsewhere: say what is next.
fn after_pairing(at_terminal: bool) {
    let here = std::env::current_dir().ok().filter(|d| use05_core::git::dirs(d).is_ok());
    let Some(dir) = here.filter(|_| at_terminal) else {
        println!("Next:\n  use05 cloud add      in each repository you want to see\n  use05 cloud enrol    so approvals from your phone count here\n  use05 cloud install  to keep it running");
        return;
    };
    let steps: [(&str, &str, Box<dyn FnOnce() -> Result<()>>); 3] = [
        ("report this repository", "add", Box::new(move || add(Some(dir)))),
        ("pin your passkeys", "enrol", Box::new(enrol)),
        ("keep running in the background", "install", Box::new(install)),
    ];
    for (what, command, step) in steps {
        println!("\nNext, {what}:");
        if let Err(e) = step() {
            println!("Could not {what}: {e:#}. Later: use05 cloud {command}");
        }
    }
}

pub fn which(program: &str) -> Option<String> {
    std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(program)).find(|p| p.is_file()).map(|p| p.to_string_lossy().to_string())
}

fn add(path: Option<PathBuf>) -> Result<()> {
    let mut c = load()?;
    let dir = path.unwrap_or(std::env::current_dir()?);
    let dirs = use05_core::git::dirs(&dir).map_err(|e| anyhow!(e.message))?;
    // The main worktree, so every worktree of the repository is one entry.
    let top = dirs.common.parent().filter(|_| dirs.common.ends_with(".git")).map(Path::to_path_buf).unwrap_or(dirs.top);
    let top = top.canonicalize()?.to_string_lossy().to_string();
    if !c.repos.contains(&top) {
        c.repos.push(top.clone());
        save(&c)?;
    }
    let api = Api::new(c);
    id_key(&api)?;
    let r = repo::Repo::open(&top)?;
    report::send_repo(&api, &r, true)?;
    println!("Reporting {} ({top}) to the console.", r.name);
    Ok(())
}

fn tty_yes(question: &str) -> Result<bool> {
    let mut tty = fs::OpenOptions::new().read(true).write(true).open("/dev/tty").context("this needs a person at a terminal")?;
    write!(tty, "{question} [y/N] ")?;
    let mut line = String::new();
    std::io::BufReader::new(tty).read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

/// Pin the console's passkeys as approvers here, each confirmed by a person at the terminal.
fn enrol() -> Result<()> {
    let api = Api::new(load()?);
    let listed = api.get("/passkeys")?;
    let path = use05_core::keys::passkeys_path().map_err(|e| anyhow!(e.message))?;
    let existing = fs::read_to_string(&path).unwrap_or_default();
    let mut pinned = 0;
    for p in listed["passkeys"].as_array().into_iter().flatten() {
        let (Some(public), Some(name), Some(id)) = (p["public"].as_str(), p["name"].as_str(), p["id"].as_str()) else { continue };
        let (name, id) = (cloud::checks::plain(name, 60), cloud::checks::plain(id, 80));
        if existing.contains(public) {
            println!("Already pinned: {name} ({id})");
            continue;
        }
        // Only a passkey made for this console's own site is put to a person at all.
        let site = match cloud::checks::offered_passkey(public, &api.c.url) {
            Ok(site) => site,
            Err(why) => {
                note_locally(&format!("enrol: refused a key the console offered ({name}): {why}"));
                println!("Skipped \"{name}\": {why}.");
                continue;
            }
        };
        let added = p["created_at"].as_str().map(|t| cloud::checks::plain(t, 10)).unwrap_or_else(|| "an unknown date".into());
        let person = p["person"].as_str().map(|t| cloud::checks::plain(t, 60)).unwrap_or_else(|| "nobody named".into());
        println!("\nPasskey \"{name}\" of {person}, made for {site}, added to the console on {added}\n  key id {id}\n  If you did not add a passkey with this name on that day, answer no.");
        // Approvals signed here count for whoever git says is working on this machine.
        let here = std::process::Command::new("git").args(["config", "user.name"]).output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
        if !here.is_empty() && !here.eq_ignore_ascii_case(&person) {
            println!("  Note: git on this machine says you are \"{here}\", not {person}. Approvals from this passkey will not count for work recorded under \"{here}\"; answer no unless that is right.");
        }
        if tty_yes("Let approvals signed by this passkey count on this machine?")? {
            let mut f = fs::OpenOptions::new().create(true).append(true).open(&path)?;
            writeln!(f, "{public} {}", name.replace(['\n', '\r'], " "))?;
            pinned += 1;
        }
    }
    println!("\n{pinned} passkey(s) pinned in {}.", path.display());
    println!("For CI to count phone approvals too, list each under [[trust.key]] in .05/policy.toml with role = \"approver\" (a change you approve at the terminal).");
    Ok(())
}

/// Hear 05's events: add this helper as a listener in 05's extensions file (D73).
fn listen(me: &str) -> Result<()> {
    let ext = home()?.join("extensions.toml");
    let current = fs::read_to_string(&ext).unwrap_or_default();
    // An older install listened for fewer events: hear testing sign-offs (D87) and discards (D89) too.
    let now = "events = [\"sealed\", \"finished\", \"gate\", \"landed\", \"approval_needed\", \"tested\", \"discarded\"]";
    let older = ["events = [\"sealed\", \"finished\", \"gate\", \"landed\", \"approval_needed\"]", "events = [\"sealed\", \"finished\", \"gate\", \"landed\", \"approval_needed\", \"tested\"]"];
    if let Some(old) = older.iter().find(|o| current.contains(&me) && current.contains(*o)) {
        fs::write(&ext, current.replace(old, now))?;
        println!("Updated the event listener in {}.", ext.display());
    } else if !current.contains(&me) {
        let entry = format!("\n# The 05 console helper hears what happened: identifiers, verdicts and testing notes, sealed to your console's key before they leave.\n[[on]]\n{now}\nrun = [{me:?}, \"event\"]\ntimeout_secs = 3\n");
        fs::write(&ext, format!("{current}{entry}"))?;
        println!("Added the event listener to {}.", ext.display());
    }
    Ok(())
}

fn install() -> Result<()> {
    let c = load()?;
    let me = std::env::current_exe()?.canonicalize()?.to_string_lossy().to_string();
    listen(&me)?;
    let log = home()?.join("cloud.log");
    let path_env = format!("{}:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin", Path::new(&c.use05).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default());
    let log_s = log.to_string_lossy().to_string();
    if cfg!(target_os = "macos") {
        let agents = PathBuf::from(std::env::var("HOME")?).join("Library/LaunchAgents");
        fs::create_dir_all(&agents)?;
        let plist = agents.join("dev.use05.cloud.plist");
        fs::write(&plist, cloud::service::launchd_plist(&me, &path_env, &log_s))?;
        let uid = String::from_utf8(std::process::Command::new("id").arg("-u").output()?.stdout)?.trim().to_string();
        let _ = std::process::Command::new("launchctl").args(["bootout", &format!("gui/{uid}/dev.use05.cloud")]).output();
        let loaded = std::process::Command::new("launchctl").args(["bootstrap", &format!("gui/{uid}"), &plist.to_string_lossy()]).status()?;
        if !loaded.success() {
            bail!("launchctl could not start the helper; see {}", plist.display());
        }
        println!("Running in the background (launchd: dev.use05.cloud). Log: {}", log.display());
        return Ok(());
    }
    // Linux: a systemd user unit, started with your session and restarted if it stops.
    let config = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config"));
    let units = config.join("systemd/user");
    let systemctl = |args: &[&str]| std::process::Command::new("systemctl").arg("--user").args(args).status().map(|s| s.success()).unwrap_or(false);
    if which("systemctl").is_some() {
        fs::create_dir_all(&units)?;
        let unit = units.join("use05-cloud.service");
        fs::write(&unit, cloud::service::systemd_unit(&me, &path_env, &log_s))?;
        if systemctl(&["daemon-reload"]) && systemctl(&["enable", "--now", "use05-cloud.service"]) {
            println!("Running in the background (systemd --user: use05-cloud). Log: {}\nTo keep it running while you are logged out: loginctl enable-linger $USER", log.display());
            return Ok(());
        }
        println!("Wrote {}, but systemd --user would not start it (no user session here?).", unit.display());
    }
    println!("Run the helper under your own supervisor, as yourself:\n  {me:?} run >> {log_s:?} 2>&1\nFor example, in a container: a process manager entry, or `nohup {me:?} run &`.");
    Ok(())
}

fn spool() -> Result<PathBuf> {
    let dir = home()?.join("cloud-spool");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// The event listener: keep the line for the running helper and return at once.
fn event() -> Result<()> {
    let mut line = String::new();
    std::io::stdin().take(64 * 1024).read_to_string(&mut line)?;
    if serde_json::from_str::<Value>(line.trim()).is_err() {
        return Ok(());
    }
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let name = format!("{nanos}-{}.json", std::process::id());
    let tmp = spool()?.join(format!(".{name}"));
    fs::write(&tmp, line.trim())?;
    fs::rename(&tmp, spool()?.join(name))?;
    Ok(())
}

fn status() -> Result<()> {
    let c = load()?;
    println!("Console: {}\nMachine: {}\nuse05:   {} ({})", c.url, c.machine, c.use05, report::use05_version(&c).unwrap_or_else(|| "not found".into()));
    for r in &c.repos {
        println!("Repo:    {r}");
    }
    let pinned = use05_core::keys::pinned_passkeys();
    println!("Passkeys pinned here: {}", pinned.len());
    let running = |cmd: &str, args: &[&str]| std::process::Command::new(cmd).args(args).output().map(|o| o.status.success()).unwrap_or(false);
    let how = if cfg!(target_os = "macos") {
        let uid = std::process::Command::new("id").arg("-u").output().ok().and_then(|o| String::from_utf8(o.stdout).ok()).unwrap_or_default();
        if running("launchctl", &["print", &format!("gui/{}/dev.use05.cloud", uid.trim())]) { "in the background (launchd)" } else { "not in the background: use05 cloud install" }
    } else if running("systemctl", &["--user", "is-active", "--quiet", "use05-cloud.service"]) {
        "in the background (systemd --user)"
    } else {
        "not as a systemd user service: use05 cloud install, or run it under your own supervisor"
    };
    println!("Helper:  {how}");
    println!("Keys:    files in {} (owner only); an agent running as you can read them", home()?.display());
    let api = Api::new(c);
    match api.post("/hello", json!({ "use05_version": report::use05_version(&api.c) })) {
        Ok(_) => println!("The console answers."),
        Err(e) => println!("{e:#}"),
    }
    Ok(())
}

fn run() -> Result<()> {
    let mut api = Api::new(load()?);
    let _ = api.post("/hello", json!({ "use05_version": report::use05_version(&api.c) }));
    if let Err(e) = id_key(&api) {
        eprintln!("keys: {e:#}");
    }
    if let Err(e) = report::sync_all(&api, true) {
        eprintln!("sync: {e:#}");
    }
    let spool_api = Api::new(api.c.clone());
    std::thread::spawn(move || {
        let mut tick = 0u32;
        loop {
            if let Err(e) = report::drain(&spool_api, &spool().unwrap_or_default()) {
                eprintln!("events: {e:#}");
            }
            tick += 1;
            if tick % 20 == 0 {
                if let Err(e) = report::sync_all(&spool_api, false) {
                    eprintln!("sync: {e:#}");
                }
            }
            std::thread::sleep(Duration::from_secs(3));
        }
    });
    loop {
        match api.get("/poll") {
            Ok(v) => {
                for i in v["instructions"].as_array().into_iter().flatten() {
                    let id = i["id"].as_str().unwrap_or_default();
                    // What the team sent this machine comes sealed to its key: open it here.
                    let payload = match open_instruction(i["kind"].as_str().unwrap_or(""), &i["payload"]) {
                        Ok(p) => p,
                        Err(e) => {
                            let _ = api.post(&format!("/done/{id}"), json!({ "ok": false, "result": {} }));
                            eprintln!("instruction: {e:#}");
                            continue;
                        }
                    };
                    let kind = i["kind"].as_str().unwrap_or("");
                    let handled = if kind == "rotate" { take_team_key(&mut api, &payload) } else { repo::handle(&api, kind, &payload) };
                    let (ok, result) = match handled {
                        Ok(r) => (true, r),
                        Err(e) => {
                            // The console gets the reason sealed; this machine's log keeps it too.
                            eprintln!("{kind}: {e:#}");
                            (false, json!({ "reason": format!("{e:#}") }))
                        }
                    };
                    // The result goes back sealed to the team and signed, like a report.
                    let reference = payload["request"].as_str().or(payload["edit"].as_str()).or(payload["signoff"].as_str()).or(payload["discard"].as_str()).unwrap_or("");
                    let sealed = api.sealed("result", payload["repo"].as_str().unwrap_or(""), reference, &json!({ "ok": ok, "result": result })).map(|(s, g)| json!({ "sealed": s, "sig": g })).unwrap_or_else(|_| json!({}));
                    if let Err(e) = api.post(&format!("/done/{id}"), json!({ "ok": ok, "result": sealed })) {
                        eprintln!("done: {e:#}");
                    }
                }
            }
            Err(e) => {
                eprintln!("poll: {e:#}");
                std::thread::sleep(Duration::from_secs(10));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_never_replaces_the_keys_of_a_machine_paired_at_a_terminal() {
        let home = tempfile::tempdir().unwrap();
        assert!(!paired_here(home.path()), "nothing here yet");
        fs::write(home.path().join("cloud-ed25519.key"), "k").unwrap();
        assert!(paired_here(home.path()), "keys and no settings: a machine's, settings lost");
        fs::write(home.path().join("cloud.toml"), "not toml [").unwrap();
        assert!(paired_here(home.path()), "settings that cannot be read");
        let c = |kind: &str| format!("url = \"u\"\ntoken = \"t\"\nmachine = \"m\"\nuse05 = \"use05\"\nrepos = []\nteam_pub = \"\"\nteam_version = 1\nkind = \"{kind}\"\n");
        fs::write(home.path().join("cloud.toml"), c("machine")).unwrap();
        assert!(paired_here(home.path()));
        fs::write(home.path().join("cloud.toml"), c("session")).unwrap();
        assert!(!paired_here(home.path()), "a session's own keys may be replaced by its next token");
    }

    #[test]
    fn the_sequence_goes_up_even_when_the_clock_goes_back() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("cloud-seq");
        let ahead = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64 + 3_600_000_000;
        fs::write(&file, ahead.to_string()).unwrap();
        let a = next_seq_in(&file);
        let b = next_seq_in(&file);
        assert!(a > ahead && b > a, "{ahead} {a} {b}");
    }
}
