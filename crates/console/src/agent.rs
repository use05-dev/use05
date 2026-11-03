//! The helpers' side: pairing, reporting what happened, and collecting instructions.
//! A helper connects out to here; the console never reaches into a machine.

use std::time::Duration;

use axum::extract::{FromRequestParts, Path, State};
use axum::http::{HeaderMap, header};
use axum::http::request::Parts;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use crate::db::Uuid;
use sqlx::SqlitePool;

use crate::util::{Fail, Res, bad, denied, hash, ok, token};
use crate::{Shared, alerts};

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/claim", post(claim_console))
        .route("/pair/start", post(pair_start))
        .route("/pair/poll", post(pair_poll))
        .route("/pair/reveal", post(pair_reveal))
        .route("/hello", post(hello))
        .route("/record", post(record))
        .route("/approval", post(approval))
        .route("/poll", get(poll))
        .route("/done/{id}", post(done))
        .route("/passkeys", get(passkeys))
}

/// A paired, not revoked machine, by its bearer token.
pub struct Machine {
    pub id: Uuid,
    pub name: String,
    /// The member who paired it: the driver of the work done on it.
    pub member: Option<Uuid>,
    /// `machine`, `session` (a cloud agent session) or `ci`.
    pub kind: String,
    /// A session or CI token speaks for this repository only.
    pub repo_only: Option<String>,
}

impl Machine {
    /// A session or CI token may not speak for any repository but its own.
    pub fn may_speak_for(&self, repo: &str) -> Result<(), Fail> {
        match &self.repo_only {
            Some(only) if only != repo => Err(crate::util::forbidden("this token reports for another repository")),
            _ => Ok(()),
        }
    }
}

impl FromRequestParts<Shared> for Machine {
    type Rejection = Fail;
    async fn from_request_parts(parts: &mut Parts, app: &Shared) -> Result<Machine, Fail> {
        let bearer = parts.headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).ok_or_else(|| denied("this machine is not paired"))?;
        let row: Option<(Uuid, String, Option<Uuid>, String, Option<String>)> = sqlx::query_as("update machines set last_seen = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where token_hash = ?1 and not revoked returning id, name, member_id, kind, repo_only").bind(hash(bearer.trim())).fetch_optional(&app.db).await?;
        let m = row.map(|(id, name, member, kind, repo_only)| Machine { id, name, member, kind, repo_only }).ok_or_else(|| denied("this machine's pairing was revoked or never existed; run: use05 cloud login"))?;
        current(&app.db, &m).await?;
        Ok(m)
    }
}

/// A token (a session's or CI's) seals to the team key it was made under, and is never sent the
/// new one: once the key changes, someone who left could read what it sends. A paired machine
/// takes the new key when it next polls.
pub async fn current(db: &SqlitePool, m: &Machine) -> Result<(), Fail> {
    if m.kind == "machine" {
        return Ok(());
    }
    let stale: bool = sqlx::query_scalar("select coalesce(m.team_version, 0) < (select coalesce(max(version), 0) from team) from machines m where m.id = ?1").bind(m.id).fetch_one(db).await?;
    if stale { Err(denied("the team's key changed since this token was made; make a new token on the console's Machines page")) } else { Ok(()) }
}

/// Which machine should do something for a repository: the allowed paired machine heard from most
/// recently. A token (a session's or CI's) is never chosen: it takes no work.
pub async fn machine_for(db: &SqlitePool, repo: &str) -> Result<Option<Uuid>, Fail> {
    Ok(sqlx::query_scalar("select m.id from repo_machines rm join machines m on m.id = rm.machine_id where rm.repo_id = ?1 and rm.allowed and not m.revoked and m.kind = 'machine' order by m.last_seen desc nulls last limit 1").bind(repo).fetch_optional(db).await?)
}

/// A machine may write about a repository only if it speaks for it. Otherwise a token taken from
/// one machine could rewrite what another machine's repository asks the owner to sign.
async fn speaks_for(app: &Shared, m: &Machine, repo: &str) -> Result<(), Fail> {
    let allowed: Option<bool> = sqlx::query_scalar("select allowed from repo_machines where repo_id = ?1 and machine_id = ?2").bind(repo).bind(m.id).fetch_optional(&app.db).await?;
    if allowed == Some(true) { Ok(()) } else { Err(denied("this machine does not speak for that repository; allow it on the console's Machines page")) }
}

/// Ask a machine to do something. A session is sent nothing, and CI only approvals to collect.
pub async fn instruct(db: &SqlitePool, machine: Uuid, kind: &str, payload: Value) -> Result<Uuid, Fail> {
    let to: Option<String> = sqlx::query_scalar("select kind from machines where id = ?1").bind(machine).fetch_optional(db).await?;
    match to.as_deref() {
        Some("machine") => {}
        Some("ci") if kind == "file_approval" => {}
        _ => return Err(bad("that is not a machine that takes work; pick one paired at a terminal")),
    }
    let id = Uuid::new_v4();
    sqlx::query("insert into instructions (id, machine_id, kind, payload) values (?1, ?2, ?3, ?4)").bind(id).bind(machine).bind(kind).bind(payload).execute(db).await?;
    Ok(id)
}

/// Keep a record as it came. A token may replace what it or another token reported, never what a
/// paired machine did: a cloud agent holding a token could otherwise rewrite the laptop's view.
/// Whether it was kept.
pub async fn store_record(db: &SqlitePool, m: &Machine, kind: &str, repo: &str, ref_key: &str, sealed: &[u8], sig: &[u8]) -> Result<bool, Fail> {
    let done = sqlx::query("insert into records (kind, repo_ref, ref_key, machine_id, sealed, sig) values (?1, ?2, ?3, ?4, ?5, ?6) on conflict (kind, repo_ref, ref_key) do update set machine_id = ?4, sealed = ?5, sig = ?6, at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where ?7 or records.machine_id = ?4 or coalesce((select kind from machines where id = records.machine_id), 'machine') <> 'machine'")
        .bind(kind)
        .bind(repo)
        .bind(ref_key)
        .bind(m.id)
        .bind(sealed)
        .bind(sig)
        .bind(m.kind == "machine")
        .execute(db)
        .await?;
    Ok(done.rows_affected() > 0)
}

#[derive(Deserialize)]
struct ClaimIn {
    code: String,
}

/// A fresh console, claimed at a terminal with the code from its log: a one-time link for the
/// owner's browser to make the first passkey with. The link is in the address's fragment, which
/// browsers never send to a server, so it stays out of any proxy's logs.
async fn claim_console(State(app): State<Shared>, headers: HeaderMap, Json(c): Json<ClaimIn>) -> Res {
    app.limits.check(&headers, "claim", 5, 600)?;
    let owned: i64 = sqlx::query_scalar("select count(*) from passkeys").fetch_one(&app.db).await?;
    if owned > 0 {
        return Err(bad("this console has an owner already; sign in to it, then pair this machine"));
    }
    let link = app.claims.claim(&c.code).ok_or_else(|| crate::util::forbidden("that claim code is not right; the console writes it to its log when it starts"))?;
    Ok(Json(json!({ "url": format!("{}/#claim={link}", app.site.origin) })))
}

#[derive(Deserialize)]
struct PairStart {
    name: String,
    /// What the machine commits to: its keys and its nonce, revealed once the browser's nonce is in.
    commit: String,
    /// SHA-256 of the word its terminal shows; whoever types the word claims the machine.
    word_hash: String,
}

async fn pair_start(State(app): State<Shared>, headers: HeaderMap, Json(body): Json<PairStart>) -> Res {
    app.limits.check(&headers, "pair", 5, 600)?;
    sqlx::query("delete from pairings where created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-15 minutes') and token is null").execute(&app.db).await?;
    let waiting: i64 = sqlx::query_scalar("select count(*) from pairings where not approved and not denied").fetch_one(&app.db).await?;
    if waiting >= 5 {
        return Err(bad("too many machines are waiting to be paired; approve or deny them in the console first"));
    }
    let team: Option<(i32, Vec<u8>)> = sqlx::query_as("select version, public from team order by version desc limit 1").fetch_optional(&app.db).await?;
    let Some((team_version, team_pub)) = team else { return Err(bad("this console has no team keys yet: sign in to it once")) };
    let commit = crate::keys::unb64(&body.commit)?;
    if commit.len() != 32 || body.word_hash.len() != 64 {
        return Err(bad("a pairing needs a commitment and the hash of a word"));
    }
    let secret = token();
    let id = Uuid::new_v4();
    let name = plain(&body.name, 60);
    sqlx::query("insert into pairings (id, machine_name, poll_secret_hash, commit_hash, word_hash) values (?1, ?2, ?3, ?4, ?5)").bind(id).bind(&name).bind(hash(&secret)).bind(&commit).bind(&body.word_hash).execute(&app.db).await?;
    Ok(Json(json!({ "pair_id": id, "poll_secret": secret, "team_pub": crate::keys::b64(&team_pub), "team_version": team_version })))
}

#[derive(Deserialize)]
struct PairPoll {
    pair_id: Uuid,
    poll_secret: String,
}

async fn pair_poll(State(app): State<Shared>, headers: HeaderMap, Json(body): Json<PairPoll>) -> Res {
    app.limits.check(&headers, "pair-poll", 400, 600)?;
    let row: Option<(bool, bool, Option<String>, Option<Vec<u8>>)> = sqlx::query_as("select approved, denied, token, browser_nonce from pairings where id = ?1 and poll_secret_hash = ?2").bind(body.pair_id).bind(hash(&body.poll_secret)).fetch_optional(&app.db).await?;
    match row {
        None => Err(denied("this pairing expired; run use05 cloud login again")),
        Some((_, true, _, _)) => Err(denied("the pairing was denied in the console")),
        Some((true, _, Some(t), _)) => {
            sqlx::query("update pairings set token = null where id = ?1").bind(body.pair_id).execute(&app.db).await?;
            Ok(Json(json!({ "token": t })))
        }
        Some((_, _, _, Some(nonce))) => Ok(Json(json!({ "waiting": true, "browser_nonce": crate::keys::b64(&nonce) }))),
        _ => Ok(Json(json!({ "waiting": true }))),
    }
}

#[derive(Deserialize)]
struct PairReveal {
    pair_id: Uuid,
    poll_secret: String,
    x_pub: String,
    ed_pub: String,
    nonce: String,
}

/// The machine reveals what it committed to, once someone claimed it and sent a nonce.
async fn pair_reveal(State(app): State<Shared>, headers: HeaderMap, Json(body): Json<PairReveal>) -> Res {
    app.limits.check(&headers, "pair-poll", 400, 600)?;
    let row: Option<(Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as("select commit_hash, browser_nonce, machine_nonce from pairings where id = ?1 and poll_secret_hash = ?2 and not approved and not denied").bind(body.pair_id).bind(hash(&body.poll_secret)).fetch_optional(&app.db).await?;
    let Some((commit, Some(_), None)) = row else { return Err(bad("nothing to reveal: the pairing was not claimed, was revealed already, or expired")) };
    let key = |t: &str| -> Result<[u8; 32], Fail> { crate::keys::unb64(t)?.try_into().map_err(|_| bad("a public key is 32 bytes")) };
    let (x_pub, ed_pub) = (key(&body.x_pub)?, key(&body.ed_pub)?);
    let nonce: [u8; 16] = crate::keys::unb64(&body.nonce)?.try_into().map_err(|_| bad("a nonce is 16 bytes"))?;
    if cloud::seal::pair_commit(&x_pub, &ed_pub, &nonce)[..] != commit[..] {
        return Err(bad("that is not what the machine committed to"));
    }
    sqlx::query("update pairings set x_pub = ?2, ed_pub = ?3, machine_nonce = ?4 where id = ?1").bind(body.pair_id).bind(&x_pub[..]).bind(&ed_pub[..]).bind(&nonce[..]).execute(&app.db).await?;
    ok()
}

#[derive(Deserialize)]
struct Hello {
    use05_version: Option<String>,
}

/// What a machine needs from the console: the team's key it pinned at pairing, and the team's id
/// key, which the owner's browser sealed to this machine when approving it.
async fn hello(State(app): State<Shared>, m: Machine, Json(body): Json<Hello>) -> Res {
    sqlx::query("update machines set use05_version = ?2 where id = ?1").bind(m.id).bind(body.use05_version).execute(&app.db).await?;
    let id_key: Option<Vec<u8>> = sqlx::query_scalar("select sealed_id_key from machines where id = ?1").bind(m.id).fetch_one(&app.db).await?;
    let team: Option<(i32, Vec<u8>)> = sqlx::query_as("select version, public from team order by version desc limit 1").fetch_optional(&app.db).await?;
    Ok(Json(json!({
        "name": m.name, "rp_id": app.site.rp_id,
        "sealed_id_key": id_key.map(|k| crate::keys::b64(&k)),
        "team": team.map(|(v, p)| json!({ "version": v, "public": crate::keys::b64(&p) })),
    })))
}

/// Text a machine supplies, as one plain line.
fn plain(text: &str, max: usize) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(max).collect::<String>().trim().to_string()
}

fn safe_id(id: &str) -> Result<(), Fail> {
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric()) { Err(bad("bad repository id")) } else { Ok(()) }
}

const KINDS: &[&str] = &["repo", "tree", "task", "event", "refusal", "ci"];
const MAX_SEALED: usize = 4 * 1024 * 1024;

#[derive(Deserialize)]
struct RecordIn {
    kind: String,
    repo: String,
    #[serde(rename = "ref", default)]
    ref_key: String,
    sealed: String,
    sig: String,
}

fn opaque(sealed: &str, sig: &str) -> Result<(Vec<u8>, Vec<u8>), Fail> {
    let sealed = crate::keys::unb64(sealed)?;
    let sig = crate::keys::unb64(sig)?;
    if sealed.is_empty() || sealed.len() > MAX_SEALED || sig.len() != 64 {
        return Err(bad("a record is a sealed body and a 64-byte signature"));
    }
    Ok((sealed, sig))
}

/// The first machine to report a repository speaks for it; another one waits for an admin.
async fn claim(app: &Shared, m: &Machine, repo: &str) -> Result<bool, Fail> {
    let mine: Option<bool> = sqlx::query_scalar("select allowed from repo_machines where repo_id = ?1 and machine_id = ?2").bind(repo).bind(m.id).fetch_optional(&app.db).await?;
    let taken: bool = sqlx::query_scalar("select exists (select 1 from repo_machines rm join machines x on x.id = rm.machine_id where rm.repo_id = ?1 and rm.allowed and not x.revoked and x.id <> ?2)").bind(repo).bind(m.id).fetch_one(&app.db).await?;
    let allowed = mine.unwrap_or(!taken);
    sqlx::query("insert into repos (id) values (?1) on conflict (id) do update set updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')").bind(repo).execute(&app.db).await?;
    if !allowed {
        if mine.is_none() {
            sqlx::query("insert into repo_machines (repo_id, machine_id, allowed) values (?1, ?2, false) on conflict do nothing").bind(repo).bind(m.id).execute(&app.db).await?;
            alerts::queue(app, None, "claim", "05: something needs you", "A machine wants to report a repository another machine already reports. Open your console to see which.", "/machines").await;
        }
        return Ok(false);
    }
    sqlx::query("insert into repo_machines (repo_id, machine_id, allowed) values (?1, ?2, true) on conflict (repo_id, machine_id) do update set last_seen = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')").bind(repo).bind(m.id).execute(&app.db).await?;
    Ok(true)
}

/// A sealed, signed record from a machine. The console stores it as it came: it cannot read it,
/// and the team's browsers check the signature against the machine's pinned key.
async fn record(State(app): State<Shared>, m: Machine, Json(r): Json<RecordIn>) -> Res {
    if !KINDS.contains(&r.kind.as_str()) {
        return Err(bad("not a kind of record the console keeps"));
    }
    safe_id(&r.repo)?;
    m.may_speak_for(&r.repo)?;
    if !r.ref_key.is_empty() {
        safe_id(&r.ref_key)?;
    }
    let (sealed, sig) = opaque(&r.sealed, &r.sig)?;
    if r.kind == "repo" {
        if !claim(&app, &m, &r.repo).await? {
            return Ok(Json(json!({ "waiting": "another machine already reports this repository; an admin allows this one on the console's Machines page" })));
        }
    } else {
        speaks_for(&app, &m, &r.repo).await?;
    }
    if !store_record(&app.db, &m, &r.kind, &r.repo, &r.ref_key, &sealed, &sig).await? {
        return Ok(Json(json!({ "kept": "a machine paired at a terminal reported this; a token does not replace it" })));
    }
    if r.kind == "refusal" {
        // A machine refused something the console asked; its words stay sealed, and on the machine.
        crate::auth::audit(&app, &format!("machine:{}", m.name), "refused", json!({})).await;
        alerts::queue(&app, m.member, "refusal", "05: something needs you", "One of your machines refused something the console asked of it. Open your console to see what.", "/machines").await;
    }
    ok()
}

#[derive(Deserialize)]
struct ApprovalIn {
    repo: String,
    #[serde(rename = "ref")]
    ref_key: String,
    sealed: String,
    sig: String,
}

/// A machine asks its driver to approve something: the statement is sealed to the team.
async fn approval(State(app): State<Shared>, m: Machine, Json(a): Json<ApprovalIn>) -> Res {
    m.may_speak_for(&a.repo)?;
    speaks_for(&app, &m, &a.repo).await?;
    safe_id(&a.ref_key)?;
    let (sealed, sig) = opaque(&a.sealed, &a.sig)?;
    let existing: Option<(Uuid, String, Option<Uuid>)> = sqlx::query_as("select id, status, machine_id from approval_requests where repo_id = ?1 and ref_key = ?2").bind(&a.repo).bind(&a.ref_key).fetch_optional(&app.db).await?;
    if let Some((id, status, machine)) = existing {
        // Asked again: the machine that asked may refresh its own request unless it was signed.
        if machine == Some(m.id) && (status == "waiting" || status == "failed") {
            sqlx::query("update approval_requests set sealed = ?2, sig = ?3, status = 'waiting', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1").bind(id).bind(&sealed).bind(&sig).execute(&app.db).await?;
        }
        return ok();
    }
    let new_id = Uuid::new_v4();
    // Asked twice at once: the first one stands.
    let added = sqlx::query("insert into approval_requests (id, repo_id, machine_id, ref_key, sealed, sig) values (?1, ?2, ?3, ?4, ?5, ?6) on conflict do nothing").bind(new_id).bind(&a.repo).bind(m.id).bind(&a.ref_key).bind(&sealed).bind(&sig).execute(&app.db).await?;
    if added.rows_affected() == 0 {
        return ok();
    }
    alerts::queue(&app, m.member, "approval", "05: something needs you", "An agent is waiting for your approval. Open your console to see what.", &format!("/approvals/{new_id}")).await;
    ok()
}

/// Wait up to 25 seconds for something to do. Unfinished instructions are offered again after a
/// minute, so a helper that restarted mid-way picks them up.
#[derive(Deserialize)]
struct PollQuery {
    /// Answer at once rather than waiting: CI collects what is there and moves on.
    #[serde(default)]
    once: bool,
}

async fn poll(State(app): State<Shared>, m: Machine, axum::extract::Query(q): axum::extract::Query<PollQuery>) -> Res {
    // A cloud session runs nothing it is sent, and is sent nothing.
    if m.kind == "session" {
        return Ok(Json(json!({ "instructions": [] })));
    }
    let _open = app.limits.polling(m.id.0).ok_or_else(|| crate::util::too_many("this machine is already polling"))?;
    for _ in 0..(if q.once { 1 } else { 25 }) {
        let rows = sqlx::query("select id, kind, payload from instructions where machine_id = ?1 and done_at is null and (delivered_at is null or delivered_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-60 seconds')) order by created_at limit 10").bind(m.id).fetch_all(&app.db).await?;
        let found = crate::db::rows_json(&rows);
        if found.as_array().is_some_and(|a| !a.is_empty()) {
            let ids: Vec<&str> = found.as_array().unwrap().iter().filter_map(|i| i["id"].as_str()).collect();
            sqlx::query("update instructions set delivered_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id in (select value from json_each(?1))").bind(serde_json::to_string(&ids).unwrap_or_default()).execute(&app.db).await?;
            return Ok(Json(json!({ "instructions": found })));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(Json(json!({ "instructions": [] })))
}

#[derive(Deserialize)]
struct Done {
    ok: bool,
    #[serde(default)]
    result: Value,
}

async fn done(State(app): State<Shared>, m: Machine, Path(id): Path<Uuid>, Json(d): Json<Done>) -> Res {
    let row: Option<(String, Value)> = sqlx::query_as("update instructions set done_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), result = ?3 where id = ?1 and machine_id = ?2 and done_at is null returning kind, payload").bind(id).bind(m.id).bind(json!({ "ok": d.ok, "result": d.result })).fetch_optional(&app.db).await?;
    let Some((kind, payload)) = row else { return ok() };
    match kind.as_str() {
        "file_approval" => {
            let request: Uuid = payload["request"].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| bad("no request"))?;
            let status = if d.ok { "filed" } else { "failed" };
            sqlx::query("update approval_requests set status = ?2, result = ?3, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1").bind(request).bind(status).bind(&d.result).execute(&app.db).await?;
        }
        "prepare_policy_edit" | "apply_policy_edit" => {
            let edit: Uuid = payload["edit"].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| bad("no edit"))?;
            let (status, prepared) = match (kind.as_str(), d.ok) {
                ("prepare_policy_edit", true) => ("ready", Some(d.result.clone())),
                ("apply_policy_edit", true) => ("applied", None),
                // Why it is stuck stays sealed with the rest; the browser opens it.
                _ => ("stuck", Some(d.result.clone())),
            };
            sqlx::query("update policy_edits set status = ?2, prepared = coalesce(?3, prepared), reason = ?4, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1")
                .bind(edit)
                .bind(status)
                .bind(prepared)
                .bind(None::<String>)
                .execute(&app.db)
                .await?;
            if !d.ok {
                let owner: Option<Uuid> = sqlx::query_scalar("select member_id from policy_edits where id = ?1").bind(edit).fetch_one(&app.db).await.unwrap_or(None);
                alerts::queue(&app, owner, "edit_stuck", "05: something needs you", "A policy edit of yours could not be applied. Open your console to see why.", &format!("/edits/{edit}")).await;
            }
        }
        "prepare_testing" | "file_testing" => {
            let signoff: Uuid = payload["signoff"].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| bad("no sign-off"))?;
            let status = match (kind.as_str(), d.ok) {
                ("prepare_testing", true) => "ready",
                ("file_testing", true) => "filed",
                _ => "stuck",
            };
            // What the machine said stays sealed; the browser opens it.
            sqlx::query("update signoffs set status = ?2, prepared = case when ?2 = 'filed' then prepared else ?3 end, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1").bind(signoff).bind(status).bind(&d.result).execute(&app.db).await?;
        }
        "prepare_discard" | "discard" => {
            let discard: Uuid = payload["discard"].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| bad("no discard"))?;
            let status = match (kind.as_str(), d.ok) {
                ("prepare_discard", true) => "ready",
                ("discard", true) => "done",
                _ => "stuck",
            };
            // What the machine said stays sealed; the browser opens it.
            sqlx::query("update discards set status = ?2, prepared = ?3, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1").bind(discard).bind(status).bind(&d.result).execute(&app.db).await?;
        }
        "rotate" if d.ok => {
            sqlx::query("update machines set team_version = max(coalesce(team_version, 0), ?2) where id = ?1").bind(m.id).bind(payload["version"].as_i64().unwrap_or(0) as i32).execute(&app.db).await?;
        }
        _ => {}
    }
    ok()
}

/// The passkeys of the member this machine belongs to: only theirs may approve work done on it.
async fn passkeys(State(app): State<Shared>, m: Machine) -> Res {
    if m.kind != "machine" {
        return Err(crate::util::forbidden("only a paired machine pins passkeys"));
    }
    let rows: Vec<(String, Vec<u8>, chrono::DateTime<chrono::Utc>, String)> = sqlx::query_as("select p.name, p.sec1, p.created_at, mb.name from passkeys p join members mb on mb.id = p.member_id where p.member_id = ?1 order by p.created_at").bind(m.member).fetch_all(&app.db).await?;
    let keys: Vec<Value> = rows
        .iter()
        .filter_map(|(name, sec1, at, person)| use05_receipt::PasskeyKey::from_sec1(&app.site.rp_id, sec1).ok().map(|k| (name, k, at, person)))
        .map(|(name, k, at, person)| json!({ "name": name, "public": use05_receipt::passkey_public_text(&k).trim(), "id": use05_receipt::PublicKey::Passkey(k).id(), "created_at": at.format("%Y-%m-%d").to_string(), "person": person }))
        .collect();
    Ok(Json(json!({ "passkeys": keys })))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> sqlx::SqlitePool {
        let db = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        sqlx::query("insert into team (version, public) values (1, x'00')").execute(&db).await.unwrap();
        sqlx::query("insert into repos (id) values ('r1')").execute(&db).await.unwrap();
        db
    }

    /// A machine or a token speaking for repository r1, last heard `seen` minutes ago.
    async fn add(db: &sqlx::SqlitePool, kind: &str, seen: i32) -> Machine {
        let id = Uuid::new_v4();
        let repo_only = (kind != "machine").then_some("r1");
        sqlx::query("insert into machines (id, name, token_hash, kind, repo_only, team_version, last_seen) values (?1, ?2, ?3, ?2, ?4, 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?5))").bind(id).bind(kind).bind(id.0.to_string()).bind(repo_only).bind(format!("-{seen} minutes")).execute(db).await.unwrap();
        sqlx::query("insert into repo_machines (repo_id, machine_id, allowed) values ('r1', ?1, 1)").bind(id).execute(db).await.unwrap();
        Machine { id, name: kind.into(), member: None, kind: kind.into(), repo_only: repo_only.map(str::to_string) }
    }

    async fn writer(db: &sqlx::SqlitePool) -> Uuid {
        sqlx::query_scalar("select machine_id from records where kind = 'repo' and repo_ref = 'r1'").fetch_one(db).await.unwrap()
    }

    #[tokio::test]
    async fn work_goes_to_a_paired_machine_never_to_a_token() {
        let db = db().await;
        let laptop = add(&db, "machine", 10).await;
        let session = add(&db, "session", 0).await;
        let ci = add(&db, "ci", 0).await;
        assert_eq!(machine_for(&db, "r1").await.unwrap(), Some(laptop.id), "the session was heard from later, but takes no work");
        assert!(instruct(&db, session.id, "prepare_testing", json!({})).await.is_err());
        assert!(instruct(&db, ci.id, "send_tree", json!({})).await.is_err());
        assert!(instruct(&db, ci.id, "file_approval", json!({})).await.is_ok(), "CI collects approvals");
        assert!(instruct(&db, laptop.id, "prepare_testing", json!({})).await.is_ok());
    }

    #[tokio::test]
    async fn a_token_does_not_overwrite_what_a_machine_reported() {
        let db = db().await;
        let laptop = add(&db, "machine", 0).await;
        let session = add(&db, "session", 0).await;
        assert!(store_record(&db, &laptop, "repo", "r1", "", &[1], &[0; 64]).await.unwrap());
        assert!(!store_record(&db, &session, "repo", "r1", "", &[2], &[0; 64]).await.unwrap(), "kept: the machine's");
        assert_eq!(writer(&db).await, laptop.id);
        // What a token reported first, a machine may replace, and the token its own.
        assert!(store_record(&db, &session, "task", "r1", "t1", &[3], &[0; 64]).await.unwrap());
        assert!(store_record(&db, &session, "task", "r1", "t1", &[4], &[0; 64]).await.unwrap());
        assert!(store_record(&db, &laptop, "task", "r1", "t1", &[5], &[0; 64]).await.unwrap());
        assert!(!store_record(&db, &session, "task", "r1", "t1", &[6], &[0; 64]).await.unwrap());
    }

    #[tokio::test]
    async fn a_token_made_under_an_older_team_key_is_refused() {
        let db = db().await;
        let laptop = add(&db, "machine", 0).await;
        let session = add(&db, "session", 0).await;
        assert!(current(&db, &session).await.is_ok());
        sqlx::query("insert into team (version, public) values (2, x'01')").execute(&db).await.unwrap();
        assert!(current(&db, &session).await.is_err(), "it would seal to a key someone who left holds");
        assert!(current(&db, &laptop).await.is_ok(), "a machine takes the new key when it next polls");
    }
}
