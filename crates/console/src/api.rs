//! The owner's side of the console. Every route here needs a signed-in owner.

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use sha2::Digest;
use serde_json::{Value, json};
use use05_receipt::{PasskeyKey, PublicKey};
use crate::db::Uuid;

use crate::agent::{instruct, machine_for};
use crate::auth::{Member, audit};
use crate::util::{forbidden, Fail, Res, bad, missing, ok, token, hash};
use crate::Shared;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/changes", get(changes))
        .route("/overview", get(overview))
        .route("/records", get(records))
        .route("/repos/{id}", get(repo))
        .route("/repos/{id}/tree/refresh", post(tree_refresh))
        .route("/repos/{id}/policy/save", post(policy_save))
        .route("/approvals/{id}", get(approval))
        .route("/approvals/{id}/sign", post(approval_sign))
        .route("/approvals/{id}/dismiss", post(approval_dismiss))
        .route("/edits/{id}", get(edit))
        .route("/edits/{id}/sign", post(edit_sign))
        .route("/edits/{id}/cancel", post(edit_cancel))
        .route("/repos/{id}/testing", post(signoff_start))
        .route("/reporters", post(reporter_new))
        .route("/repos/{id}/discard", post(discard_start))
        .route("/repos/{id}/ask-approval", post(ask_approval_start))
        .route("/discards/{id}", get(discard_view))
        .route("/discards/{id}/sign", post(discard_sign))
        .route("/forget", post(forget))
        .route("/signoffs/{id}", get(signoff))
        .route("/signoffs/{id}/sign", post(signoff_sign))
        .route("/base", get(base).put(base_save))
        .route("/machines", get(machines))
        .route("/machines/{id}/revoke", post(machine_revoke))
        .route("/machines/{id}/repos/{repo}/allow", post(machine_allow))
        .route("/pairings/{id}/claim", post(pairing_claim))
        .route("/pairings/{id}/approve", post(pairing_approve))
        .route("/pairings/{id}/deny", post(pairing_deny))
        .route("/passkeys", get(passkeys))
        .route("/passkeys/{id}/delete", post(passkey_delete))
        .route("/settings", get(settings))
        .route("/settings/test-email", post(test_email))
}

/// Rows as JSON (bytes as base64), for a query with nothing to bind.
async fn json(app: &Shared, sql: &str) -> Result<Value, Fail> {
    Ok(crate::db::rows_json(&sqlx::query(sql).fetch_all(&app.db).await?))
}

const ONLINE: &str = "(m.last_seen > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-90 seconds'))";

/// What the console can say about the team's work without reading it: who must approve what, and
/// which machines and repositories exist. Everything else the browser opens from `records`.
async fn overview(State(app): State<Shared>, me: Member) -> Res {
    let approvals = json(&app, &format!("select a.id, a.repo_id, a.ref_key, a.machine_id, a.status, a.vote, a.result, a.created_at, a.updated_at, {}, {}, mc.member_id = '{}' as mine, mb.id as driver_id, mb.name as driver from approval_requests a left join machines mc on mc.id = a.machine_id left join members mb on mb.id = mc.member_id where a.status <> 'dismissed' order by a.created_at desc limit 200", "a.sealed as sealed", "a.sig as sig", me.id)).await?;
    let edits = json(&app, "select e.id, e.repo_id, e.status, e.reason, e.updated_at, e.member_id from policy_edits e where e.status in ('waiting', 'preparing', 'ready', 'signed', 'stuck') order by e.updated_at desc").await?;
    let refusals = json(&app, "select at, actor from audit where action = 'refused' and at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-7 days') order by at desc limit 10").await?;
    let pairings = json(&app, &format!("select id, machine_name, created_at, claimed_by is not null as claimed, claimed_by = '{me}' as mine, {} as commit_hash, {} as x_pub, {} as ed_pub, {} as machine_nonce, {} as browser_nonce from pairings where not approved and not denied and created_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-15 minutes') order by created_at", "commit_hash", "x_pub", "ed_pub", "machine_nonce", "browser_nonce", me = me.id)).await?;
    let machines = json(&app, &format!("select m.id, m.name, m.last_seen, m.use05_version, {ONLINE} as online, {}, {}, m.pin, m.team_version, m.member_id, m.kind, m.repo_only from machines m where not m.revoked order by m.last_seen desc nulls last", "m.x_pub as x_pub", "m.ed_pub as ed_pub")).await?;
    let repo_machines = json(&app, "select rm.repo_id, rm.machine_id, rm.allowed from repo_machines rm").await?;
    let team_version: Option<i32> = sqlx::query_scalar("select max(version) from team").fetch_one(&app.db).await?;
    Ok(Json(json!({ "approvals": approvals, "edits": edits, "refusals": refusals, "pairings": pairings, "machines": machines, "repo_machines": repo_machines, "me": me.id, "team_version": team_version })))
}

/// Tell an open page, as it happens, that something changed, so it looks again at once. Only that:
/// the page then asks for what it shows, as before. It ends when the session does.
async fn changes(State(app): State<Shared>, _m: Member, headers: axum::http::HeaderMap) -> axum::response::Sse<impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>> {
    let cookie = crate::auth::cookie_value(&headers).unwrap_or_default();
    let rx = app.changes.subscribe();
    let stream = futures_util::stream::unfold((rx, app, cookie), |(mut rx, app, cookie)| async move {
        loop {
            tokio::select! {
                changed = rx.changed() => {
                    changed.ok()?;
                    // A burst of changes (a machine syncing) is one look.
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    rx.borrow_and_update();
                    return Some((Ok(axum::response::sse::Event::default().data("changed")), (rx, app, cookie)));
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                    crate::auth::session_member(&app.db, &cookie, false).await.ok().flatten()?;
                }
            }
        }
    });
    axum::response::Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

#[derive(Deserialize)]
struct RecordsQuery {
    /// A time the browser got from an earlier answer.
    since: Option<String>,
}

/// Everything machines reported, sealed and signed, newest first. The browser opens it.
async fn records(State(app): State<Shared>, _m: Member, Query(q): Query<RecordsQuery>) -> Res {
    let rows = sqlx::query(RECORDS_SINCE).bind(q.since).fetch_all(&app.db).await?;
    Ok(Json(crate::db::rows_json(&rows)))
}

/// Newest first, after `since`; a `since` that is not a time gives everything, never nothing.
const RECORDS_SINCE: &str = "select kind, repo_ref as repo, ref_key as ref, machine_id as machine, at, sealed, sig from records where (?1 is null or at > coalesce(strftime('%Y-%m-%dT%H:%M:%fZ', ?1), '')) order by at desc limit 5000";

async fn repo(State(app): State<Shared>, _m: Member, Path(id): Path<String>) -> Res {
    let edits: Value = sqlx::query("select id, status, reason, machine_id, prepared, created_at, updated_at from policy_edits where repo_id = ?1 order by created_at desc limit 10").bind(&id).fetch_all(&app.db).await.map(|r| crate::db::rows_json(&r))?;
    let machines: Value = sqlx::query(&format!("select m.id, m.name, m.last_seen, {ONLINE} as online from repo_machines rm join machines m on m.id = rm.machine_id where rm.repo_id = ?1 and not m.revoked order by m.last_seen desc")).bind(&id).fetch_all(&app.db).await.map(|r| crate::db::rows_json(&r))?;
    Ok(Json(json!({ "edits": edits, "machines": machines, "editable": cloud::guard::EDITABLE })))
}

async fn tree_refresh(State(app): State<Shared>, _m: Member, Path(id): Path<String>) -> Res {
    let Some(machine) = machine_for(&app.db, &id).await? else { return Err(bad("no machine has this repository")) };
    instruct(&app.db, machine, "send_tree", json!({ "repo": id })).await?;
    ok()
}

/// A policy edit as the browser sends it (D86): it previewed and checked the edit itself, with the
/// same Rust compiled to WebAssembly; the console sees none of it. The file goes sealed to the
/// editor's own machine, which checks it again against the policy it reads; a copy of the file and
/// of what changed goes sealed to the team, for the edit's page.
#[derive(Deserialize)]
struct EditIn {
    /// Made by the browser, so the machine's sealed copy can name the edit it is for.
    id: Uuid,
    machine: Uuid,
    /// `{ toml, base_rev }`, sealed to the machine.
    sealed: String,
}

async fn policy_save(State(app): State<Shared>, me: Member, Path(id): Path<String>, Json(c): Json<EditIn>) -> Res {
    // Your own machine prepares it: it trusts your passkeys, and the edit is yours to sign.
    let mine: bool = sqlx::query_scalar("select exists (select 1 from repo_machines rm join machines m on m.id = rm.machine_id where rm.repo_id = ?1 and rm.allowed and not m.revoked and m.id = ?2 and m.member_id = ?3 and m.kind = 'machine')").bind(&id).bind(c.machine).bind(me.id).fetch_one(&app.db).await?;
    if !mine {
        return Err(bad("that is not one of your machines with this repository"));
    }
    let edit = c.id;
    let inserted = sqlx::query("insert into policy_edits (id, repo_id, machine_id, status, member_id) values (?1, ?2, ?3, 'preparing', ?4) on conflict (id) do nothing").bind(edit).bind(&id).bind(c.machine).bind(me.id).execute(&app.db).await?;
    if inserted.rows_affected() == 0 {
        return Err(bad("that edit exists already"));
    }
    instruct(&app.db, c.machine, "prepare_policy_edit", json!({ "edit": edit, "repo": id, "sealed": c.sealed })).await?;
    audit(&app, &me.name, "policy_edit", json!({ "repo": id })).await;
    Ok(Json(json!({ "edit": edit })))
}

/// The team's starting template, sealed to the team: the console keeps it and cannot read it.
async fn base(State(app): State<Shared>, _m: Member) -> Res {
    let sealed: Option<String> = sqlx::query_scalar("select toml from base_policy where id = 1").fetch_optional(&app.db).await?;
    Ok(Json(json!({ "sealed": sealed })))
}

#[derive(Deserialize)]
struct BaseIn {
    sealed: String,
}

async fn base_save(State(app): State<Shared>, me: Member, Json(c): Json<BaseIn>) -> Res {
    admin_only(&me, "only an admin can change the base policy")?;
    sqlx::query("insert into base_policy (id, toml) values (1, ?1) on conflict (id) do update set toml = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')").bind(&c.sealed).execute(&app.db).await?;
    audit(&app, &me.name, "base_policy", json!({})).await;
    ok()
}

/// One approval request: its routing, its sealed statement, and the driver's passkeys to sign with.
async fn approval(State(app): State<Shared>, _m: Member, Path(id): Path<Uuid>) -> Res {
    let row: Option<Value> = sqlx::query(&format!("select a.id, a.repo_id, a.ref_key, a.machine_id, a.status, a.vote, a.result, a.created_at, {}, {}, m.name as machine, mb.id as driver_id, mb.name as driver from approval_requests a left join machines m on m.id = a.machine_id left join members mb on mb.id = m.member_id where a.id = ?1", "a.sealed as sealed", "a.sig as sig")).bind(id).fetch_optional(&app.db).await?.map(|r| crate::db::row_json(Some(&r)));
    let row = row.ok_or_else(|| missing("there is no such approval request"))?;
    let keys: Vec<(String,)> = sqlx::query_as("select id from passkeys where member_id = ?1").bind(row["driver_id"].as_str().and_then(|d| d.parse::<Uuid>().ok())).fetch_all(&app.db).await?;
    Ok(Json(json!({ "request": row, "rp_id": app.site.rp_id, "credentials": keys.iter().map(|(k,)| k).collect::<Vec<_>>() })))
}

#[derive(Deserialize)]
struct Signed {
    /// The signed envelope (and, for a policy edit, the commit it approves), sealed by the
    /// browser to the machine's key: the console relays it and cannot read it. The machine checks
    /// everything itself, as it always did.
    sealed: String,
}

/// Only the driver approves their own session's work (D86).
async fn driver_only(app: &Shared, me: &Member, driver: Option<Uuid>) -> Result<Uuid, Fail> {
    match driver {
        Some(d) if d == me.id => Ok(d),
        Some(d) => {
            let name: String = sqlx::query_scalar("select name from members where id = ?1").bind(d).fetch_one(&app.db).await.unwrap_or_else(|_| "its driver".into());
            Err(forbidden(format!("only {name} can approve their own session's work")))
        }
        None => Err(forbidden("the person whose machine this is has left the team")),
    }
}

async fn approval_sign(State(app): State<Shared>, me: Member, Path(id): Path<Uuid>, Json(s): Json<Signed>) -> Res {
    let row: Option<(String, Option<Uuid>, String, Option<Uuid>)> = sqlx::query_as("select a.repo_id, a.machine_id, a.status, m.member_id from approval_requests a left join machines m on m.id = a.machine_id where a.id = ?1").bind(id).fetch_optional(&app.db).await?;
    let Some((repo, machine, status, driver)) = row else { return Err(missing("there is no such approval request")) };
    driver_only(&app, &me, driver).await?;
    if status == "filed" {
        return Err(bad("this approval is already filed"));
    }
    let machine = match machine {
        Some(m) => m,
        None => machine_for(&app.db, &repo).await?.ok_or_else(|| bad("no machine has this repository"))?,
    };
    instruct(&app.db, machine, "file_approval", json!({ "request": id, "repo": repo, "sealed": s.sealed })).await?;
    sqlx::query("update approval_requests set status = 'signed', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1").bind(id).execute(&app.db).await?;
    audit(&app, &me.name, "approval_signed", json!({ "request": id })).await;
    ok()
}

/// Hiding a waiting approval is for its driver, or an admin.
async fn approval_dismiss(State(app): State<Shared>, me: Member, Path(id): Path<Uuid>) -> Res {
    let driver: Option<Option<Uuid>> = sqlx::query_scalar("select m.member_id from approval_requests a left join machines m on m.id = a.machine_id where a.id = ?1").bind(id).fetch_optional(&app.db).await?;
    owner_or_admin(&me, driver.flatten(), "only its driver or an admin can set this approval aside")?;
    sqlx::query("update approval_requests set status = 'dismissed', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1 and status <> 'filed'").bind(id).execute(&app.db).await?;
    audit(&app, &me.name, "approval_dismissed", json!({ "request": id })).await;
    ok()
}

fn owner_or_admin(me: &Member, owner: Option<Uuid>, why: &str) -> Result<(), Fail> {
    if me.role == crate::team::Role::Admin || owner == Some(me.id) { Ok(()) } else { Err(forbidden(why)) }
}

fn admin_only(me: &Member, why: &str) -> Result<(), Fail> {
    owner_or_admin(me, None, why)
}

async fn edit(State(app): State<Shared>, _m: Member, Path(id): Path<Uuid>) -> Res {
    let row: Option<Value> = sqlx::query("select e.*, e.repo_id as repo, m.name as machine from policy_edits e left join machines m on m.id = e.machine_id where e.id = ?1").bind(id).fetch_optional(&app.db).await?.map(|r| crate::db::row_json(Some(&r)));
    let row = row.ok_or_else(|| missing("there is no such policy edit"))?;
    let keys: Vec<(String,)> = sqlx::query_as("select id from passkeys where member_id = ?1").bind(row["member_id"].as_str().and_then(|d| d.parse::<Uuid>().ok())).fetch_all(&app.db).await?;
    Ok(Json(json!({ "edit": row, "rp_id": app.site.rp_id, "credentials": keys.iter().map(|(k,)| k).collect::<Vec<_>>() })))
}

async fn edit_sign(State(app): State<Shared>, me: Member, Path(id): Path<Uuid>, Json(s): Json<Signed>) -> Res {
    let row: Option<(String, Option<Uuid>, Option<Value>, String, Option<Uuid>)> = sqlx::query_as("select repo_id, machine_id, prepared, status, member_id from policy_edits where id = ?1").bind(id).fetch_optional(&app.db).await?;
    let Some((repo, Some(machine), Some(_prepared), status, owner)) = row else { return Err(missing("this edit is not ready to sign")) };
    driver_only(&app, &me, owner).await?;
    if status != "ready" {
        return Err(bad(format!("this edit is {status}, not ready to sign")));
    }
    instruct(&app.db, machine, "apply_policy_edit", json!({ "edit": id, "repo": repo, "sealed": s.sealed })).await?;
    sqlx::query("update policy_edits set status = 'signed', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1").bind(id).execute(&app.db).await?;
    audit(&app, &me.name, "policy_edit_signed", json!({ "edit": id })).await;
    ok()
}

#[derive(Deserialize)]
struct SignoffIn {
    /// Made by the browser, so the machine's sealed copy names the sign-off it is for.
    id: Uuid,
    machine: Uuid,
    /// `{ signoff, repo, task, tree, outcome, note }`, sealed to the machine.
    sealed: String,
}

/// A testing sign-off from a phone (D87): the driver's own machine prepares the statement with the
/// note they typed (sealed to it), their passkey signs it, the machine files it.
async fn signoff_start(State(app): State<Shared>, me: Member, Path(id): Path<String>, Json(c): Json<SignoffIn>) -> Res {
    let mine: bool = sqlx::query_scalar("select exists (select 1 from repo_machines rm join machines m on m.id = rm.machine_id where rm.repo_id = ?1 and rm.allowed and not m.revoked and m.id = ?2 and m.member_id = ?3 and m.kind = 'machine')").bind(&id).bind(c.machine).bind(me.id).fetch_one(&app.db).await?;
    if !mine {
        return Err(forbidden("only the person whose machine did the work signs off testing for it"));
    }
    let inserted = sqlx::query("insert into signoffs (id, repo_id, machine_id, member_id) values (?1, ?2, ?3, ?4) on conflict (id) do nothing").bind(c.id).bind(&id).bind(c.machine).bind(me.id).execute(&app.db).await?;
    if inserted.rows_affected() == 0 {
        return Err(bad("that sign-off exists already"));
    }
    instruct(&app.db, c.machine, "prepare_testing", json!({ "signoff": c.id, "repo": id, "sealed": c.sealed })).await?;
    audit(&app, &me.name, "testing_signoff", json!({ "repo": id })).await;
    Ok(Json(json!({ "signoff": c.id })))
}

/// Work is held for a person but its machine never asked here (the session ended first, say):
/// the person asks for the approval to be prepared, from the console, and signs it there.
async fn ask_approval_start(State(app): State<Shared>, me: Member, Path(id): Path<String>, Json(c): Json<SignoffIn>) -> Res {
    let mine: bool = sqlx::query_scalar("select exists (select 1 from repo_machines rm join machines m on m.id = rm.machine_id where rm.repo_id = ?1 and rm.allowed and not m.revoked and m.id = ?2 and m.member_id = ?3 and m.kind = 'machine')").bind(&id).bind(c.machine).bind(me.id).fetch_one(&app.db).await?;
    if !mine {
        return Err(forbidden("only the person whose machine did the work can ask for its approval"));
    }
    instruct(&app.db, c.machine, "ask_approval", json!({ "ask": c.id, "repo": id, "sealed": c.sealed })).await?;
    audit(&app, &me.name, "approval_asked_for", json!({ "repo": id })).await;
    Ok(Json(json!({ "ask": c.id })))
}

/// Throwing a task's work away from a phone (D89): the machine that holds it prepares the
/// discard with what would be lost, the person's passkey signs it, the machine does it.
async fn discard_start(State(app): State<Shared>, me: Member, Path(id): Path<String>, Json(c): Json<SignoffIn>) -> Res {
    let mine: bool = sqlx::query_scalar("select exists (select 1 from repo_machines rm join machines m on m.id = rm.machine_id where rm.repo_id = ?1 and rm.allowed and not m.revoked and m.id = ?2 and m.member_id = ?3 and m.kind = 'machine')").bind(&id).bind(c.machine).bind(me.id).fetch_one(&app.db).await?;
    if !mine {
        return Err(forbidden("only the person whose machine did the work discards it"));
    }
    let inserted = sqlx::query("insert into discards (id, repo_id, machine_id, member_id) values (?1, ?2, ?3, ?4) on conflict (id) do nothing").bind(c.id).bind(&id).bind(c.machine).bind(me.id).execute(&app.db).await?;
    if inserted.rows_affected() == 0 {
        return Err(bad("that discard exists already"));
    }
    instruct(&app.db, c.machine, "prepare_discard", json!({ "discard": c.id, "repo": id, "sealed": c.sealed })).await?;
    audit(&app, &me.name, "discard_asked", json!({ "repo": id })).await;
    Ok(Json(json!({ "discard": c.id })))
}

/// A discard the machine never answered stops waiting: the page would otherwise say it is
/// working it out for ever (the machine asleep, offline, or not the one that answers for this
/// repository). The request is closed too, so a late answer cannot act on it.
async fn expire_unanswered(db: &sqlx::SqlitePool, id: &str) -> Result<(), Fail> {
    let stopped = sqlx::query("update discards set status = 'stuck', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1 and ((status = 'preparing' and created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-120 seconds')) or (status = 'signed' and updated_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-300 seconds')))").bind(id).execute(db).await?;
    if stopped.rows_affected() > 0 {
        sqlx::query("update instructions set done_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where done_at is null and kind in ('prepare_discard', 'discard') and json_extract(payload, '$.discard') = ?1").bind(id).execute(db).await?;
    }
    Ok(())
}

async fn discard_view(State(app): State<Shared>, _m: Member, Path(id): Path<Uuid>) -> Res {
    expire_unanswered(&app.db, &id.to_string()).await?;
    let row: Option<Value> = sqlx::query("select id, repo_id, machine_id, member_id, status, prepared, created_at, updated_at from discards where id = ?1").bind(id).fetch_optional(&app.db).await?.map(|r| crate::db::row_json(Some(&r)));
    let row = row.ok_or_else(|| missing("there is no such discard"))?;
    let keys: Vec<(String,)> = sqlx::query_as("select id from passkeys where member_id = ?1").bind(row["member_id"].as_str().and_then(|d| d.parse::<Uuid>().ok())).fetch_all(&app.db).await?;
    Ok(Json(json!({ "discard": row, "rp_id": app.site.rp_id, "credentials": keys.iter().map(|(k,)| k).collect::<Vec<_>>() })))
}

async fn discard_sign(State(app): State<Shared>, me: Member, Path(id): Path<Uuid>, Json(s): Json<Signed>) -> Res {
    let row: Option<(String, Option<Uuid>, String, Option<Uuid>)> = sqlx::query_as("select repo_id, machine_id, status, member_id from discards where id = ?1").bind(id).fetch_optional(&app.db).await?;
    let Some((repo, Some(machine), status, owner)) = row else { return Err(missing("this discard is not ready to sign")) };
    driver_only(&app, &me, owner).await?;
    if status != "ready" {
        return Err(bad(format!("this discard is {status}, not ready to sign")));
    }
    instruct(&app.db, machine, "discard", json!({ "discard": id, "repo": repo, "sealed": s.sealed })).await?;
    sqlx::query("update discards set status = 'signed', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1").bind(id).execute(&app.db).await?;
    audit(&app, &me.name, "discard_signed", json!({ "discard": id })).await;
    ok()
}

#[derive(Deserialize)]
struct Forget {
    kind: String,
    #[serde(rename = "ref")]
    ref_key: String,
}

#[derive(Deserialize)]
struct ForgetIn {
    repo: String,
    #[serde(default)]
    records: Vec<Forget>,
    #[serde(default)]
    approvals: Vec<Uuid>,
}

/// What a person's browser, which can read them, found to belong to work they threw away (D89):
/// the console forgets those records. Only what their own machines reported, unless an admin.
async fn forget(State(app): State<Shared>, me: Member, Json(f): Json<ForgetIn>) -> Res {
    if f.records.len() + f.approvals.len() > 2000 {
        return Err(bad("too much to forget at once"));
    }
    let admin = me.role == crate::team::Role::Admin;
    let n = forget_records(&app.db, me.id, admin, &f.repo, &f.records, &f.approvals).await?;
    Ok(Json(json!({ "forgotten": n })))
}

async fn forget_records(db: &sqlx::SqlitePool, member: Uuid, admin: bool, repo: &str, records: &[Forget], approvals: &[Uuid]) -> Result<u64, Fail> {
    let owned = "(?4 or machine_id in (select id from machines where member_id = ?3))";
    let mut tx = db.begin().await?;
    let mut n = 0;
    for r in records {
        n += sqlx::query(&format!("delete from records where repo_ref = ?1 and kind = ?2 and ref_key = ?5 and {owned}")).bind(repo).bind(&r.kind).bind(member).bind(admin).bind(&r.ref_key).execute(&mut *tx).await?.rows_affected();
    }
    for a in approvals {
        n += sqlx::query(&format!("delete from approval_requests where repo_id = ?1 and id = ?2 and {owned}")).bind(repo).bind(a).bind(member).bind(admin).execute(&mut *tx).await?.rows_affected();
    }
    tx.commit().await?;
    Ok(n)
}

#[derive(Deserialize)]
struct ReporterIn {
    /// `session` (a cloud agent session) or `ci`.
    kind: String,
    repo: String,
    name: String,
    x_pub: String,
    ed_pub: String,
    /// The browser's pin over its keys (HMAC under the team's pin key).
    pin: String,
    /// The team's id key, wrapped under the key the team shares with it.
    sealed_id_key: String,
    /// SHA-256 of the bearer token the browser made; the token itself never reaches the console.
    token_hash: String,
    team_version: i32,
}

/// A token for a cloud session or a CI job (D86): keys made in your browser and pinned by the team,
/// reporting as you for one repository. A session is sent nothing; CI only collects approvals.
async fn reporter_new(State(app): State<Shared>, me: Member, Json(r): Json<ReporterIn>) -> Res {
    if !["session", "ci"].contains(&r.kind.as_str()) {
        return Err(bad("a token is for a cloud session or for CI"));
    }
    let known: bool = sqlx::query_scalar("select exists (select 1 from repo_machines rm join machines m on m.id = rm.machine_id where rm.repo_id = ?1 and m.member_id = ?2 and not m.revoked)").bind(&r.repo).bind(me.id).fetch_one(&app.db).await?;
    if !known {
        return Err(forbidden("make a token for a repository one of your machines reports"));
    }
    let key = |t: &str| -> Result<Vec<u8>, Fail> { crate::keys::unb64(t).and_then(|k| if k.len() == 32 { Ok(k) } else { Err(bad("a public key is 32 bytes")) }) };
    let (x_pub, ed_pub) = (key(&r.x_pub)?, key(&r.ed_pub)?);
    if r.token_hash.len() != 64 || r.pin.trim().is_empty() {
        return Err(bad("the token's hash and pin are missing"));
    }
    let current: Option<i32> = sqlx::query_scalar("select max(version) from team").fetch_one(&app.db).await?;
    if current != Some(r.team_version) {
        return Err(bad("the team's key changed meanwhile; unlock again and make the token again"));
    }
    let id = Uuid::new_v4();
    let name = r.name.chars().filter(|c| !c.is_control()).take(60).collect::<String>();
    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("insert into machines (id, name, token_hash, member_id, x_pub, ed_pub, pin, team_version, sealed_id_key, kind, repo_only) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)").bind(id).bind(&name).bind(&r.token_hash).bind(me.id).bind(&x_pub).bind(&ed_pub).bind(r.pin.trim()).bind(r.team_version).bind(crate::keys::unb64(&r.sealed_id_key)?).bind(&r.kind).bind(&r.repo).execute(&mut *tx).await?;
    sqlx::query("insert into repo_machines (repo_id, machine_id, allowed) values (?1, ?2, 1)").bind(&r.repo).bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    audit(&app, &me.name, "token_made", json!({ "kind": r.kind })).await;
    Ok(Json(json!({ "id": id })))
}

async fn signoff(State(app): State<Shared>, _m: Member, Path(id): Path<Uuid>) -> Res {
    let row: Option<Value> = sqlx::query("select id, repo_id, machine_id, member_id, status, prepared, created_at, updated_at from signoffs where id = ?1").bind(id).fetch_optional(&app.db).await?.map(|r| crate::db::row_json(Some(&r)));
    let row = row.ok_or_else(|| missing("there is no such sign-off"))?;
    let keys: Vec<(String,)> = sqlx::query_as("select id from passkeys where member_id = ?1").bind(row["member_id"].as_str().and_then(|d| d.parse::<Uuid>().ok())).fetch_all(&app.db).await?;
    Ok(Json(json!({ "signoff": row, "rp_id": app.site.rp_id, "credentials": keys.iter().map(|(k,)| k).collect::<Vec<_>>() })))
}

async fn signoff_sign(State(app): State<Shared>, me: Member, Path(id): Path<Uuid>, Json(s): Json<Signed>) -> Res {
    let row: Option<(String, Option<Uuid>, String, Option<Uuid>)> = sqlx::query_as("select repo_id, machine_id, status, member_id from signoffs where id = ?1").bind(id).fetch_optional(&app.db).await?;
    let Some((repo, Some(machine), status, owner)) = row else { return Err(missing("this sign-off is not ready to sign")) };
    driver_only(&app, &me, owner).await?;
    if status != "ready" {
        return Err(bad(format!("this sign-off is {status}, not ready to sign")));
    }
    instruct(&app.db, machine, "file_testing", json!({ "signoff": id, "repo": repo, "sealed": s.sealed })).await?;
    sqlx::query("update signoffs set status = 'signed', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1").bind(id).execute(&app.db).await?;
    audit(&app, &me.name, "testing_signed", json!({ "signoff": id })).await;
    ok()
}

async fn edit_cancel(State(app): State<Shared>, me: Member, Path(id): Path<Uuid>) -> Res {
    let owner: Option<Option<Uuid>> = sqlx::query_scalar("select member_id from policy_edits where id = ?1").bind(id).fetch_optional(&app.db).await?;
    owner_or_admin(&me, owner.flatten(), "only whoever made this edit, or an admin, can cancel it")?;
    audit(&app, &me.name, "policy_edit_cancelled", json!({ "edit": id })).await;
    sqlx::query("update policy_edits set status = 'cancelled', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1 and status in ('waiting', 'preparing', 'ready', 'stuck')").bind(id).execute(&app.db).await?;
    ok()
}

async fn machines(State(app): State<Shared>, me: Member) -> Res {
    let admin = me.role == crate::team::Role::Admin;
    let machines = json(&app, &format!("select m.id, m.name, m.created_at, m.last_seen, m.use05_version, m.revoked, {ONLINE} as online, (select count(*) from repo_machines rm where rm.machine_id = m.id) as repos, mb.name as person, ({admin} or m.member_id = '{}') as yours, m.kind <> 'machine' and coalesce(m.team_version, 0) < (select coalesce(max(version), 0) from team) as stale from machines m left join members mb on mb.id = m.member_id order by m.revoked, m.created_at desc", me.id)).await?;
    let pairings = json(&app, &format!("select id, machine_name, created_at, claimed_by is not null as claimed, claimed_by = '{me}' as mine, {} as commit_hash, {} as x_pub, {} as ed_pub, {} as machine_nonce, {} as browser_nonce from pairings where not approved and not denied and created_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-15 minutes') order by created_at", "commit_hash", "x_pub", "ed_pub", "machine_nonce", "browser_nonce", me = me.id)).await?;
    let refusals = json(&app, "select at, actor, detail from audit where action = 'refused' order by at desc limit 20").await?;
    let waiting = json(&app, "select m.id as machine_id, m.name as machine, rm.repo_id, rm.last_seen from repo_machines rm join machines m on m.id = rm.machine_id join repos r on r.id = rm.repo_id where not rm.allowed and not m.revoked order by rm.last_seen desc").await?;
    Ok(Json(json!({ "machines": machines, "pairings": pairings, "refusals": refusals, "waiting": waiting, "admin": admin })))
}

/// Let another machine speak for a repository a machine already reports.
async fn machine_allow(State(app): State<Shared>, me: Member, Path((id, repo)): Path<(Uuid, String)>) -> Res {
    admin_only(&me, "only an admin can let another machine report a repository")?;
    sqlx::query("update repo_machines set allowed = true where machine_id = ?1 and repo_id = ?2").bind(id).bind(&repo).execute(&app.db).await?;
    audit(&app, &me.name, "machine_allowed", json!({ "machine": id, "repo": repo })).await;
    ok()
}

async fn machine_revoke(State(app): State<Shared>, me: Member, Path(id): Path<Uuid>) -> Res {
    let owner: Option<Option<Uuid>> = sqlx::query_scalar("select member_id from machines where id = ?1").bind(id).fetch_optional(&app.db).await?;
    owner_or_admin(&me, owner.flatten(), "only the machine's owner or an admin can revoke it")?;
    sqlx::query("update machines set revoked = true where id = ?1").bind(id).execute(&app.db).await?;
    audit(&app, &me.name, "machine_revoked", json!({ "machine": id })).await;
    ok()
}

/// The machine belongs to whoever approves its pairing: its work is theirs to approve.
#[derive(Deserialize)]
struct Claim {
    /// The word the machine's terminal shows: only the person there can type it.
    word: String,
    /// The browser's nonce, sent only after it has the machine's commitment.
    nonce: String,
}

/// Whoever types the word the machine's terminal shows claims it: nobody else on the team can
/// pair (and so own) someone's machine.
async fn pairing_claim(State(app): State<Shared>, me: Member, Path(id): Path<Uuid>, Json(body): Json<Claim>) -> Res {
    if !app.limits.allow_at(&me.id.to_string(), "pair-claim", 10, 600, chrono::Utc::now().timestamp() as u64) {
        return Err(bad("too many tries; wait a few minutes"));
    }
    let row: Option<(String, Option<Uuid>)> = sqlx::query_as("select word_hash, claimed_by from pairings where id = ?1 and not approved and not denied and created_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-15 minutes')").bind(id).fetch_optional(&app.db).await?;
    let Some((word_hash, claimed)) = row else { return Err(bad("this pairing request expired")) };
    if claimed.is_some() {
        return Err(bad("someone is already pairing this machine; if that is not you, deny it"));
    }
    let word: String = body.word.to_uppercase().chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let typed = if word.len() == 6 { format!("{}-{}", &word[..3], &word[3..]) } else { word };
    if !crate::util::same_secret(&word_hash, &hex::encode(sha2::Sha256::digest(typed.as_bytes()))) {
        return Err(bad("that is not the word on the machine's terminal"));
    }
    let nonce = crate::keys::unb64(&body.nonce)?;
    if nonce.len() != 16 {
        return Err(bad("a nonce is 16 bytes"));
    }
    sqlx::query("update pairings set claimed_by = ?2, browser_nonce = ?3 where id = ?1 and claimed_by is null").bind(id).bind(me.id).bind(&nonce).execute(&app.db).await?;
    ok()
}

#[derive(Deserialize)]
struct Approve {
    /// The browser's pin over the machine's keys (HMAC under the team's pin key).
    pin: String,
    /// The team's id key, wrapped under the key the team shares with this machine.
    sealed_id_key: String,
    /// The team version the browser's code covered.
    team_version: i32,
}

/// Only the person who claimed the pairing approves it, once the codes on both screens agree.
async fn pairing_approve(State(app): State<Shared>, me: Member, Path(id): Path<Uuid>, Json(body): Json<Approve>) -> Res {
    let row: Option<(String, Option<Uuid>, Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as("select machine_name, claimed_by, x_pub, ed_pub from pairings where id = ?1 and not approved and not denied and machine_nonce is not null and created_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-15 minutes')").bind(id).fetch_optional(&app.db).await?;
    let Some((name, claimed, x_pub, ed_pub)) = row else { return Err(bad("this pairing request expired, or the machine has not shown its code yet")) };
    if claimed != Some(me.id) {
        return Err(forbidden("only the person who typed the machine's word can pair it"));
    }
    if body.pin.trim().is_empty() || body.sealed_id_key.is_empty() {
        return Err(bad("the browser did not pin the machine's keys or send it the team's id key"));
    }
    let team_version: Option<i32> = sqlx::query_scalar("select max(version) from team").fetch_one(&app.db).await?;
    if team_version != Some(body.team_version) {
        return Err(bad("the team's key changed meanwhile; unlock again and pair again"));
    }
    let sealed_id_key = crate::keys::unb64(&body.sealed_id_key)?;
    let machine = Uuid::new_v4();
    let secret = token();
    sqlx::query("insert into machines (id, name, token_hash, member_id, x_pub, ed_pub, pin, team_version, sealed_id_key) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)").bind(machine).bind(&name).bind(hash(&secret)).bind(me.id).bind(x_pub).bind(ed_pub.clone()).bind(body.pin.trim()).bind(team_version).bind(sealed_id_key).execute(&app.db).await?;
    sqlx::query("update pairings set approved = true, token = ?2, machine_id = ?3 where id = ?1").bind(id).bind(&secret).bind(machine).execute(&app.db).await?;
    audit(&app, &me.name, "machine_paired", json!({ "machine": name })).await;
    // Pairing a Mac again leaves its earlier pairings behind as offline duplicates that nothing
    // will ever use. Retire them here, so nobody has to pick the right one out of a list.
    if let Some(keys) = &ed_pub {
        let retired = retire_older_pairings(&app.db, me.id, keys, machine).await?;
        if retired > 0 {
            audit(&app, &me.name, "machine_pairings_retired", json!({ "machine": name, "count": retired })).await;
        }
    }
    ok()
}

/// Revoke this person's other, older pairings of the same machine (the same signing key). Only
/// the machine itself can pair again with that key, so these tokens are stale by definition.
async fn retire_older_pairings(db: &sqlx::SqlitePool, member: Uuid, ed_pub: &[u8], keep: Uuid) -> Result<u64, Fail> {
    let done = sqlx::query("update machines set revoked = true where member_id = ?1 and ed_pub = ?2 and id <> ?3 and not revoked and kind = 'machine'").bind(member).bind(ed_pub).bind(keep).execute(db).await?;
    Ok(done.rows_affected())
}

async fn pairing_deny(State(app): State<Shared>, me: Member, Path(id): Path<Uuid>) -> Res {
    admin_only(&me, "only an admin can deny a pairing; the person at that machine can stop it there")?;
    sqlx::query("update pairings set denied = true where id = ?1").bind(id).execute(&app.db).await?;
    audit(&app, &me.name, "pairing_denied", json!({ "pairing": id })).await;
    ok()
}

async fn passkeys(State(app): State<Shared>, me: Member) -> Res {
    let rows: Vec<(String, String, Vec<u8>, chrono::DateTime<chrono::Utc>, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as("select id, name, sec1, created_at, last_used from passkeys where member_id = ?1 order by created_at").bind(me.id).fetch_all(&app.db).await?;
    let keys: Vec<Value> = rows
        .iter()
        .map(|(id, name, sec1, created, used)| {
            let key = PasskeyKey::from_sec1(&app.site.rp_id, sec1).ok();
            json!({
                "id": id, "name": name, "created_at": created, "last_used": used, "this_session": me.passkey == *id,
                "key_id": key.as_ref().map(|k| PublicKey::Passkey(k.clone()).id()),
                "public": key.as_ref().map(|k| use05_receipt::passkey_public_text(k).trim().to_string()),
            })
        })
        .collect();
    Ok(Json(json!({ "passkeys": keys })))
}

async fn passkey_delete(State(app): State<Shared>, me: Member, Path(id): Path<String>) -> Res {
    let count: i64 = sqlx::query_scalar("select count(*) from passkeys where member_id = ?1").bind(me.id).fetch_one(&app.db).await?;
    if count <= 1 {
        return Err(bad("this is your only passkey; add another before removing it"));
    }
    sqlx::query("delete from passkeys where id = ?1 and member_id = ?2").bind(&id).bind(me.id).execute(&app.db).await?;
    audit(&app, &me.name, "passkey_removed", json!({ "id": id })).await;
    ok()
}

async fn settings(State(app): State<Shared>, me: Member) -> Res {
    let alerts: Value = sqlx::query("select kind, subject, sent, error, at from alerts where member_id = ?1 or (member_id is null and ?2) order by at desc limit 20").bind(me.id).bind(me.role == crate::team::Role::Admin).fetch_all(&app.db).await.map(|r| crate::db::rows_json(&r))?;
    let (email, verified): (Option<String>, bool) = sqlx::query_as("select email, email_verified from members where id = ?1").bind(me.id).fetch_one(&app.db).await?;
    Ok(Json(json!({ "email": app.mail.enabled(), "my_email": email, "verified": verified, "rp_id": app.site.rp_id, "origin": app.site.origin, "alerts": alerts })))
}

async fn test_email(State(app): State<Shared>, _m: Member) -> Res {
    crate::alerts::queue(&app, Some(_m.id), "test", "05: a test email from your console", "This is a test. Emails come only when something needs you.", "/").await;
    ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_member_forgets_only_what_their_own_machines_reported() {
        let db = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        let (me, them) = (Uuid::new_v4(), Uuid::new_v4());
        let (mine, theirs) = (Uuid::new_v4(), Uuid::new_v4());
        for (m, who) in [(me, "Alex"), (them, "Sam")] {
            sqlx::query("insert into members (id, name, role) values (?1, ?2, 'member')").bind(m).bind(who).execute(&db).await.unwrap();
        }
        for (id, owner) in [(mine, me), (theirs, them)] {
            sqlx::query("insert into machines (id, name, token_hash, member_id) values (?1, 'm', ?2, ?3)").bind(id).bind(id.0.to_string()).bind(owner).execute(&db).await.unwrap();
        }
        sqlx::query("insert into repos (id) values ('r1')").execute(&db).await.unwrap();
        for (r, m) in [("t1", mine), ("e1", mine), ("t2", theirs)] {
            sqlx::query("insert into records (kind, repo_ref, ref_key, machine_id, sealed, sig) values ('event', 'r1', ?1, ?2, x'01', x'02')").bind(r).bind(m).execute(&db).await.unwrap();
        }
        let ask = Uuid::new_v4();
        sqlx::query("insert into approval_requests (id, repo_id, machine_id, ref_key, sealed, sig) values (?1, 'r1', ?2, 'a1', x'01', x'02')").bind(ask).bind(mine).execute(&db).await.unwrap();
        let refs = vec![Forget { kind: "event".into(), ref_key: "t1".into() }, Forget { kind: "event".into(), ref_key: "e1".into() }, Forget { kind: "event".into(), ref_key: "t2".into() }];
        assert_eq!(forget_records(&db, me, false, "r1", &refs, &[ask]).await.unwrap(), 3, "two records and one request, not Sam's");
        let left: Vec<String> = sqlx::query_scalar("select ref_key from records").fetch_all(&db).await.unwrap();
        assert_eq!(left, vec!["t2".to_string()]);
        assert_eq!(forget_records(&db, me, true, "r1", &refs, &[]).await.unwrap(), 1, "an admin may clear anyone's");
    }

    #[tokio::test]
    async fn a_discard_the_machine_never_answers_stops_waiting() {
        let db = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        let machine = Uuid::new_v4();
        sqlx::query("insert into machines (id, name, token_hash) values (?1, 'm', ?2)").bind(machine).bind(machine.0.to_string()).execute(&db).await.unwrap();
        sqlx::query("insert into repos (id) values ('r1')").execute(&db).await.unwrap();
        let (fresh, old, signed_old) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        for (id, status, age) in [(fresh, "preparing", "-10 seconds"), (old, "preparing", "-200 seconds"), (signed_old, "signed", "-400 seconds")] {
            sqlx::query("insert into discards (id, repo_id, machine_id, status, created_at, updated_at) values (?1, 'r1', ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?4), strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?4))").bind(id).bind(machine).bind(status).bind(age).execute(&db).await.unwrap();
            instruct(&db, machine, "prepare_discard", json!({ "discard": id.to_string(), "repo": "r1" })).await.unwrap();
        }
        for id in [fresh, old, signed_old] {
            expire_unanswered(&db, &id.to_string()).await.unwrap();
        }
        let status = |id: Uuid| {
            let db = db.clone();
            async move { sqlx::query_scalar::<_, String>("select status from discards where id = ?1").bind(id).fetch_one(&db).await.unwrap() }
        };
        assert_eq!(status(fresh).await, "preparing", "still within its two minutes");
        assert_eq!(status(old).await, "stuck");
        assert_eq!(status(signed_old).await, "stuck");
        let open: i64 = sqlx::query_scalar("select count(*) from instructions where done_at is null").fetch_one(&db).await.unwrap();
        assert_eq!(open, 1, "only the fresh request is still open to the machine");
    }

    #[tokio::test]
    async fn pairing_a_machine_again_retires_only_its_older_pairings() {
        let db = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        let (me, them) = (Uuid::new_v4(), Uuid::new_v4());
        for (m, who) in [(me, "Alex"), (them, "Sam")] {
            sqlx::query("insert into members (id, name, role) values (?1, ?2, 'member')").bind(m).bind(who).execute(&db).await.unwrap();
        }
        let key_mac: &[u8] = &[1; 32];
        let key_laptop: &[u8] = &[2; 32];
        let (old_a, old_b, current, laptop, theirs) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        for (id, owner, key) in [(old_a, me, key_mac), (old_b, me, key_mac), (current, me, key_mac), (laptop, me, key_laptop), (theirs, them, key_mac)] {
            sqlx::query("insert into machines (id, name, token_hash, member_id, ed_pub) values (?1, 'm', ?2, ?3, ?4)").bind(id).bind(id.0.to_string()).bind(owner).bind(key).execute(&db).await.unwrap();
        }
        assert_eq!(retire_older_pairings(&db, me, key_mac, current).await.unwrap(), 2, "the two older pairings of this machine");
        let live: Vec<Uuid> = sqlx::query_scalar("select id from machines where not revoked order by id").fetch_all(&db).await.unwrap();
        for kept in [current, laptop, theirs] {
            assert!(live.contains(&kept), "{kept} must stay paired: a different machine, someone else's, or the new pairing");
        }
        assert!(!live.contains(&old_a) && !live.contains(&old_b));
    }

    #[tokio::test]
    async fn records_since_a_time_and_since_nonsense() {
        let db = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        sqlx::query("insert into records (kind, repo_ref, ref_key, sealed, sig) values ('repo', 'r1', '', x'01', x'02')").execute(&db).await.unwrap();
        let count = |since: Option<&str>| {
            let db = db.clone();
            let since = since.map(str::to_string);
            async move { sqlx::query(RECORDS_SINCE).bind(since).fetch_all(&db).await.unwrap().len() }
        };
        assert_eq!(count(None).await, 1);
        assert_eq!(count(Some("2000-01-01T00:00:00.000Z")).await, 1);
        assert_eq!(count(Some("2999-01-01T00:00:00.000Z")).await, 0);
        assert_eq!(count(Some("not a time")).await, 1, "everything, not nothing");
    }
}
