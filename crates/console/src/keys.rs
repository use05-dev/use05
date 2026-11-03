//! The team's keys, as the server sees them: opaque bytes. Members' browsers make, wrap and seal
//! them; the server stores and hands them back, and decides only who may store what.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde_json::json;
use crate::db::Uuid;

use crate::Shared;
use crate::auth::{Admin, Member, audit};
use crate::util::{Fail, Res, bad, forbidden, ok};

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/keys/me", get(mine))
        .route("/keys/setup", post(setup))
        .route("/keys/join", post(join))
        .route("/keys/passkey-wrap", post(passkey_wrap))
        .route("/keys/recovery", post(recovery))
        .route("/keys/members", get(members))
        .route("/keys/own", post(own))
        .route("/keys/rotate", post(rotate))
        .route("/keys/confirm-machines", get(to_confirm).post(confirm_machines))
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn unb64(text: &str) -> Result<Vec<u8>, Fail> {
    STANDARD.decode(text).map_err(|_| bad("not base64"))
}

fn key32(text: &str) -> Result<Vec<u8>, Fail> {
    let k = unb64(text)?;
    if k.len() == 32 { Ok(k) } else { Err(bad("a public key is 32 bytes")) }
}

async fn mine(State(app): State<Shared>, me: Member) -> Res {
    let public: Option<Vec<u8>> = sqlx::query_scalar("select public from members where id = ?1").bind(me.id).fetch_one(&app.db).await?;
    let wraps: Vec<(String, Option<String>, Vec<u8>)> = sqlx::query_as("select kind, passkey_id, wrapped from key_wraps where member_id = ?1").bind(me.id).fetch_all(&app.db).await?;
    let grants: Vec<(i32, Vec<u8>)> = sqlx::query_as("select version, sealed from team_grants where member_id = ?1 order by version").bind(me.id).fetch_all(&app.db).await?;
    let team: Option<(i32, Vec<u8>)> = sqlx::query_as("select version, public from team order by version desc limit 1").fetch_optional(&app.db).await?;
    let own: Vec<(i32, Vec<u8>)> = sqlx::query_as("select version, wrapped from own_grants where member_id = ?1 order by version").bind(me.id).fetch_all(&app.db).await?;
    Ok(Json(json!({
        "member_id": me.id,
        "own": own.iter().map(|(v, w)| json!({ "version": v, "wrapped": b64(w) })).collect::<Vec<_>>(),
        "member_public": public.map(|p| b64(&p)),
        "wraps": wraps.iter().map(|(k, p, w)| json!({ "kind": k, "passkey_id": p, "wrapped": b64(w) })).collect::<Vec<_>>(),
        "grants": grants.iter().map(|(v, s)| json!({ "version": v, "sealed": b64(s) })).collect::<Vec<_>>(),
        "team": team.map(|(v, p)| json!({ "version": v, "public": b64(&p) })),
        "passkey": me.passkey,
        "rotate_needed": rotate_needed(&app).await?,
    })))
}

/// Someone was removed since the team's key last changed: their copy still opens what machines send.
async fn rotate_needed(app: &Shared) -> Result<bool, Fail> {
    Ok(sqlx::query_scalar("select exists (select 1 from audit where action = 'member_removed' and at > (select max(created_at) from team))").fetch_one(&app.db).await?)
}

#[derive(Deserialize)]
struct Wrap {
    passkey_id: String,
    wrapped: String,
}

#[derive(Deserialize)]
struct Setup {
    member_public: String,
    passkey: Wrap,
    recovery: String,
    team_public: String,
    grant: String,
    own: String,
    pin: String,
}

async fn store_member_keys(db: &mut sqlx::SqliteConnection, me: &Member, member_public: &str, passkey: &Wrap, recovery: &str) -> Result<(), Fail> {
    let owned: bool = sqlx::query_scalar("select exists (select 1 from passkeys where id = ?1 and member_id = ?2)").bind(&passkey.passkey_id).bind(me.id).fetch_one(&mut *db).await?;
    if !owned {
        return Err(forbidden("that passkey is not yours"));
    }
    sqlx::query("update members set public = ?2 where id = ?1").bind(me.id).bind(key32(member_public)?).execute(&mut *db).await?;
    sqlx::query("insert into key_wraps (id, member_id, kind, passkey_id, wrapped) values (?1, ?2, 'passkey', ?3, ?4)").bind(Uuid::new_v4()).bind(me.id).bind(&passkey.passkey_id).bind(unb64(&passkey.wrapped)?).execute(&mut *db).await?;
    sqlx::query("delete from key_wraps where member_id = ?1 and kind = 'recovery'").bind(me.id).execute(&mut *db).await?;
    sqlx::query("insert into key_wraps (id, member_id, kind, wrapped) values (?1, ?2, 'recovery', ?3)").bind(Uuid::new_v4()).bind(me.id).bind(unb64(recovery)?).execute(&mut *db).await?;
    Ok(())
}

/// The first admin makes the team's keys. Once, all at once.
async fn setup(State(app): State<Shared>, Admin(me): Admin, Json(body): Json<Setup>) -> Res {
    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let exists: bool = sqlx::query_scalar("select exists (select 1 from team)").fetch_one(&mut *tx).await?;
    if exists {
        return Err(bad("this team already has its keys"));
    }
    store_member_keys(&mut tx, &me, &body.member_public, &body.passkey, &body.recovery).await?;
    sqlx::query("insert into team (version, public) values (1, ?1)").bind(key32(&body.team_public)?).execute(&mut *tx).await?;
    sqlx::query("insert into team_grants (member_id, version, sealed) values (?1, 1, ?2)").bind(me.id).bind(unb64(&body.grant)?).execute(&mut *tx).await?;
    sqlx::query("insert into own_grants (member_id, version, wrapped) values (?1, 1, ?2)").bind(me.id).bind(unb64(&body.own)?).execute(&mut *tx).await?;
    sqlx::query("update members set pin = ?2 where id = ?1").bind(me.id).bind(&body.pin).execute(&mut *tx).await?;
    tx.commit().await?;
    audit(&app, &me.name, "team_keys_made", json!({})).await;
    ok()
}

#[derive(Deserialize)]
struct Join {
    member_public: String,
    passkey: Wrap,
    recovery: String,
    grant: String,
    own: String,
    pin: String,
    version: i32,
}

/// Someone who joined by invitation stores their keys and their copy of the team's secret, which
/// their browser re-sealed from the invitation. Once, all at once, and only for the current key.
async fn join(State(app): State<Shared>, me: Member, Json(body): Json<Join>) -> Res {
    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let has: Option<Vec<u8>> = sqlx::query_scalar("select public from members where id = ?1").bind(me.id).fetch_one(&mut *tx).await?;
    if has.is_some() {
        return Err(bad("you already have your keys"));
    }
    let version: i32 = sqlx::query_scalar("select max(version) from team").fetch_one(&mut *tx).await?;
    if version != body.version {
        return Err(bad("the team's key changed since you were invited; ask for a new invitation"));
    }
    store_member_keys(&mut tx, &me, &body.member_public, &body.passkey, &body.recovery).await?;
    sqlx::query("insert into team_grants (member_id, version, sealed) values (?1, ?2, ?3)").bind(me.id).bind(version).bind(unb64(&body.grant)?).execute(&mut *tx).await?;
    sqlx::query("insert into own_grants (member_id, version, wrapped) values (?1, ?2, ?3)").bind(me.id).bind(version).bind(unb64(&body.own)?).execute(&mut *tx).await?;
    sqlx::query("update members set pin = ?2 where id = ?1").bind(me.id).bind(&body.pin).execute(&mut *tx).await?;
    tx.commit().await?;
    ok()
}

/// A wrap of your key for another of your passkeys.
async fn passkey_wrap(State(app): State<Shared>, me: Member, Json(body): Json<Wrap>) -> Res {
    let owned: bool = sqlx::query_scalar("select exists (select 1 from passkeys where id = ?1 and member_id = ?2)").bind(&body.passkey_id).bind(me.id).fetch_one(&app.db).await?;
    if !owned {
        return Err(forbidden("that passkey is not yours"));
    }
    sqlx::query("delete from key_wraps where member_id = ?1 and passkey_id = ?2").bind(me.id).bind(&body.passkey_id).execute(&app.db).await?;
    sqlx::query("insert into key_wraps (id, member_id, kind, passkey_id, wrapped) values (?1, ?2, 'passkey', ?3, ?4)").bind(Uuid::new_v4()).bind(me.id).bind(&body.passkey_id).bind(unb64(&body.wrapped)?).execute(&app.db).await?;
    ok()
}

#[derive(Deserialize)]
struct Recovery {
    wrapped: String,
}

/// A new recovery code replaces the old one.
async fn recovery(State(app): State<Shared>, me: Member, Json(body): Json<Recovery>) -> Res {
    sqlx::query("delete from key_wraps where member_id = ?1 and kind = 'recovery'").bind(me.id).execute(&app.db).await?;
    sqlx::query("insert into key_wraps (id, member_id, kind, wrapped) values (?1, ?2, 'recovery', ?3)").bind(Uuid::new_v4()).bind(me.id).bind(unb64(&body.wrapped)?).execute(&app.db).await?;
    audit(&app, &me.name, "recovery_code_replaced", json!({})).await;
    ok()
}

/// Who gets the team's next key: every member with a key of their own.
async fn members(State(app): State<Shared>, Admin(_me): Admin) -> Res {
    let rows: Vec<(Uuid, String, Vec<u8>, Option<String>)> = sqlx::query_as("select id, name, public, pin from members where public is not null order by created_at").fetch_all(&app.db).await?;
    Ok(Json(json!({ "members": rows.iter().map(|(id, name, p, pin)| json!({ "id": id, "name": name, "public": b64(p), "pin": pin })).collect::<Vec<_>>() })))
}

#[derive(Deserialize)]
struct Grant {
    member_id: Uuid,
    sealed: String,
}

#[derive(Deserialize)]
struct Pin {
    id: Uuid,
    pin: String,
}

#[derive(Deserialize)]
struct Rotate {
    version: i32,
    public: String,
    grants: Vec<Grant>,
    /// The admin's own copy of the new key.
    own: String,
    /// Members and machines the admin's browser checked under the old key, pinned under the new.
    member_pins: Vec<Pin>,
    machine_pins: Vec<Pin>,
    /// The base template, re-sealed to the new key; none if there was none the team vouched for.
    base: Option<String>,
}

/// A new team key, made in an admin's browser and sealed to each member who stays. Machines
/// keep sealing to the old one until their owner confirms the new one with a passkey.
async fn rotate(State(app): State<Shared>, Admin(me): Admin, Json(body): Json<Rotate>) -> Res {
    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let current: Option<i32> = sqlx::query_scalar("select max(version) from team").fetch_one(&mut *tx).await?;
    if Some(body.version - 1) != current {
        return Err(bad("the team's key changed meanwhile; reload and try again"));
    }
    let mut holders: Vec<Uuid> = sqlx::query_scalar("select id from members where public is not null").fetch_all(&mut *tx).await?;
    let mut granted: Vec<Uuid> = body.grants.iter().map(|g| g.member_id).collect();
    holders.sort();
    granted.sort();
    if holders != granted {
        return Err(bad("the new key must go to every member with a key, once each; reload and try again"));
    }
    sqlx::query("insert into team (version, public) values (?1, ?2)").bind(body.version).bind(key32(&body.public)?).execute(&mut *tx).await?;
    for g in &body.grants {
        sqlx::query("insert into team_grants (member_id, version, sealed) values (?1, ?2, ?3)").bind(g.member_id).bind(body.version).bind(unb64(&g.sealed)?).execute(&mut *tx).await?;
    }
    sqlx::query("insert into own_grants (member_id, version, wrapped) values (?1, ?2, ?3)").bind(me.id).bind(body.version).bind(unb64(&body.own)?).execute(&mut *tx).await?;
    for p in &body.member_pins {
        sqlx::query("update members set pin = ?2 where id = ?1").bind(p.id).bind(&p.pin).execute(&mut *tx).await?;
    }
    // A machine the admin's browser could not check keeps its old pin, which no longer verifies.
    for p in &body.machine_pins {
        sqlx::query("update machines set pin = ?2 where id = ?1").bind(p.id).bind(&p.pin).execute(&mut *tx).await?;
    }
    match &body.base {
        Some(b) => sqlx::query("insert into base_policy (id, toml) values (1, ?1) on conflict (id) do update set toml = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')").bind(b).execute(&mut *tx).await?,
        None => sqlx::query("delete from base_policy").execute(&mut *tx).await?,
    };
    // Open invitations carry the old key: they would let someone in with it.
    sqlx::query("update invites set used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where used_at is null").execute(&mut *tx).await?;
    tx.commit().await?;
    audit(&app, &me.name, "team_key_changed", json!({ "version": body.version })).await;
    ok()
}

/// What a member's passkey signs so their machines take the team's current key.
async fn to_confirm(State(app): State<Shared>, me: Member) -> Res {
    let keys: Vec<String> = sqlx::query_scalar("select id from passkeys where member_id = ?1").bind(me.id).fetch_all(&app.db).await?;
    Ok(Json(json!({ "rp_id": app.site.rp_id, "credentials": keys })))
}

#[derive(Deserialize)]
struct Confirm {
    envelope: serde_json::Value,
}

/// Relay a member's signed word to their machines. Each machine checks the passkey itself
/// against the ones pinned on it; here only who may send it to which machine is decided.
async fn confirm_machines(State(app): State<Shared>, me: Member, Json(body): Json<Confirm>) -> Res {
    let payload = body.envelope["payload"].as_str().and_then(|p| STANDARD.decode(p).ok()).and_then(|p| serde_json::from_slice::<serde_json::Value>(&p).ok()).ok_or_else(|| bad("not a signed statement"))?;
    let what = &payload["predicate"];
    let team: (i32, Vec<u8>) = sqlx::query_as("select version, public from team order by version desc limit 1").fetch_one(&app.db).await?;
    if payload["predicateType"] != cloud::checks::TEAM_KEY || what["version"].as_i64() != Some(team.0.into()) || what["team_pub"].as_str() != Some(b64(&team.1).as_str()) {
        return Err(bad("that is not the team's current key"));
    }
    // Machines are named by their signing keys: each knows its own, whatever the console says.
    let named: Vec<Vec<u8>> = what["machines"].as_array().into_iter().flatten().filter_map(|m| STANDARD.decode(m.as_str()?).ok()).collect();
    let named_hex: Vec<String> = named.iter().map(|k| hex::encode_upper(k)).collect();
    let machines: Vec<Uuid> = sqlx::query_scalar("select id from machines where hex(ed_pub) in (select value from json_each(?1)) and member_id = ?2 and not revoked and kind = 'machine'").bind(serde_json::to_string(&named_hex).unwrap_or_default()).bind(me.id).fetch_all(&app.db).await?;
    if named.is_empty() || machines.len() != named.len() {
        return Err(forbidden("you can confirm the key for your own machines only"));
    }
    for m in &machines {
        crate::agent::instruct(&app.db, *m, "rotate", json!({ "envelope": body.envelope, "version": team.0 })).await?;
    }
    audit(&app, &me.name, "team_key_confirmed", json!({ "machines": machines.len(), "version": team.0 })).await;
    ok()
}

#[derive(Deserialize)]
struct Own {
    version: i32,
    wrapped: String,
}

/// Your own copy of a team key, wrapped under a key from your own secret: the console cannot make
/// one, so your browser trusts it over a key sealed to you by anyone.
async fn own(State(app): State<Shared>, me: Member, Json(body): Json<Own>) -> Res {
    sqlx::query("insert into own_grants (member_id, version, wrapped) values (?1, ?2, ?3) on conflict (member_id, version) do update set wrapped = ?3").bind(me.id).bind(body.version).bind(unb64(&body.wrapped)?).execute(&app.db).await?;
    ok()
}
