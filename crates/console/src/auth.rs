//! Signing in: passkeys only. The first passkey needs the one-time setup secret (a variable
//! set where the console is hosted); later ones need someone signed in.

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use crate::db::Uuid;

use crate::team::Role;
use crate::util::{Fail, Res, b64url, bad, denied, forbidden, hash, ok, random_bytes, token, too_many};
use sqlx::SqlitePool;
use crate::{Shared, alerts, webauthn};

/// A session ends after this long without the person using the console; using it renews it.
const IDLE_MINUTES: i64 = 60;
/// The cookie itself outlives any session: the server decides when one has ended.
const COOKIE_DAYS: i64 = 30;
const COOKIE: &str = "s05";

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/me", get(me))
        .route("/auth/register/start", post(register_start))
        .route("/auth/register/finish", post(register_finish))
        .route("/auth/login/start", post(login_start))
        .route("/auth/login/finish", post(login_finish))
        .route("/auth/recheck/start", post(recheck_start))
        .route("/auth/logout", post(logout))
}

pub fn cookie_value(headers: &HeaderMap) -> Option<String> {
    headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(';')).find_map(|c| c.trim().strip_prefix(&format!("{COOKIE}=")).map(str::to_string))
}

/// A signed-in member of the team. Changing requests must also carry `x-05: 1`, which a page on
/// another site cannot send without the browser asking this server first (it never agrees).
#[derive(Clone)]
pub struct Member {
    pub id: Uuid,
    pub name: String,
    pub role: Role,
    /// The passkey this session signed in with.
    pub passkey: String,
}

impl FromRequestParts<Shared> for Member {
    type Rejection = Fail;
    async fn from_request_parts(parts: &mut Parts, app: &Shared) -> Result<Member, Fail> {
        if parts.method != Method::GET && parts.headers.get("x-05").is_none() {
            return Err(denied("missing the x-05 header"));
        }
        let Some(value) = cookie_value(&parts.headers) else { return Err(denied("sign in first")) };
        // The page says when the person did something; its own polling does not keep them signed in.
        let active = parts.headers.contains_key("x-05-active");
        session_member(&app.db, &value, active).await?.ok_or_else(|| denied("your session has ended; sign in again"))
    }
}

/// A signed-in admin: may invite and remove people and change roles.
pub struct Admin(pub Member);

impl FromRequestParts<Shared> for Admin {
    type Rejection = Fail;
    async fn from_request_parts(parts: &mut Parts, app: &Shared) -> Result<Admin, Fail> {
        let m = Member::from_request_parts(parts, app).await?;
        if m.role == Role::Admin { Ok(Admin(m)) } else { Err(forbidden("only an admin can do that")) }
    }
}

/// Who a session belongs to, while it lasts. `active`: the person just did something, so it lasts
/// another hour from now.
pub async fn session_member(db: &SqlitePool, cookie: &str, active: bool) -> Result<Option<Member>, Fail> {
    if active {
        sqlx::query("update sessions set expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+' || ?2 || ' minutes') where token_hash = ?1 and expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')").bind(hash(cookie)).bind(IDLE_MINUTES).execute(db).await?;
    }
    let row: Option<(Uuid, String, String, String)> = sqlx::query_as(
        "select m.id, m.name, m.role, s.passkey_id from sessions s join passkeys p on p.id = s.passkey_id join members m on m.id = p.member_id where s.token_hash = ?1 and s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
    )
    .bind(hash(cookie))
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(id, name, role, passkey)| Member { id, name, role: Role::parse(&role), passkey }))
}

async fn member_of(app: &Shared, headers: &HeaderMap) -> Result<Option<Member>, Fail> {
    match cookie_value(headers) {
        Some(value) => session_member(&app.db, &value, false).await,
        None => Ok(None),
    }
}

async fn signed_in(app: &Shared, headers: &HeaderMap) -> bool {
    let Some(value) = cookie_value(headers) else { return false };
    sqlx::query_scalar::<_, i64>("select count(*) from sessions where token_hash = ?1 and expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')").bind(hash(&value)).fetch_one(&app.db).await.unwrap_or(0) > 0
}

async fn passkey_count(app: &Shared) -> Result<i64, Fail> {
    Ok(sqlx::query_scalar("select count(*) from passkeys").fetch_one(&app.db).await?)
}

async fn me(State(app): State<Shared>, headers: HeaderMap) -> Res {
    let member = member_of(&app, &headers).await?;
    Ok(Json(json!({
        "signed_in": member.is_some(),
        "member": member.map(|m| json!({ "id": m.id, "name": m.name, "role": m.role.word() })),
        "setup_needed": passkey_count(&app).await? == 0,
        "rp_id": app.site.rp_id,
        "email": app.mail.enabled(),
    })))
}

async fn new_challenge(app: &Shared, purpose: &str) -> Result<(Uuid, Vec<u8>), Fail> {
    new_challenge_for(app, purpose, Value::Null).await
}

/// A challenge, with what it is for (a new member's id and name, or an invitation).
async fn new_challenge_for(app: &Shared, purpose: &str, context: Value) -> Result<(Uuid, Vec<u8>), Fail> {
    let id = Uuid::new_v4();
    let challenge = random_bytes(32);
    sqlx::query("delete from challenges where created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-10 minutes')").execute(&app.db).await?;
    let open: i64 = sqlx::query_scalar("select count(*) from challenges").fetch_one(&app.db).await?;
    if open > 500 {
        return Err(too_many("too many sign-ins are waiting; try again in a few minutes"));
    }
    sqlx::query("insert into challenges (id, purpose, challenge, context) values (?1, ?2, ?3, ?4)").bind(id).bind(purpose).bind(&challenge).bind(&context).execute(&app.db).await?;
    Ok((id, challenge))
}

async fn take_challenge(app: &Shared, id: Uuid, purposes: &[&str]) -> Result<(String, Vec<u8>), Fail> {
    take_challenge_for(app, id, purposes).await.map(|(p, c, _)| (p, c))
}

async fn take_challenge_for(app: &Shared, id: Uuid, purposes: &[&str]) -> Result<(String, Vec<u8>, Value), Fail> {
    let row: Option<(String, Vec<u8>, Option<Value>)> = sqlx::query_as("delete from challenges where id = ?1 and created_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-5 minutes') returning purpose, challenge, context").bind(id).fetch_optional(&app.db).await?;
    row.filter(|(p, _, _)| purposes.contains(&p.as_str())).map(|(p, c, x)| (p, c, x.unwrap_or(Value::Null))).ok_or_else(|| bad("that sign-in attempt expired; try again"))
}

async fn new_session(db: &SqlitePool, passkey: &str) -> Result<String, Fail> {
    let value = token();
    sqlx::query("insert into sessions (token_hash, passkey_id, expires_at) values (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+' || ?3 || ' minutes'))").bind(hash(&value)).bind(passkey).bind(IDLE_MINUTES).execute(db).await?;
    sqlx::query("delete from sessions where expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 days')").execute(db).await?;
    Ok(value)
}

/// Lax, not Strict: a link from an email or a notification then opens the console signed in.
/// Changes still need the `x-05` header, which no other site's page can send.
fn session_cookie(value: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{secure}", COOKIE_DAYS * 86400)
}

async fn start_session(app: &Shared, passkey: &str) -> Result<Response, Fail> {
    let value = new_session(&app.db, passkey).await?;
    sqlx::query("update passkeys set last_used = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1").bind(passkey).execute(&app.db).await?;
    Ok(([(header::SET_COOKIE, session_cookie(&value, app.secure_cookie))], Json(json!({ "ok": true }))).into_response())
}

pub async fn audit(app: &Shared, actor: &str, action: &str, detail: Value) {
    let _ = sqlx::query("insert into audit (actor, action, detail) values (?1, ?2, ?3)").bind(actor).bind(action).bind(detail).execute(&app.db).await;
}

#[derive(Deserialize)]
struct Proof {
    challenge_id: Uuid,
    credential: webauthn::Assertion,
}

#[derive(Deserialize)]
struct RegisterStart {
    setup_secret: Option<String>,
    /// Setting up: the first member's name.
    name: Option<String>,
    /// Joining: the invitation's token.
    invite: Option<String>,
    /// For another passkey: a fresh check with one the console already has. A stolen session
    /// cookie alone cannot add a passkey.
    proof: Option<Proof>,
}

/// A fresh passkey check, for the few things a session alone may not do.
async fn recheck_start(State(app): State<Shared>, headers: HeaderMap) -> Res {
    app.limits.check(&headers, "auth", 30, 600)?;
    if headers.get("x-05").is_none() || !signed_in(&app, &headers).await {
        return Err(denied("sign in first"));
    }
    let (id, challenge) = new_challenge(&app, "recheck").await?;
    let me = member_of(&app, &headers).await?.ok_or_else(|| denied("sign in first"))?;
    let keys: Vec<(String,)> = sqlx::query_as("select id from passkeys where member_id = ?1").bind(me.id).fetch_all(&app.db).await?;
    Ok(Json(json!({
        "challenge_id": id,
        "options": { "challenge": b64url(&challenge), "rpId": app.site.rp_id, "allowCredentials": keys.iter().map(|(id,)| json!({ "type": "public-key", "id": id })).collect::<Vec<_>>(), "userVerification": "required", "timeout": 120000 }
    })))
}

/// A fresh check with one of *this member's* passkeys.
async fn check_proof(app: &Shared, me: &Member, proof: Option<Proof>) -> Result<String, Fail> {
    let proof = proof.ok_or_else(|| denied("confirm with one of your passkeys first"))?;
    let (_, challenge) = take_challenge(app, proof.challenge_id, &["recheck"]).await?;
    let row: Option<(Vec<u8>, String)> = sqlx::query_as("select sec1, name from passkeys where id = ?1 and member_id = ?2").bind(&proof.credential.id).bind(me.id).fetch_optional(&app.db).await?;
    let Some((sec1, name)) = row else { return Err(denied("that passkey is not one of yours")) };
    webauthn::assert(&proof.credential, &sec1, &challenge, &app.site).map_err(denied)?;
    Ok(name)
}

async fn register_start(State(app): State<Shared>, headers: HeaderMap, Json(body): Json<RegisterStart>) -> Res {
    app.limits.check(&headers, "auth", 30, 600)?;
    if headers.get("x-05").is_none() {
        return Err(denied("missing the x-05 header"));
    }
    // Who the passkey will belong to: the first member, someone invited, or the member signed in.
    let (purpose, member, name) = if passkey_count(&app).await? == 0 {
        if !app.claims.accepts(body.setup_secret.as_deref().unwrap_or_default()) {
            return Err(denied("that claim code is not right; it is in the console's log, or run use05 cloud login with the console's address"));
        }
        let name = crate::team::person_name(body.name.as_deref().unwrap_or("")).ok_or_else(|| bad("say your name"))?;
        ("register-setup", Uuid::new_v4(), name)
    } else if let Some(token) = body.invite.as_deref() {
        let invite = crate::team::open_invite(&app, token).await?;
        ("join", Uuid::new_v4(), invite.name)
    } else if let Some(me) = member_of(&app, &headers).await? {
        check_proof(&app, &me, body.proof).await?;
        ("register", me.id, me.name)
    } else {
        return Err(denied("sign in to add another passkey"));
    };
    let context = json!({ "member": member, "name": name, "invite": body.invite.as_deref().map(hash) });
    let (id, challenge) = new_challenge_for(&app, purpose, context).await?;
    let existing: Vec<(String,)> = sqlx::query_as("select id from passkeys where member_id = ?1").bind(member).fetch_all(&app.db).await?;
    Ok(Json(json!({
        "challenge_id": id,
        "options": {
            "challenge": b64url(&challenge),
            "rp": { "id": app.site.rp_id, "name": "05 console" },
            "user": { "id": b64url(member.as_bytes()), "name": name, "displayName": name },
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "authenticatorSelection": { "residentKey": "preferred", "userVerification": "required" },
            "excludeCredentials": existing.iter().map(|(id,)| json!({ "type": "public-key", "id": id })).collect::<Vec<_>>(),
            "attestation": "none",
            "timeout": 120000,
        }
    })))
}

#[derive(Deserialize)]
struct RegisterFinish {
    challenge_id: Uuid,
    name: String,
    credential: webauthn::Registration,
}

async fn register_finish(State(app): State<Shared>, headers: HeaderMap, Json(body): Json<RegisterFinish>) -> Result<Response, Fail> {
    app.limits.check(&headers, "auth", 30, 600)?;
    if headers.get("x-05").is_none() {
        return Err(denied("missing the x-05 header"));
    }
    let (purpose, challenge, context) = take_challenge_for(&app, body.challenge_id, &["register", "register-setup", "join"]).await?;
    let member: Uuid = context["member"].as_str().and_then(|m| m.parse().ok()).ok_or_else(|| bad("that sign-in attempt expired; try again"))?;
    let person = context["name"].as_str().unwrap_or("").to_string();
    if purpose == "register" && member_of(&app, &headers).await?.is_none_or(|m| m.id != member) {
        return Err(denied("sign in to add another passkey"));
    }
    let (id, sec1) = webauthn::register(&body.credential, &challenge, &app.site).map_err(bad)?;
    let name = body.name.trim().chars().take(60).collect::<String>();
    let name = if name.is_empty() { "passkey".to_string() } else { name };
    // One write, all or nothing: two first sign-ups at once leave one admin; a join that fails
    // leaves no member without a passkey.
    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    match purpose.as_str() {
        "register-setup" => {
            let set_up: i64 = sqlx::query_scalar("select count(*) from passkeys").fetch_one(&mut *tx).await?;
            if set_up != 0 {
                return Err(denied("the console is already set up"));
            }
            sqlx::query("insert into members (id, name, role) values (?1, ?2, 'admin')").bind(member).bind(&person).execute(&mut *tx).await?;
        }
        "join" => {
            let role = crate::team::use_invite(&mut tx, context["invite"].as_str().unwrap_or("")).await?;
            crate::team::name_free(&mut tx, &person).await?;
            sqlx::query("insert into members (id, name, role) values (?1, ?2, ?3)").bind(member).bind(&person).bind(role.word()).execute(&mut *tx).await?;
        }
        _ => {}
    }
    sqlx::query("insert into passkeys (id, name, sec1, member_id) values (?1, ?2, ?3, ?4)").bind(&id).bind(&name).bind(&sec1).bind(member).execute(&mut *tx).await?;
    tx.commit().await?;
    if purpose == "join" {
        audit(&app, &person, "joined", json!({})).await;
    }
    audit(&app, &person, "passkey_added", json!({ "name": name })).await;
    alerts::queue(&app, Some(member), "passkey", "05: a passkey was added to your console", &format!("A passkey named \"{name}\" was added for {person}. It can sign in and approve. If it was not you, remove it under Machines, and run use05 cloud enrol nowhere until you have."), "/machines").await;
    if purpose != "register" {
        return start_session(&app, &id).await;
    }
    Ok(Json(json!({ "ok": true })).into_response())
}

async fn login_start(State(app): State<Shared>, headers: HeaderMap) -> Res {
    app.limits.check(&headers, "auth", 30, 600)?;
    let (id, challenge) = new_challenge(&app, "login").await?;
    let keys: Vec<(String,)> = sqlx::query_as("select id from passkeys").fetch_all(&app.db).await?;
    Ok(Json(json!({
        "challenge_id": id,
        "options": {
            "challenge": b64url(&challenge),
            "rpId": app.site.rp_id,
            "allowCredentials": keys.iter().map(|(id,)| json!({ "type": "public-key", "id": id })).collect::<Vec<_>>(),
            "userVerification": "required",
            "timeout": 120000,
        }
    })))
}

#[derive(Deserialize)]
struct LoginFinish {
    challenge_id: Uuid,
    credential: webauthn::Assertion,
}

async fn login_finish(State(app): State<Shared>, headers: HeaderMap, Json(body): Json<LoginFinish>) -> Result<Response, Fail> {
    app.limits.check(&headers, "auth", 30, 600)?;
    let (_, challenge) = take_challenge(&app, body.challenge_id, &["login"]).await?;
    let row: Option<(Vec<u8>, String, String)> = sqlx::query_as("select p.sec1, p.name, m.name from passkeys p join members m on m.id = p.member_id where p.id = ?1").bind(&body.credential.id).fetch_optional(&app.db).await?;
    let Some((sec1, name, person)) = row else { return Err(denied("this passkey is not one of the console's")) };
    webauthn::assert(&body.credential, &sec1, &challenge, &app.site).map_err(denied)?;
    audit(&app, &person, "signed_in", json!({ "passkey": name })).await;
    start_session(&app, &body.credential.id).await
}

async fn logout(State(app): State<Shared>, headers: HeaderMap) -> Result<Response, Fail> {
    if let Some(value) = cookie_value(&headers) {
        sqlx::query("delete from sessions where token_hash = ?1").bind(hash(&value)).execute(&app.db).await?;
    }
    let _ = ok();
    Ok(([(header::SET_COOKIE, format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"))], Json(json!({ "ok": true }))).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> sqlx::SqlitePool {
        let db = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        let m = Uuid::new_v4();
        sqlx::query("insert into members (id, name, role) values (?1, 'Alex', 'admin')").bind(m).execute(&db).await.unwrap();
        sqlx::query("insert into passkeys (id, name, sec1, member_id) values ('pk', 'iPhone', x'00', ?1)").bind(m).execute(&db).await.unwrap();
        db
    }

    /// Minutes until the session ends. Dates as days are floats: read in the millisecond the
    /// session was made, an hour can come out a hair over 60.
    async fn left(db: &sqlx::SqlitePool, cookie: &str) -> f64 {
        sqlx::query_scalar("select (julianday(expires_at) - julianday('now')) * 1440 from sessions where token_hash = ?1").bind(hash(cookie)).fetch_one(db).await.unwrap()
    }

    #[tokio::test]
    async fn a_session_ends_after_an_hour_without_use_and_use_renews_it() {
        let db = db().await;
        let cookie = new_session(&db, "pk").await.unwrap();
        assert!((59.0..=60.001).contains(&left(&db, &cookie).await));
        // Twenty minutes pass; the page polls on its own: that is not use.
        sqlx::query("update sessions set expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+40 minutes')").execute(&db).await.unwrap();
        assert!(session_member(&db, &cookie, false).await.unwrap().is_some());
        assert!(left(&db, &cookie).await < 41.0);
        // The person does something: an hour from now again.
        assert!(session_member(&db, &cookie, true).await.unwrap().is_some());
        assert!(left(&db, &cookie).await > 59.0);
        // An hour without use: signed out.
        sqlx::query("update sessions set expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 minutes')").execute(&db).await.unwrap();
        assert!(session_member(&db, &cookie, true).await.unwrap().is_none(), "use after it ended does not bring it back");
    }

    #[test]
    fn the_cookie_lasts_and_follows_links_from_email() {
        let c = session_cookie("v", true);
        assert!(c.contains("SameSite=Lax") && c.contains("HttpOnly") && c.contains("Secure"), "{c}");
        assert!(c.contains(&format!("Max-Age={}", 30 * 86400)), "the server, not the cookie, ends a session: {c}");
    }
}
