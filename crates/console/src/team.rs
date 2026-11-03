//! The team: members, admins, invitations and removal.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use crate::db::Uuid;

use crate::Shared;
use crate::auth::{Admin, Member, audit};
use crate::util::{Fail, Res, bad, hash, ok, token};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Admin,
    Member,
}

impl Role {
    pub fn parse(text: &str) -> Role {
        if text == "admin" { Role::Admin } else { Role::Member }
    }
    pub fn word(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Member => "member",
        }
    }
}

const INVITE_HOURS: i64 = 48;

/// An invitation works once, within 48 hours of being made.
pub fn invite_usable(created: DateTime<Utc>, used: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    used.is_none() && now < created + Duration::hours(INVITE_HOURS)
}

/// Removing someone (`new_role` = None) or changing their role must leave the team an admin.
pub fn may_change(admins: usize, target_is_admin: bool, new_role: Option<Role>) -> Result<(), &'static str> {
    if target_is_admin && admins <= 1 && new_role != Some(Role::Admin) { Err("a team needs an admin") } else { Ok(()) }
}

/// A person's name as the console keeps it: one plain line, at most 60 characters.
pub fn person_name(text: &str) -> Option<String> {
    let name: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(60).collect::<String>().trim().to_string();
    (!name.is_empty()).then_some(name)
}

pub struct Invite {
    pub name: String,
}

const SPENT: &str = "this invite was used or has expired";

/// An invitation that can still be used, by its token.
pub async fn open_invite(app: &Shared, token: &str) -> Result<Invite, Fail> {
    let row: Option<(String, DateTime<Utc>, Option<DateTime<Utc>>)> = sqlx::query_as("select name, created_at, used_at from invites where token_hash = ?1").bind(hash(token)).fetch_optional(&app.db).await?;
    match row {
        Some((name, created, used)) if invite_usable(created, used, Utc::now()) => Ok(Invite { name }),
        _ => Err(bad(SPENT)),
    }
}

/// Use an invitation (by the hash of its token), once.
pub async fn use_invite(db: &mut sqlx::SqliteConnection, token_hash: &str) -> Result<Role, Fail> {
    let row: Option<(String,)> = sqlx::query_as(&format!("update invites set used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where token_hash = ?1 and used_at is null and created_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-{INVITE_HOURS} hours') returning role")).bind(token_hash).fetch_optional(db).await?;
    row.map(|(r,)| Role::parse(&r)).ok_or_else(|| bad(SPENT))
}

/// Names are how people tell each other's work apart (and how approvals match git's): one each.
pub async fn name_free(db: &mut sqlx::SqliteConnection, name: &str) -> Result<(), Fail> {
    let taken: bool = sqlx::query_scalar("select exists (select 1 from members where lower(name) = lower(?1))").bind(name).fetch_one(db).await?;
    if taken { Err(bad("someone on the team already has that name; use another")) } else { Ok(()) }
}

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/team", get(team))
        .route("/team/invites", post(invite))
        .route("/team/invites/{id}/cancel", post(cancel_invite))
        .route("/team/members/{id}/remove", post(remove))
        .route("/team/members/{id}/role", post(set_role))
        .route("/join/{token}", get(join_info))
        .route("/me/name", post(rename))
        .route("/me/email", post(set_email))
        .route("/verify/{token}", get(verify))
}

async fn team(State(app): State<Shared>, me: Member) -> Res {
    let members: serde_json::Value = sqlx::query("select m.id, m.name, m.role, case when ?1 or m.id = ?2 then m.email end as email, m.email_verified, m.created_at, (select count(*) from passkeys p where p.member_id = m.id) as passkeys from members m order by m.created_at").bind(me.role == Role::Admin).bind(me.id).fetch_all(&app.db).await.map(|r| crate::db::rows_json(&r))?;
    let invites: serde_json::Value = if me.role == Role::Admin {
        sqlx::query(&format!("select id, name, role, created_at, strftime('%Y-%m-%dT%H:%M:%fZ', created_at, '+{INVITE_HOURS} hours') as expires_at from invites where used_at is null and created_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-{INVITE_HOURS} hours') order by created_at desc")).fetch_all(&app.db).await.map(|r| crate::db::rows_json(&r))?
    } else {
        json!([])
    };
    Ok(Json(json!({ "members": members, "invites": invites, "me": { "id": me.id, "role": me.role.word() } })))
}

#[derive(Deserialize)]
struct NewInvite {
    name: String,
    role: String,
    /// The team's secret, wrapped by a key only the link's fragment carries.
    sealed_bundle: Option<String>,
}

async fn invite(State(app): State<Shared>, Admin(me): Admin, Json(body): Json<NewInvite>) -> Res {
    let name = person_name(&body.name).ok_or_else(|| bad("say who you are inviting"))?;
    let role = Role::parse(&body.role);
    name_free(&mut *app.db.acquire().await?, &name).await?;
    let secret = token();
    let bundle = match body.sealed_bundle.as_deref() {
        Some(b) => Some(crate::keys::unb64(b)?),
        None => None,
    };
    sqlx::query("insert into invites (id, token_hash, name, role, created_by, sealed_bundle) values (?1, ?2, ?3, ?4, ?5, ?6)").bind(Uuid::new_v4()).bind(hash(&secret)).bind(&name).bind(role.word()).bind(me.id).bind(bundle).execute(&app.db).await?;
    audit(&app, &me.name, "invited", json!({ "name": name, "role": role.word() })).await;
    Ok(Json(json!({ "link": format!("{}/join/{secret}", app.site.origin), "expires_in_hours": INVITE_HOURS })))
}

async fn join_info(State(app): State<Shared>, Path(token): Path<String>) -> Res {
    let invite = open_invite(&app, &token).await?;
    let bundle: Option<Vec<u8>> = sqlx::query_scalar("select sealed_bundle from invites where token_hash = ?1").bind(hash(&token)).fetch_one(&app.db).await?;
    Ok(Json(json!({ "name": invite.name, "sealed_bundle": bundle.map(|b| crate::keys::b64(&b)) })))
}

/// The admins, locked for the rest of the transaction: two admins acting at once see each other.
async fn locked_admins(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<Vec<Uuid>, Fail> {
    Ok(sqlx::query_scalar("select id from members where role = 'admin' order by id").fetch_all(&mut **tx).await?)
}

/// Remove someone: their passkeys go (and with them every session), their machines are revoked,
/// and the invitations they made stop working.
async fn remove(State(app): State<Shared>, Admin(me): Admin, Path(id): Path<Uuid>) -> Res {
    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let admins = locked_admins(&mut tx).await?;
    if !admins.contains(&me.id) {
        return Err(crate::util::forbidden("only an admin can do that"));
    }
    may_change(admins.len(), admins.contains(&id), None).map_err(bad)?;
    sqlx::query("update machines set revoked = true where member_id = ?1").bind(id).execute(&mut *tx).await?;
    sqlx::query("update invites set used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where created_by = ?1 and used_at is null").bind(id).execute(&mut *tx).await?;
    let name: Option<String> = sqlx::query_scalar("delete from members where id = ?1 returning name").bind(id).fetch_optional(&mut *tx).await?;
    let name = name.ok_or_else(|| crate::util::missing("there is no such member"))?;
    tx.commit().await?;
    audit(&app, &me.name, "member_removed", json!({ "name": name })).await;
    ok()
}

async fn cancel_invite(State(app): State<Shared>, Admin(me): Admin, Path(id): Path<Uuid>) -> Res {
    sqlx::query("update invites set used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') where id = ?1 and used_at is null").bind(id).execute(&app.db).await?;
    audit(&app, &me.name, "invite_cancelled", json!({ "invite": id })).await;
    ok()
}

#[derive(Deserialize)]
struct NewRole {
    role: String,
}

async fn set_role(State(app): State<Shared>, Admin(me): Admin, Path(id): Path<Uuid>, Json(body): Json<NewRole>) -> Res {
    let new = Role::parse(&body.role);
    let mut tx = app.db.begin_with("BEGIN IMMEDIATE").await?;
    let admins = locked_admins(&mut tx).await?;
    if !admins.contains(&me.id) {
        return Err(crate::util::forbidden("only an admin can do that"));
    }
    may_change(admins.len(), admins.contains(&id), Some(new)).map_err(bad)?;
    let name: Option<String> = sqlx::query_scalar("update members set role = ?2 where id = ?1 returning name").bind(id).bind(new.word()).fetch_optional(&mut *tx).await?;
    let name = name.ok_or_else(|| crate::util::missing("there is no such member"))?;
    tx.commit().await?;
    audit(&app, &me.name, "role_changed", json!({ "member": name, "role": new.word() })).await;
    ok()
}

#[derive(Deserialize)]
struct NewEmail {
    email: String,
}

/// Your address for alerts. Nothing but the confirmation goes to it until you open that link.
async fn set_email(State(app): State<Shared>, me: Member, Json(body): Json<NewEmail>) -> Res {
    // A few confirmations a day per person, and per address: no sending mail to strangers.
    if !app.limits.allow_at(&me.id.to_string(), "confirm-email", 5, 86_400, chrono::Utc::now().timestamp() as u64) {
        return Err(crate::util::too_many("too many confirmation emails today; try again tomorrow"));
    }
    let email = body.email.trim().to_string();
    if email.len() > 200 || email.chars().any(|c| c.is_whitespace() || c.is_control()) || !email.split_once('@').is_some_and(|(a, b)| !a.is_empty() && b.contains('.')) {
        return Err(bad("that is not an email address"));
    }
    let sent_there: i64 = sqlx::query_scalar("select count(*) from alerts where kind = 'verify' and to_address = ?1 and at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')").bind(&email).fetch_one(&app.db).await?;
    if sent_there >= 3 {
        return Err(crate::util::too_many("that address has had enough confirmation emails today"));
    }
    sqlx::query("update members set email = ?2, email_verified = false where id = ?1").bind(me.id).bind(&email).execute(&app.db).await?;
    audit(&app, &me.name, "email_set", json!({})).await;
    let secret = token();
    sqlx::query("delete from email_tokens where member_id = ?1").bind(me.id).execute(&app.db).await?;
    sqlx::query("insert into email_tokens (token_hash, member_id, email) values (?1, ?2, ?3)").bind(hash(&secret)).bind(me.id).bind(&email).execute(&app.db).await?;
    crate::alerts::queue_to(&app, me.id, &email, "05: confirm your email", "Open this link to get 05 alerts at this address. If you did not ask for this, ignore it.", &format!("/verify/{secret}")).await;
    ok()
}

/// Confirm an address by the link sent to it, within 24 hours.
async fn verify(State(app): State<Shared>, Path(token): Path<String>) -> Res {
    let row: Option<(Uuid, String)> = sqlx::query_as("delete from email_tokens where token_hash = ?1 and created_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-24 hours') returning member_id, email").bind(hash(&token)).fetch_optional(&app.db).await?;
    let Some((member, email)) = row else { return Err(bad("this link was used or has expired; send a new one from Settings")) };
    sqlx::query("update members set email_verified = true where id = ?1 and email = ?2").bind(member).bind(&email).execute(&app.db).await?;
    Ok(Json(json!({ "email": email })))
}

#[derive(Deserialize)]
struct Rename {
    name: String,
}

/// Your name, as your machines' work is recorded under it (git's user.name) for approvals to match.
async fn rename(State(app): State<Shared>, me: Member, Json(body): Json<Rename>) -> Res {
    let name = person_name(&body.name).ok_or_else(|| bad("say your name"))?;
    if name.to_lowercase() != me.name.to_lowercase() {
        name_free(&mut *app.db.acquire().await?, &name).await?;
    }
    sqlx::query("update members set name = ?2 where id = ?1").bind(me.id).bind(&name).execute(&app.db).await?;
    audit(&app, &me.name, "renamed", json!({ "to": name })).await;
    ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn an_invite_is_good_once_for_48_hours() {
        let made = Utc::now();
        assert!(invite_usable(made, None, made + Duration::hours(47)));
        assert!(!invite_usable(made, None, made + Duration::hours(49)));
        assert!(!invite_usable(made, Some(made + Duration::hours(1)), made + Duration::hours(2)));
    }

    #[test]
    fn a_team_keeps_an_admin() {
        assert_eq!(may_change(1, true, Some(Role::Member)), Err("a team needs an admin"));
        assert_eq!(may_change(1, true, None), Err("a team needs an admin"));
        assert_eq!(may_change(1, true, Some(Role::Admin)), Ok(()));
        assert_eq!(may_change(2, true, None), Ok(()));
        assert_eq!(may_change(1, false, None), Ok(()));
    }
}
