//! Email, only for what needs a person: an approval waiting, a policy edit that could not be
//! applied, a helper refusing a request, a passkey added. Each alert goes to the member it is
//! about, at the address they confirmed; one about nobody in particular goes to the admins. A burst
//! becomes one email. Emails say only that something needs you: never the repository, goals or file names.
//! They go out through Cloudflare Email Service or any SMTP server; without either, alerts are
//! kept in the console only.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{Value, json};
use crate::db::Uuid;

use crate::Shared;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provider {
    Cloudflare { account: String, token: String },
    Smtp { url: String },
    Off,
}

/// Cloudflare when both of its settings are there, else SMTP when `SMTP_URL` is, else off.
pub fn provider_from(var: &dyn Fn(&str) -> Option<String>) -> Provider {
    match (var("CLOUDFLARE_ACCOUNT_ID"), var("CLOUDFLARE_API_TOKEN"), var("SMTP_URL")) {
        (Some(account), Some(token), _) => Provider::Cloudflare { account, token },
        (_, _, Some(url)) => Provider::Smtp { url },
        _ => Provider::Off,
    }
}

/// The email settings, checked: a provider needs your own sender address (mail from someone else's
/// domain is refused or lands in spam), and SMTP needs TLS (its password would cross the network in
/// the clear).
pub fn mail_from(var: &dyn Fn(&str) -> Option<String>) -> Result<(Provider, String), String> {
    let provider = provider_from(var);
    if let Provider::Smtp { url } = &provider {
        if url.starts_with("smtp://") && !url.contains("tls=required") {
            return Err("SMTP_URL sends its password unencrypted: use smtps://, or smtp:// with ?tls=required".into());
        }
    }
    match (&provider, var("ALERT_FROM")) {
        (Provider::Off, from) => Ok((provider, from.unwrap_or_default())),
        (_, Some(from)) if from.contains('@') => Ok((provider, from)),
        _ => Err("set ALERT_FROM to the address emails come from, on your own domain".into()),
    }
}

pub struct Mail {
    pub provider: Provider,
    pub from: String,
    pub origin: String,
}

impl Mail {
    pub fn enabled(&self) -> bool {
        self.provider != Provider::Off
    }
}

/// The body Cloudflare's send endpoint takes.
pub fn message(from: &str, to: &str, subject: &str, text: &str) -> Value {
    json!({ "from": { "address": from, "name": "05 console" }, "to": to, "subject": subject, "text": text })
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    Sent,
    /// Rate limited or Cloudflare is down: the alerts stay queued.
    Later,
    Failed(String),
}

/// What Cloudflare's answer means for the alerts in it.
pub fn outcome(status: u16, body: &Value) -> Outcome {
    if status == 429 || status >= 500 || body["errors"].as_array().is_some_and(|e| e.iter().any(|e| e["code"] == 10004)) {
        return Outcome::Later;
    }
    if body["success"] == true {
        return match body["result"]["permanent_bounces"].as_array().and_then(|b| b.first()).and_then(Value::as_str) {
            Some(address) => Outcome::Failed(format!("{address} bounced")),
            None => Outcome::Sent,
        };
    }
    match body["errors"].as_array().and_then(|e| e.first()) {
        Some(e) => Outcome::Failed(format!("Cloudflare said {} ({})", e["message"].as_str().unwrap_or("no reason"), e["code"])),
        None => Outcome::Failed(format!("Cloudflare answered {status}")),
    }
}

/// A plain-text email to one person, for SMTP.
pub fn smtp_message(from: &str, to: &str, subject: &str, text: &str) -> Result<lettre::Message, String> {
    lettre::Message::builder()
        .from(format!("05 console <{from}>").parse().map_err(|e| format!("the sender address: {e}"))?)
        .to(to.parse().map_err(|e| format!("the address {to}: {e}"))?)
        .subject(subject)
        .header(lettre::message::header::ContentType::TEXT_PLAIN)
        .body(text.to_string())
        .map_err(|e| e.to_string())
}

/// An alert for one member (the driver of the work it is about), or for the admins when nobody's.
pub async fn queue(app: &Shared, member: Option<Uuid>, kind: &str, subject: &str, body: &str, link: &str) {
    let _ = sqlx::query("insert into alerts (kind, subject, body, link, member_id) values (?1, ?2, ?3, ?4, ?5)").bind(kind).bind(subject).bind(body).bind(link).bind(member).execute(&app.db).await;
}

/// An alert to an address the member has not confirmed yet: only ever the confirmation.
pub async fn queue_to(app: &Shared, member: Uuid, address: &str, subject: &str, body: &str, link: &str) {
    let _ = sqlx::query("insert into alerts (kind, subject, body, link, member_id, to_address) values ('verify', ?1, ?2, ?3, ?4, ?5)").bind(subject).bind(body).bind(link).bind(member).bind(address).execute(&app.db).await;
}

async fn send(app: &Shared, client: &reqwest::Client, to: &str, subject: &str, text: &str) -> Outcome {
    match &app.mail.provider {
        Provider::Off => Outcome::Failed("email is off".into()),
        Provider::Cloudflare { account, token } => {
            let sent = client.post(format!("https://api.cloudflare.com/client/v4/accounts/{account}/email/sending/send")).bearer_auth(token).json(&message(&app.mail.from, to, subject, text)).send().await;
            match sent {
                Ok(r) => {
                    let status = r.status().as_u16();
                    outcome(status, &r.json::<Value>().await.unwrap_or(Value::Null))
                }
                Err(e) => {
                    tracing::warn!("email: {e}");
                    Outcome::Later
                }
            }
        }
        Provider::Smtp { url } => {
            use lettre::AsyncTransport;
            let message = match smtp_message(&app.mail.from, to, subject, text) {
                Ok(m) => m,
                Err(why) => return Outcome::Failed(why),
            };
            let transport = match lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::from_url(url) {
                Ok(t) => t.timeout(Some(Duration::from_secs(15))).build(),
                Err(e) => return Outcome::Failed(format!("SMTP_URL cannot be used: {e}")),
            };
            match transport.send(message).await {
                Ok(_) => Outcome::Sent,
                Err(e) if e.is_permanent() => Outcome::Failed(format!("the mail server refused it: {e}")),
                Err(e) => {
                    tracing::warn!("email: {e}");
                    Outcome::Later
                }
            }
        }
    }
}

type Pending = (i64, String, String, Option<String>);

/// Send what is waiting, every few seconds, to each person's confirmed address. A burst within
/// one pass becomes one email per person.
pub async fn sender(app: Shared) {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).build().expect("http client");
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let rows: Vec<(i64, String, String, Option<String>, Option<String>, Option<Uuid>, Option<String>, bool)> = match sqlx::query_as(
            "select a.id, a.subject, a.body, a.link, a.to_address, a.member_id, m.email, coalesce(m.email_verified, false) from alerts a left join members m on m.id = a.member_id where not a.sent and a.error is null order by a.id limit 50",
        )
        .fetch_all(&app.db)
        .await
        {
            Ok(rows) => rows,
            Err(_) => continue,
        };
        if rows.is_empty() {
            continue;
        }
        if !app.mail.enabled() {
            let ids: Vec<i64> = rows.iter().map(|r| r.0).collect();
            let _ = sqlx::query("update alerts set error = 'email is off: set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN, or SMTP_URL' where id in (select value from json_each(?1))").bind(serde_json::to_string(&ids).unwrap_or_default()).execute(&app.db).await;
            continue;
        }
        let admins: Vec<(String,)> = sqlx::query_as("select email from members where role = 'admin' and email_verified and email is not null").fetch_all(&app.db).await.unwrap_or_default();
        let mut by_address: BTreeMap<String, Vec<Pending>> = BTreeMap::new();
        let mut nowhere: Vec<i64> = Vec::new();
        for (id, subject, body, link, to_address, member, email, verified) in rows {
            let addresses: Vec<String> = match (to_address, member, email) {
                (Some(a), _, _) => vec![a],
                (None, Some(_), Some(e)) if verified => vec![e],
                (None, None, _) => admins.iter().map(|(e,)| e.clone()).collect(),
                _ => vec![],
            };
            if addresses.is_empty() {
                nowhere.push(id);
            }
            for a in addresses {
                by_address.entry(a).or_default().push((id, subject.clone(), body.clone(), link.clone()));
            }
        }
        let _ = sqlx::query("update alerts set error = 'no confirmed email address to send it to' where id in (select value from json_each(?1))").bind(serde_json::to_string(&nowhere).unwrap_or_default()).execute(&app.db).await;
        for (to, pending) in by_address {
            let ids: Vec<i64> = pending.iter().map(|p| p.0).collect();
            let (subject, text) = if pending.len() == 1 {
                let (_, s, b, l) = &pending[0];
                (s.clone(), format!("{b}\n\nOpen it: {}{}\n", app.mail.origin, l.clone().unwrap_or_default()))
            } else {
                let lines: Vec<String> = pending.iter().map(|(_, s, _, l)| format!("- {s}: {}{}", app.mail.origin, l.clone().unwrap_or_default())).collect();
                (format!("05: {} things need you", pending.len()), format!("{}\n", lines.join("\n")))
            };
            let text = format!("{text}\nApproving always asks for your passkey; this link only opens the page.\n");
            match send(&app, &client, &to, &subject, &text).await {
                Outcome::Sent => {
                    let _ = sqlx::query("update alerts set sent = true, link = case when kind = 'verify' then null else link end where id in (select value from json_each(?1))").bind(serde_json::to_string(&ids).unwrap_or_default()).execute(&app.db).await;
                }
                Outcome::Failed(why) => {
                    let _ = sqlx::query("update alerts set error = ?2 where id in (select value from json_each(?1))").bind(serde_json::to_string(&ids).unwrap_or_default()).bind(why).execute(&app.db).await;
                }
                Outcome::Later => tokio::time::sleep(Duration::from_secs(55)).await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_needs_its_own_sender_and_tls() {
        let env = |pairs: &'static [(&'static str, &'static str)]| move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string());
        assert!(mail_from(&env(&[])).is_ok(), "no email at all is fine");
        assert!(mail_from(&env(&[("SMTP_URL", "smtps://u:p@mail.example.com:465")])).is_err(), "a provider without ALERT_FROM");
        assert_eq!(mail_from(&env(&[("SMTP_URL", "smtps://u:p@mail.example.com:465"), ("ALERT_FROM", "05@example.com")])).unwrap().1, "05@example.com");
        assert!(mail_from(&env(&[("SMTP_URL", "smtp://u:p@mail.example.com:25"), ("ALERT_FROM", "05@example.com")])).is_err(), "credentials in the clear");
        assert!(mail_from(&env(&[("SMTP_URL", "smtp://u:p@mail.example.com:587?tls=required"), ("ALERT_FROM", "05@example.com")])).is_ok());
    }

    #[test]
    fn provider_is_chosen_from_settings() {
        let vars = |set: &'static [(&'static str, &'static str)]| move |k: &str| set.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string());
        assert_eq!(provider_from(&vars(&[("CLOUDFLARE_ACCOUNT_ID", "a"), ("CLOUDFLARE_API_TOKEN", "t")])), Provider::Cloudflare { account: "a".into(), token: "t".into() });
        assert_eq!(provider_from(&vars(&[("SMTP_URL", "smtps://u:p@mail.example:465")])), Provider::Smtp { url: "smtps://u:p@mail.example:465".into() });
        assert_eq!(provider_from(&vars(&[("CLOUDFLARE_ACCOUNT_ID", "a"), ("CLOUDFLARE_API_TOKEN", "t"), ("SMTP_URL", "smtp://x")])), Provider::Cloudflare { account: "a".into(), token: "t".into() }, "Cloudflare wins");
        assert_eq!(provider_from(&vars(&[("CLOUDFLARE_ACCOUNT_ID", "a")])), Provider::Off, "half a Cloudflare setup is off");
        assert_eq!(provider_from(&vars(&[])), Provider::Off);
    }

    #[test]
    fn smtp_message_is_plain_text_to_one_member() {
        let m = smtp_message("alerts@example.com", "me@example.com", "05: approve this", "body text").unwrap();
        let raw = String::from_utf8(m.formatted()).unwrap();
        assert!(raw.contains("To: me@example.com"), "{raw}");
        assert!(raw.contains("Subject: 05: approve this"), "{raw}");
        assert!(raw.contains("Content-Type: text/plain"), "{raw}");
        assert!(raw.contains("body text"), "{raw}");
    }

    #[test]
    fn the_message_cloudflare_expects() {
        let m = message("alerts@use05.dev", "me@example.com", "05: approve this", "body");
        assert_eq!(m, json!({ "from": { "address": "alerts@use05.dev", "name": "05 console" }, "to": "me@example.com", "subject": "05: approve this", "text": "body" }));
    }

    #[test]
    fn delivered_and_queued_are_sent() {
        let ok = json!({ "success": true, "errors": [], "result": { "delivered": ["me@example.com"], "permanent_bounces": [], "queued": [] } });
        assert_eq!(outcome(200, &ok), Outcome::Sent);
        let queued = json!({ "success": true, "errors": [], "result": { "delivered": [], "permanent_bounces": [], "queued": ["me@example.com"] } });
        assert_eq!(outcome(200, &queued), Outcome::Sent);
    }

    #[test]
    fn a_bounce_or_a_refusal_is_kept_as_the_reason() {
        let bounced = json!({ "success": true, "errors": [], "result": { "delivered": [], "permanent_bounces": ["me@example.com"], "queued": [] } });
        assert_eq!(outcome(200, &bounced), Outcome::Failed("me@example.com bounced".into()));
        let refused = json!({ "success": false, "errors": [{ "code": 10102, "message": "email.sending.error.forbidden" }], "result": null });
        assert_eq!(outcome(403, &refused), Outcome::Failed("Cloudflare said email.sending.error.forbidden (10102)".into()));
    }

    #[test]
    fn rate_limits_and_outages_are_tried_again() {
        let limited = json!({ "success": false, "errors": [{ "code": 10004, "message": "rate limited" }], "result": null });
        assert_eq!(outcome(429, &limited), Outcome::Later);
        assert_eq!(outcome(502, &json!(null)), Outcome::Later);
    }
}
