//! The 05 console, self-hosted: passkey sign-in, metadata only.
//!
//! The machines' helpers connect out to this server; it never connects to them. What it can ask a
//! helper to do is fixed and small (file a signed approval, prepare or apply a policy edit, send
//! the folder tree), and the helper checks every request itself, so a compromised console cannot
//! make a machine run anything or approve anything without the owner's passkey.

mod agent;
mod alerts;
mod claim;
mod api;
mod auth;
mod db;
mod keys;
mod limits;
mod team;
mod util;
mod webauthn;

use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderValue, header};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

pub struct App {
    pub db: SqlitePool,
    pub site: webauthn::Site,
    /// Who may set up a fresh console (claim.rs).
    pub claims: claim::Claims,
    /// Bumped whenever something changes, so open pages can update at once.
    pub changes: tokio::sync::watch::Sender<u64>,
    pub secure_cookie: bool,
    pub mail: alerts::Mail,
    pub limits: limits::Limiter,
}

pub type Shared = Arc<App>;

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    if var("DATABASE_URL").is_some() && var("DATABASE").is_none() {
        anyhow::bail!("the console keeps its data in one SQLite file now: set DATABASE to its path (in the image, /data/console.db on a volume), not DATABASE_URL");
    }
    let path = var("DATABASE").unwrap_or_else(|| "console.db".into());
    let origin = var("ORIGIN").unwrap_or_else(|| "http://localhost:8080".into());
    let rp_id = var("RP_ID").unwrap_or_else(|| origin.split("://").nth(1).unwrap_or("localhost").split(':').next().unwrap_or("localhost").to_string());
    // One file; WAL lets the browser read while machines write, and a busy writer is waited for.
    let options = SqliteConnectOptions::new().filename(&path).create_if_missing(true).journal_mode(SqliteJournalMode::Wal).foreign_keys(true).busy_timeout(std::time::Duration::from_secs(5));
    let db = SqlitePoolOptions::new().max_connections(8).connect_with(options).await?;
    sqlx::migrate!("./migrations").run(&db).await?;

    let (provider, from) = alerts::mail_from(&var).map_err(|e| anyhow::anyhow!(e))?;
    let app = Arc::new(App {
        db,
        secure_cookie: origin.starts_with("https://"),
        site: webauthn::Site { rp_id, origin: origin.clone() },
        claims: claim::Claims::new(var("SETUP_SECRET")),
        changes: tokio::sync::watch::channel(0).0,
        limits: limits::Limiter::default(),
        mail: alerts::Mail { provider, from, origin },
    });
    tokio::spawn(alerts::sender(app.clone()));
    // A fresh console says, in its own log, how its owner claims it.
    let owned: i64 = sqlx::query_scalar("select count(*) from passkeys").fetch_one(&app.db).await?;
    if owned == 0 {
        let code = if app.claims.made_here { app.claims.code().to_string() } else { "the SETUP_SECRET setting".to_string() };
        tracing::info!("05 console has no owner yet. Claim it from your terminal: use05 cloud login {} (claim code: {code})", app.mail.origin);
    }

    let web = var("WEB_DIR").unwrap_or_else(|| "web/dist".into());
    let spa = ServeDir::new(&web).fallback(ServeFile::new(format!("{web}/index.html")));
    let csp = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    let router = Router::new()
        .nest("/api", api::routes().merge(auth::routes()).merge(team::routes()).merge(keys::routes()))
        .nest("/agent", agent::routes())
        .layer(axum::middleware::from_fn_with_state(app.clone(), changed))
        .fallback_service(spa)
        .layer(SetResponseHeaderLayer::overriding(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(csp)))
        .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::overriding(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")))
        .layer(SetResponseHeaderLayer::overriding(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000")))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(8 * 1024 * 1024))
        .with_state(app);

    let port = var("PORT").unwrap_or_else(|| "8080".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    tracing::info!("05 console listening on {port}");
    axum::serve(listener, router).await?;
    Ok(())
}

/// Any change that went through (a record, an approval, a pairing, a policy edit) tells the open
/// pages to look again. They are told only that something changed, never what.
async fn changed(axum::extract::State(app): axum::extract::State<Shared>, req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let changing = req.method() != axum::http::Method::GET;
    let res = next.run(req).await;
    if changing && res.status().is_success() {
        app.changes.send_modify(|n| *n += 1);
    }
    res
}
