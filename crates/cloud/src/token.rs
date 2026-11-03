//! A token a member made in their browser for a cloud agent session or a CI job (D86): its own
//! keys, the team's key and version as the member's browser held them, the repository it speaks
//! for, and a bearer secret. `u05_` and base64url JSON.

use base64::Engine;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Reporter {
    /// `session` or `ci`.
    pub kind: String,
    pub url: String,
    pub bearer: String,
    pub x: [u8; 32],
    pub ed: [u8; 32],
    pub team: [u8; 32],
    pub version: i64,
    pub repo: String,
    pub name: String,
    /// Who made it: the person CI prepares approvals for.
    pub person: String,
}

#[derive(Deserialize)]
struct Raw {
    v: u32,
    kind: String,
    url: String,
    bearer: String,
    x: String,
    ed: String,
    team: String,
    version: i64,
    repo: String,
    name: String,
    #[serde(default)]
    person: String,
}

impl Reporter {
    pub fn parse(text: &str) -> Result<Reporter, String> {
        let body = text.trim().strip_prefix("u05_").ok_or("that is not a 05 token (they start with u05_)")?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body.trim_end_matches('=')).map_err(|_| "the token is damaged: copy it again")?;
        let r: Raw = serde_json::from_slice(&json).map_err(|_| "the token is damaged: copy it again")?;
        if r.v != 1 || !["session", "ci"].contains(&r.kind.as_str()) {
            return Err("this token is for something else, or from a newer 05".into());
        }
        if !crate::checks::console_url_ok(&r.url) {
            return Err("the token names a console that is not on https".into());
        }
        let key = |hex_text: &str| -> Result<[u8; 32], String> { hex::decode(hex_text).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| "the token is damaged: copy it again".to_string()) };
        let team = base64::engine::general_purpose::STANDARD.decode(&r.team).ok().and_then(|b| b.try_into().ok()).ok_or("the token is damaged: copy it again")?;
        Ok(Reporter { kind: r.kind, url: r.url.trim_end_matches('/').to_string(), bearer: r.bearer, x: key(&r.x)?, ed: key(&r.ed)?, team, version: r.version, repo: r.repo, name: r.name, person: r.person })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn token(json: &str) -> String {
        format!("u05_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
    }

    #[test]
    fn a_token_reads_back_with_its_keys_and_its_one_repository() {
        let t = token(r#"{"v":1,"kind":"session","url":"https://console.example.com","bearer":"b","x":"0101010101010101010101010101010101010101010101010101010101010101","ed":"0202020202020202020202020202020202020202020202020202020202020202","team":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","version":2,"repo":"abc123","name":"Cloud session: acme"}"#);
        let r = Reporter::parse(&format!("  {t}\n")).unwrap();
        assert_eq!((r.kind.as_str(), r.repo.as_str(), r.version, r.x, r.ed[0]), ("session", "abc123", 2, [1u8; 32], 2));
        assert_eq!(r.team.len(), 32);
    }

    #[test]
    fn a_token_that_is_not_one_is_refused() {
        assert!(Reporter::parse("u05_???").is_err());
        assert!(Reporter::parse("ghp_abc").is_err(), "another kind of token");
        assert!(Reporter::parse(&token(r#"{"v":1,"kind":"admin","url":"https://c","bearer":"b","x":"01","ed":"02","team":"AQ==","version":1,"repo":"r","name":"n"}"#)).is_err());
        assert!(Reporter::parse(&token(r#"{"v":1,"kind":"ci","url":"http://evil.example","bearer":"b","x":"0101010101010101010101010101010101010101010101010101010101010101","ed":"0202020202020202020202020202020202020202020202020202020202020202","team":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","version":1,"repo":"r","name":"n"}"#)).is_err(), "not https");
    }
}
