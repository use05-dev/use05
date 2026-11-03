//! The console's database is one SQLite file. What SQLite needs said once: ids stored as text, and
//! rows turned into JSON for the API. Times are text in one format that sorts as time, made in SQL
//! only: strftime('%Y-%m-%dT%H:%M:%fZ', 'now'[, '-15 minutes']).

use base64::Engine;
use serde_json::{Map, Value};
use sqlx::sqlite::{Sqlite, SqliteArgumentValue, SqliteRow, SqliteTypeInfo, SqliteValueRef};
use sqlx::{Column, Row, TypeInfo, ValueRef};

/// A uuid stored as text, so a person reading the file reads ids, and an id bound from Rust always
/// matches one written by SQL. Used in place of `uuid::Uuid` throughout the console.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Uuid(pub uuid::Uuid);

impl Uuid {
    pub fn new_v4() -> Uuid {
        Uuid(uuid::Uuid::new_v4())
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for Uuid {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Uuid, uuid::Error> {
        s.parse().map(Uuid)
    }
}

impl sqlx::Type<Sqlite> for Uuid {
    fn type_info() -> SqliteTypeInfo {
        <String as sqlx::Type<Sqlite>>::type_info()
    }
}

impl<'q> sqlx::Encode<'q, Sqlite> for Uuid {
    fn encode_by_ref(&self, buf: &mut Vec<SqliteArgumentValue<'q>>) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <String as sqlx::Encode<Sqlite>>::encode(self.0.to_string(), buf)
    }
}

impl<'r> sqlx::Decode<'r, Sqlite> for Uuid {
    fn decode(value: SqliteValueRef<'r>) -> Result<Uuid, sqlx::error::BoxDynError> {
        Ok(Uuid(<&str as sqlx::Decode<Sqlite>>::decode(value)?.parse()?))
    }
}

/// Columns that hold a yes or no (SQLite keeps them as 0 and 1).
const BOOLEAN: &[&str] = &["online", "mine", "claimed", "yours", "allowed", "revoked", "approved", "denied", "email_verified", "sent", "stale"];
/// Columns that hold JSON (SQLite keeps it as text).
const JSON: &[&str] = &["result", "detail", "prepared", "payload", "data", "context"];

/// One row as a JSON object: numbers, yes or no, JSON, text, and bytes as base64.
pub fn row_json(row: Option<&SqliteRow>) -> Value {
    let Some(row) = row else { return Value::Null };
    let mut out = Map::new();
    for (i, column) in row.columns().iter().enumerate() {
        let name = column.name();
        let raw = row.try_get_raw(i).ok();
        let kind = raw.as_ref().filter(|r| !r.is_null()).map(|r| r.type_info().name().to_string());
        let value = match kind.as_deref() {
            None => Value::Null,
            Some("INTEGER") if BOOLEAN.contains(&name) => Value::Bool(row.try_get::<i64, _>(i).unwrap_or(0) != 0),
            Some("INTEGER") => row.try_get::<i64, _>(i).map(Value::from).unwrap_or(Value::Null),
            Some("REAL") => row.try_get::<f64, _>(i).map(Value::from).unwrap_or(Value::Null),
            Some("BLOB") => Value::String(base64::engine::general_purpose::STANDARD.encode(row.try_get::<Vec<u8>, _>(i).unwrap_or_default())),
            Some(_) => {
                let text: String = row.try_get(i).unwrap_or_default();
                if JSON.contains(&name) { serde_json::from_str(&text).unwrap_or(Value::String(text)) } else { Value::String(text) }
            }
        };
        out.insert(name.to_string(), value);
    }
    Value::Object(out)
}

/// Rows as a JSON array.
pub fn rows_json(rows: &[SqliteRow]) -> Value {
    Value::Array(rows.iter().map(|r| row_json(Some(r))).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn rows_become_json_with_booleans_objects_and_base64() {
        let db = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        let rows = sqlx::query(r#"select 1 as online, 0 as mine, 2 as n, '{"a":1}' as result, x'00ff' as sealed, null as gone, 'hi' as name"#).fetch_all(&db).await.unwrap();
        assert_eq!(rows_json(&rows), json!([{ "online": true, "mine": false, "n": 2, "result": { "a": 1 }, "sealed": "AP8=", "gone": null, "name": "hi" }]));
        assert_eq!(row_json(rows.first()), json!({ "online": true, "mine": false, "n": 2, "result": { "a": 1 }, "sealed": "AP8=", "gone": null, "name": "hi" }));
        assert_eq!(row_json(None), json!(null));
    }

    #[tokio::test]
    async fn ids_are_stored_as_text() {
        let db = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        let id = Uuid::new_v4();
        let (kind, back): (String, Uuid) = sqlx::query_as("select typeof(?1), ?1").bind(id).fetch_one(&db).await.unwrap();
        assert_eq!((kind.as_str(), back), ("text", id));
        assert_eq!(serde_json::to_value(id).unwrap(), json!(id.to_string()));
    }

    #[tokio::test]
    async fn one_timestamp_format_sorts_as_time() {
        let db = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        let (now, before): (String, String) = sqlx::query_as("select strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-15 minutes')").fetch_one(&db).await.unwrap();
        assert!(before < now && now.ends_with('Z') && now.len() == "2026-11-02T10:00:00.000Z".len(), "{before} {now}");
    }
}
