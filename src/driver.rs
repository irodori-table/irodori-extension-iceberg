use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Map, Value};

use crate::abi::{self, IrodoriConnectorBuffer};
use crate::rest_catalog::{self, RestCatalog};
use crate::{ABI_VERSION, CONFIG_JSON, DRIVER_LINKED, ENGINE, MANIFEST_JSON};

static CONNECTIONS: OnceLock<Mutex<HashMap<String, LakehouseConnection>>> = OnceLock::new();

struct LakehouseConnection {
    conn: duckdb::Connection,
    redaction_values: Vec<String>,
    catalog: Option<RestCatalog>,
}

#[derive(Default)]
struct ObjectMeta {
    schema: String,
    name: String,
    kind: String,
    columns: Vec<Value>,
}

type QueryRows = Vec<Vec<Value>>;
type QueryOutput = (Vec<String>, QueryRows, bool);

fn connections() -> &'static Mutex<HashMap<String, LakehouseConnection>> {
    CONNECTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn call_json(request: IrodoriConnectorBuffer) -> IrodoriConnectorBuffer {
    let request = match abi::parse_request(request) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let method = match abi::request_method(request.as_ref()) {
        Ok(method) => method,
        Err(response) => return response,
    };

    match method {
        "health" | "ping" => abi::ok(Map::from_iter([
            ("engine".to_string(), Value::String(ENGINE.to_string())),
            ("abiVersion".to_string(), json!(ABI_VERSION)),
            ("driverLinked".to_string(), Value::Bool(DRIVER_LINKED)),
        ])),
        "describe" | "capabilities" => abi::ok(Map::from_iter([
            ("engine".to_string(), Value::String(ENGINE.to_string())),
            ("abiVersion".to_string(), json!(ABI_VERSION)),
            ("driverLinked".to_string(), Value::Bool(DRIVER_LINKED)),
            (
                "manifest".to_string(),
                serde_json::from_str(MANIFEST_JSON).unwrap_or(Value::Null),
            ),
            (
                "config".to_string(),
                serde_json::from_str(CONFIG_JSON).unwrap_or(Value::Null),
            ),
        ])),
        "manifest" => abi::owned_buffer(MANIFEST_JSON.to_string()),
        "config" => abi::owned_buffer(CONFIG_JSON.to_string()),
        "connect" => connect(request.as_ref().expect("connect has request")),
        "query" => query(request.as_ref().expect("query has request")),
        "metadata" => metadata(request.as_ref().expect("metadata has request")),
        "close" => close(request.as_ref().expect("close has request")),
        other => abi::error(
            "connector.unknownMethod",
            format!("unknown connector method: {other}"),
        ),
    }
}

fn connect(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let conn = match duckdb::Connection::open_in_memory() {
        Ok(conn) => conn,
        Err(err) => return abi::error("connector.connectFailed", format!("connect failed: {err}")),
    };
    let redaction_values = redaction_values(request);
    if let Err(err) = apply_settings(&conn, request) {
        return abi::error("connector.connectFailed", redact(&redaction_values, &err));
    }
    let catalog = match rest_catalog::from_request(request) {
        Ok(catalog) => catalog,
        Err(err) => return abi::error("connector.connectFailed", redact(&redaction_values, &err)),
    };
    // Catalog mode owns table discovery; the single-path view only applies
    // when no catalog is configured.
    if catalog.is_none() {
        if let Err(err) = configure_connection(&conn, request) {
            return abi::error("connector.connectFailed", redact(&redaction_values, &err));
        }
    }
    let server_version = conn
        .query_row("select version()", [], |row| row.get::<_, String>(0))
        .unwrap_or_else(|_| "DuckDB lakehouse runtime".to_string());
    let mut guard = match connections().lock() {
        Ok(guard) => guard,
        Err(_) => {
            return abi::error(
                "connector.statePoisoned",
                "Connector connection state is poisoned.",
            )
        }
    };
    guard.insert(
        connection_id.clone(),
        LakehouseConnection {
            conn,
            redaction_values,
            catalog,
        },
    );
    abi::ok(Map::from_iter([
        ("engine".to_string(), Value::String(ENGINE.to_string())),
        ("connectionId".to_string(), Value::String(connection_id)),
        ("serverVersion".to_string(), Value::String(server_version)),
        ("driverLinked".to_string(), Value::Bool(DRIVER_LINKED)),
    ]))
}

fn query(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let Some(sql) = abi::string_field(request, "sql")
        .or_else(|| abi::string_field(request, "query"))
        .or_else(|| abi::string_field(request, "statement"))
    else {
        return abi::error(
            "connector.invalidRequest",
            "query requires a string sql, query, or statement field.",
        );
    };
    let mut guard = match connections().lock() {
        Ok(guard) => guard,
        Err(_) => {
            return abi::error(
                "connector.statePoisoned",
                "Connector connection state is poisoned.",
            )
        }
    };
    let Some(connection) = guard.get_mut(&connection_id) else {
        return abi::error(
            "connector.connectionNotFound",
            format!("no open connection: {connection_id}"),
        );
    };
    match run_query(&connection.conn, sql, abi::max_rows(request)) {
        Ok((columns, rows, truncated)) => abi::ok(Map::from_iter([
            ("connectionId".to_string(), Value::String(connection_id)),
            (
                "columns".to_string(),
                Value::Array(columns.into_iter().map(Value::String).collect()),
            ),
            (
                "rows".to_string(),
                Value::Array(rows.into_iter().map(Value::Array).collect()),
            ),
            ("truncated".to_string(), Value::Bool(truncated)),
        ])),
        Err(err) => abi::error(
            "connector.queryFailed",
            redact(&connection.redaction_values, &err),
        ),
    }
}

fn metadata(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let mut guard = match connections().lock() {
        Ok(guard) => guard,
        Err(_) => {
            return abi::error(
                "connector.statePoisoned",
                "Connector connection state is poisoned.",
            )
        }
    };
    let Some(connection) = guard.get_mut(&connection_id) else {
        return abi::error(
            "connector.connectionNotFound",
            format!("no open connection: {connection_id}"),
        );
    };
    if let Some(catalog) = &connection.catalog {
        return match rest_catalog::sync(catalog, &connection.conn) {
            Ok((metadata, warnings)) => abi::ok(Map::from_iter([
                ("connectionId".to_string(), Value::String(connection_id)),
                ("metadata".to_string(), metadata),
                (
                    "warnings".to_string(),
                    Value::Array(
                        warnings
                            .into_iter()
                            .map(|warning| {
                                Value::String(redact(&connection.redaction_values, &warning))
                            })
                            .collect(),
                    ),
                ),
            ])),
            Err(err) => abi::error(
                "connector.metadataFailed",
                redact(&connection.redaction_values, &err),
            ),
        };
    }
    match load_metadata(&connection.conn) {
        Ok(metadata) => abi::ok(Map::from_iter([
            ("connectionId".to_string(), Value::String(connection_id)),
            ("metadata".to_string(), metadata),
        ])),
        Err(err) => abi::error(
            "connector.metadataFailed",
            redact(&connection.redaction_values, &err),
        ),
    }
}

fn close(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let closed = match connections().lock() {
        Ok(mut guard) => guard.remove(&connection_id).is_some(),
        Err(_) => {
            return abi::error(
                "connector.statePoisoned",
                "Connector connection state is poisoned.",
            )
        }
    };
    abi::ok(Map::from_iter([
        ("connectionId".to_string(), Value::String(connection_id)),
        ("closed".to_string(), Value::Bool(closed)),
    ]))
}

fn configure_connection(conn: &duckdb::Connection, request: &Value) -> Result<(), String> {
    let Some(path) = option_string(
        request,
        &[
            "tablePath",
            "path",
            "location",
            "uri",
            "url",
            "connectionString",
        ],
    )
    .or_else(|| abi::profile_field(request, "database").map(str::to_string)) else {
        return Ok(());
    };
    let view = clean_identifier(
        &option_string(request, &["table", "tableName", "view", "viewName"])
            .unwrap_or_else(|| "lakehouse_table".to_string()),
    );
    let escaped_path = sql_string(&path);
    let sql = match ENGINE {
        "deltaLake" => {
            load_extension(conn, "httpfs", false)?;
            load_extension(conn, "delta", true)?;
            format!("create or replace view {view} as select * from delta_scan({escaped_path})")
        }
        "iceberg" | "s3Tables" => {
            load_extension(conn, "httpfs", false)?;
            load_extension(conn, "iceberg", true)?;
            format!("create or replace view {view} as select * from iceberg_scan({escaped_path})")
        }
        "hudi" | "hive" => {
            load_extension(conn, "httpfs", false)?;
            let pattern = parquet_pattern(&path);
            format!(
                "create or replace view {view} as select * from read_parquet({}, hive_partitioning=true, union_by_name=true)",
                sql_string(&pattern)
            )
        }
        _ => return Ok(()),
    };
    conn.execute_batch(&sql)
        .map_err(|err| format!("lakehouse table view creation failed: {err}"))?;
    Ok(())
}

fn apply_settings(conn: &duckdb::Connection, request: &Value) -> Result<(), String> {
    for statement in secret_statements(request) {
        conn.execute_batch(&statement)
            .map_err(|err| format!("DuckDB credential setup failed: {err}"))?;
    }
    for (field, setting) in [
        ("s3Region", "s3_region"),
        ("region", "s3_region"),
        ("s3Endpoint", "s3_endpoint"),
        ("s3UrlStyle", "s3_url_style"),
        ("s3AccessKeyId", "s3_access_key_id"),
        ("accessKeyId", "s3_access_key_id"),
        ("s3SecretAccessKey", "s3_secret_access_key"),
        ("secretAccessKey", "s3_secret_access_key"),
        ("s3SessionToken", "s3_session_token"),
        ("sessionToken", "s3_session_token"),
    ] {
        if let Some(value) = option_string(request, &[field]) {
            let sql = format!("set {setting} = {}", sql_string(&value));
            conn.execute_batch(&sql)
                .map_err(|err| format!("DuckDB setting {setting} failed: {err}"))?;
        }
    }
    Ok(())
}

pub(crate) fn load_extension(
    conn: &duckdb::Connection,
    extension: &str,
    required: bool,
) -> Result<(), String> {
    let install = format!("install {extension};");
    let load = format!("load {extension};");
    let install_result = conn.execute_batch(&install);
    let load_result = conn.execute_batch(&load);
    if required {
        load_result
            .or(install_result)
            .map_err(|err| format!("DuckDB extension {extension} unavailable: {err}"))?;
    }
    Ok(())
}

fn run_query(conn: &duckdb::Connection, sql: &str, cap: usize) -> Result<QueryOutput, String> {
    let lead = sql.trim_start().to_ascii_lowercase();
    let is_query = [
        "select", "with", "show", "pragma", "explain", "describe", "values", "table", "call",
    ]
    .iter()
    .any(|keyword| lead.starts_with(keyword));
    if !is_query {
        conn.execute(sql, [])
            .map_err(|err| format!("query failed: {err}"))?;
        return Ok((Vec::new(), Vec::new(), false));
    }

    let mut stmt = conn
        .prepare(sql)
        .map_err(|err| format!("query failed: {err}"))?;
    let mut duck_rows = stmt
        .query([])
        .map_err(|err| format!("query failed: {err}"))?;
    let columns = duck_rows
        .as_ref()
        .map(|stmt| {
            stmt.column_names()
                .iter()
                .map(|column| column.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let column_count = columns.len();
    let mut rows = Vec::new();
    let mut truncated = false;
    while let Some(row) = duck_rows
        .next()
        .map_err(|err| format!("query failed: {err}"))?
    {
        if rows.len() >= cap {
            truncated = true;
            break;
        }
        rows.push(
            (0..column_count)
                .map(|index| cell_to_json(row, index))
                .collect(),
        );
    }
    Ok((columns, rows, truncated))
}

fn load_metadata(conn: &duckdb::Connection) -> Result<Value, String> {
    let mut objects = BTreeMap::<(String, String), ObjectMeta>::new();
    let mut stmt = conn
        .prepare(
            "select table_schema, table_name, table_type \
             from information_schema.tables \
             where table_schema not in ('information_schema', 'pg_catalog') \
             order by table_schema, table_name",
        )
        .map_err(|err| format!("metadata objects failed: {err}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|err| format!("metadata objects failed: {err}"))?;
    for row in rows {
        let (schema, name, table_type) =
            row.map_err(|err| format!("metadata objects failed: {err}"))?;
        objects.insert(
            (schema.clone(), name.clone()),
            ObjectMeta {
                schema,
                name,
                kind: if table_type.eq_ignore_ascii_case("VIEW") {
                    "view".to_string()
                } else {
                    "table".to_string()
                },
                columns: Vec::new(),
            },
        );
    }

    let mut stmt = conn
        .prepare(
            "select table_schema, table_name, column_name, data_type, is_nullable, ordinal_position \
             from information_schema.columns \
             where table_schema not in ('information_schema', 'pg_catalog') \
             order by table_schema, table_name, ordinal_position",
        )
        .map_err(|err| format!("metadata columns failed: {err}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i32>(5)?,
            ))
        })
        .map_err(|err| format!("metadata columns failed: {err}"))?;
    for row in rows {
        let (schema, table, name, data_type, nullable, ordinal) =
            row.map_err(|err| format!("metadata columns failed: {err}"))?;
        if let Some(object) = objects.get_mut(&(schema, table)) {
            object.columns.push(json!({
                "name": name,
                "dataType": data_type,
                "nullable": nullable.eq_ignore_ascii_case("YES"),
                "ordinal": ordinal
            }));
        }
    }

    let mut schemas = BTreeMap::<String, Vec<Value>>::new();
    for object in objects.into_values() {
        schemas
            .entry(object.schema.clone())
            .or_default()
            .push(json!({
                "schema": object.schema,
                "name": object.name,
                "kind": object.kind,
                "columns": object.columns,
                "indexes": [],
                "primaryKey": [],
                "foreignKeys": []
            }));
    }
    Ok(json!({
        "schemas": schemas
            .into_iter()
            .map(|(name, objects)| json!({ "name": name, "objects": objects }))
            .collect::<Vec<_>>()
    }))
}

fn cell_to_json(row: &duckdb::Row, index: usize) -> Value {
    use duckdb::types::Value as DuckValue;
    match row.get::<usize, DuckValue>(index) {
        Ok(DuckValue::Null) => Value::Null,
        Ok(DuckValue::Boolean(value)) => Value::Bool(value),
        Ok(DuckValue::TinyInt(value)) => json!(value),
        Ok(DuckValue::SmallInt(value)) => json!(value),
        Ok(DuckValue::Int(value)) => json!(value),
        Ok(DuckValue::BigInt(value)) => json!(value),
        Ok(DuckValue::UTinyInt(value)) => json!(value),
        Ok(DuckValue::USmallInt(value)) => json!(value),
        Ok(DuckValue::UInt(value)) => json!(value),
        Ok(DuckValue::UBigInt(value)) => json!(value),
        Ok(DuckValue::Float(value)) => json!(value as f64),
        Ok(DuckValue::Double(value)) => json!(value),
        Ok(DuckValue::Text(value)) => Value::String(value),
        Ok(DuckValue::Blob(value)) => Value::String(format!("\\x{}", hex_encode(&value))),
        Ok(other) => Value::String(format!("{other:?}")),
        Err(_) => Value::Null,
    }
}

fn parquet_pattern(path: &str) -> String {
    if path.contains('*') || path.ends_with(".parquet") {
        path.to_string()
    } else {
        format!("{}/**/*.parquet", path.trim_end_matches('/'))
    }
}

fn clean_identifier(value: &str) -> String {
    let mut out = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if out.is_empty() {
        out = "lakehouse_table".to_string();
    }
    if out.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// The object-store credentials a profile implies, as DuckDB `CREATE SECRET`
/// statements.
///
/// The connector used to forward a handful of `SET s3_*` settings, which covers
/// exactly one of the credential sources `connector.config.json` declares:
/// a static access key. DuckDB's secret manager is the surface for the rest —
/// the AWS credential chain (and with it SSO and web identity), and the Azure
/// providers.
///
/// Pure on purpose. The statements are the whole behaviour worth testing, and
/// asserting on them needs no DuckDB, no network, and no credentials.
fn secret_statements(request: &Value) -> Vec<String> {
    let mut statements = Vec::new();
    if let Some(s3) = s3_secret(request) {
        statements.push(s3);
    }
    if let Some(azure) = azure_secret(request) {
        statements.push(azure);
    }
    statements
}

/// `CREATE SECRET` for S3-compatible storage, or `None` when the profile names
/// no S3 credential source and DuckDB's own defaults should stand.
fn s3_secret(request: &Value) -> Option<String> {
    let mut params: Vec<(&str, String)> = Vec::new();

    let key_id = option_string(
        request,
        &["s3AccessKeyId", "accessKeyId", "awsAccessKeyId", "user"],
    )
    .filter(|value| looks_like_access_key_id(value));
    let secret = option_string(
        request,
        &[
            "s3SecretAccessKey",
            "secretAccessKey",
            "awsSecretAccessKey",
            "password",
        ],
    );
    let session_token = option_string(
        request,
        &["s3SessionToken", "sessionToken", "awsSessionToken"],
    );
    let profile = option_string(request, &["awsProfile", "profile"]);
    let chain = option_string(request, &["awsCredentialChain", "credentialChain"]);
    let use_chain = option_string(request, &["awsUseCredentialChain", "useCredentialChain"])
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "yes"));

    // A static key pair is an explicit instruction; anything else that names a
    // credential source falls through to the chain, which is what carries SSO,
    // web identity, ECS/IMDS, and a profile's own `role_arn`.
    match (key_id, secret) {
        (Some(key_id), Some(secret)) => {
            params.push(("PROVIDER", "config".to_string()));
            params.push(("KEY_ID", sql_string(&key_id)));
            params.push(("SECRET", sql_string(&secret)));
            if let Some(token) = session_token {
                params.push(("SESSION_TOKEN", sql_string(&token)));
            }
        }
        _ if use_chain || profile.is_some() || chain.is_some() => {
            params.push(("PROVIDER", "credential_chain".to_string()));
            if let Some(chain) = chain {
                params.push(("CHAIN", sql_string(&chain)));
            }
            if let Some(profile) = profile {
                params.push(("PROFILE", sql_string(&profile)));
            }
        }
        _ => return None,
    }

    for (option, key) in [
        (["s3Region", "region", "awsRegion"].as_slice(), "REGION"),
        (["s3Endpoint", "endpoint"].as_slice(), "ENDPOINT"),
        (["s3UrlStyle", "urlStyle"].as_slice(), "URL_STYLE"),
    ] {
        if let Some(value) = option_string(request, option) {
            params.push((key, sql_string(&value)));
        }
    }

    Some(create_secret("irodori_s3", "s3", &params))
}

/// `CREATE SECRET` for Azure Blob / ADLS, or `None` when the profile names no
/// Azure credential source.
fn azure_secret(request: &Value) -> Option<String> {
    let mut params = azure_provider_params(request)?;
    if let Some(account) = option_string(request, &["azureAccountName", "accountName"]) {
        params.push(("ACCOUNT_NAME", sql_string(&account)));
    }
    Some(create_secret("irodori_azure", "azure", &params))
}

/// Which Azure provider the profile is asking for, and its parameters.
///
/// Split out so each branch can answer for itself; a profile that names an
/// Azure credential source but cannot complete it (a service principal with
/// neither a secret nor a certificate) answers `None` rather than emitting a
/// secret that cannot authenticate — that would displace whatever DuckDB could
/// otherwise have used and fail later and less clearly.
fn azure_provider_params(request: &Value) -> Option<Vec<(&'static str, String)>> {
    // A SAS token is delivered as a connection string; DuckDB's config provider
    // is the only one that accepts one.
    if let Some(connection_string) = option_string(
        request,
        &["azureConnectionString", "azureSasToken", "sasToken"],
    ) {
        return Some(vec![
            ("PROVIDER", "config".to_string()),
            ("CONNECTION_STRING", sql_string(&connection_string)),
        ]);
    }

    let tenant_id = option_string(request, &["azureTenantId", "tenantId"]);
    let client_id = option_string(request, &["azureClientId", "clientId"]);
    if let (Some(tenant_id), Some(client_id)) = (tenant_id, client_id) {
        // Secret or certificate — a service principal authenticates with one or
        // the other, never neither.
        let credential = match (
            option_string(request, &["azureClientSecret", "clientSecret"]),
            option_string(
                request,
                &["azureClientCertificatePath", "clientCertificatePath"],
            ),
        ) {
            (Some(secret), _) => ("CLIENT_SECRET", sql_string(&secret)),
            (None, Some(path)) => ("CLIENT_CERTIFICATE_PATH", sql_string(&path)),
            (None, None) => return None,
        };
        return Some(vec![
            ("PROVIDER", "service_principal".to_string()),
            ("TENANT_ID", sql_string(&tenant_id)),
            ("CLIENT_ID", sql_string(&client_id)),
            credential,
        ]);
    }

    // `cli`, `managed_identity`, `env`, … — this is what carries Azure AD
    // interactive login and managed identity.
    let chain = option_string(request, &["azureCredentialChain", "azureChain"])?;
    Some(vec![
        ("PROVIDER", "credential_chain".to_string()),
        ("CHAIN", sql_string(&chain)),
    ])
}

fn create_secret(name: &str, kind: &str, params: &[(&str, String)]) -> String {
    let body = params
        .iter()
        .map(|(key, value)| format!("    {key} {value}"))
        .collect::<Vec<_>>()
        .join(",\n");
    format!("create or replace secret {name} (\n    TYPE {kind},\n{body}\n);")
}

/// An AWS access key id is 20 uppercase alphanumerics beginning with `A`
/// (`AKIA…` long-term, `ASIA…` temporary). The connection form overloads `user`
/// for both a profile name and an access key id, so the shape is what tells
/// them apart.
fn looks_like_access_key_id(value: &str) -> bool {
    value.len() == 20
        && value.starts_with('A')
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

pub(crate) fn sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub(crate) fn option_string(request: &Value, fields: &[&str]) -> Option<String> {
    request_containers(request)
        .into_iter()
        .find_map(|container| {
            fields.iter().find_map(|field| {
                container
                    .get(*field)
                    .map(|value| match value {
                        Value::String(value) => value.clone(),
                        Value::Number(value) => value.to_string(),
                        Value::Bool(value) => value.to_string(),
                        _ => String::new(),
                    })
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
            })
        })
}

fn request_containers(request: &Value) -> Vec<&Value> {
    [
        Some(request),
        request.get("profile"),
        request.get("options"),
        request.get("auth"),
        request.get("secrets"),
        request
            .get("profile")
            .and_then(|profile| profile.get("options")),
        request
            .get("profile")
            .and_then(|profile| profile.get("auth")),
        request
            .get("profile")
            .and_then(|profile| profile.get("secrets")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn redaction_values(request: &Value) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    let mut push = |value: String| {
        if !value.is_empty() && !values.iter().any(|existing| existing == &value) {
            values.push(value);
        }
    };
    for field in [
        "password",
        "token",
        "catalogToken",
        "catalogBearerToken",
        "bearerToken",
        "accessKeyId",
        "secretAccessKey",
        "s3AccessKeyId",
        "s3SecretAccessKey",
        "sessionToken",
        "s3SessionToken",
        "oauth2ClientSecret",
        "clientSecret",
    ] {
        if let Some(value) = option_string(request, &[field]) {
            push(value);
        }
    }
    // The OAuth2 credential is `clientId:clientSecret`; error text may contain
    // either the combined form or the secret half on its own.
    for field in ["credential", "oauth2Credential", "catalogCredential"] {
        if let Some(value) = option_string(request, &[field]) {
            if let Some((_, secret)) = value.split_once(':') {
                push(secret.trim().to_string());
            }
            push(value);
        }
    }
    values
}

fn redact(values: &[String], message: &str) -> String {
    values.iter().fold(message.to_string(), |message, secret| {
        if secret.is_empty() {
            message
        } else {
            message.replace(secret, "****")
        }
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_safe_view_names_and_sql_strings() {
        assert_eq!(clean_identifier("1 a-b"), "_1_a_b");
        assert_eq!(sql_string("s3://bucket/a'b"), "'s3://bucket/a''b'");
        assert_eq!(
            parquet_pattern("s3://bucket/table"),
            "s3://bucket/table/**/*.parquet"
        );
    }
}

#[cfg(test)]
mod catalog_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    /// OAuth2 behavior for the mock catalog: the token endpoint issues
    /// `mock-token-{n}` for the expected client credentials, and every other
    /// route requires a currently valid issued token (or the optional static
    /// bearer). Tests revoke tokens to simulate expiry mid-session.
    #[derive(Default)]
    struct MockOAuth {
        client_id: String,
        client_secret: String,
        /// A user-supplied bearer accepted alongside issued tokens, so tests
        /// can prove a static token wins without tripping the auth wall.
        accept_static: Option<String>,
        issued: Mutex<Vec<String>>,
        revoked: Mutex<Vec<String>>,
        token_request_bodies: Mutex<Vec<String>>,
    }

    impl MockOAuth {
        fn new(client_id: &str, client_secret: &str) -> Arc<Self> {
            Arc::new(Self {
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                ..Self::default()
            })
        }

        fn issued_count(&self) -> usize {
            self.issued.lock().expect("issued tokens").len()
        }

        fn revoke_all_tokens(&self) {
            let issued = self.issued.lock().expect("issued tokens").clone();
            *self.revoked.lock().expect("revoked tokens") = issued;
        }

        fn accepts(&self, authorization: Option<&str>) -> bool {
            let Some(bearer) = authorization.and_then(|value| value.strip_prefix("Bearer ")) else {
                return false;
            };
            if self.accept_static.as_deref() == Some(bearer) {
                return true;
            }
            let issued = self.issued.lock().expect("issued tokens");
            let revoked = self.revoked.lock().expect("revoked tokens");
            issued.iter().any(|token| token == bearer)
                && !revoked.iter().any(|token| token == bearer)
        }

        /// Handles `POST /v1/oauth/tokens`, form-encoded per RFC 6749.
        fn token_response(&self, body: &str) -> String {
            self.token_request_bodies
                .lock()
                .expect("token request bodies")
                .push(body.to_string());
            let fields: HashMap<String, String> = body
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .map(|(key, value)| (url_decode(key), url_decode(value)))
                .collect();
            let ok = fields.get("grant_type").map(String::as_str) == Some("client_credentials")
                && fields.get("client_id") == Some(&self.client_id)
                && fields.get("client_secret") == Some(&self.client_secret);
            if !ok {
                return http_response(
                    "401 Unauthorized",
                    &json!({
                        "error": "invalid_client",
                        "error_description": "unknown client id or bad client secret"
                    })
                    .to_string(),
                );
            }
            let mut issued = self.issued.lock().expect("issued tokens");
            let token = format!("mock-token-{}", issued.len() + 1);
            issued.push(token.clone());
            http_response(
                "200 OK",
                &json!({
                    "access_token": token,
                    "token_type": "bearer",
                    "expires_in": 3600
                })
                .to_string(),
            )
        }
    }

    fn url_decode(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'+' => out.push(b' '),
                b'%' if index + 2 < bytes.len() => {
                    let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                    match u8::from_str_radix(hex, 16) {
                        Ok(byte) => {
                            out.push(byte);
                            index += 2;
                        }
                        Err(_) => out.push(b'%'),
                    }
                }
                byte => out.push(byte),
            }
            index += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn http_response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// Reads one HTTP request (headers plus a Content-Length body) from the
    /// stream and returns `(method, path, authorization, body)`.
    fn read_request(stream: &mut std::net::TcpStream) -> (String, String, Option<String>, String) {
        let mut data = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            match stream.read(&mut chunk) {
                Ok(0) => break None,
                Ok(read) => {
                    data.extend_from_slice(&chunk[..read]);
                    if let Some(position) = data.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break Some(position + 4);
                    }
                }
                Err(_) => break None,
            }
        };
        let Some(header_end) = header_end else {
            return (String::new(), String::new(), None, String::new());
        };
        let head = String::from_utf8_lossy(&data[..header_end]).into_owned();
        let mut request_line = head.lines().next().unwrap_or("").split_whitespace();
        let method = request_line.next().unwrap_or("").to_string();
        let path = request_line.next().unwrap_or("").to_string();
        let mut authorization = None;
        let mut content_length = 0usize;
        for line in head.lines().skip(1) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            match name.to_ascii_lowercase().as_str() {
                "authorization" => authorization = Some(value.trim().to_string()),
                "content-length" => content_length = value.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
        while data.len() < header_end + content_length {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => data.extend_from_slice(&chunk[..read]),
                Err(_) => break,
            }
        }
        let body = String::from_utf8_lossy(&data[header_end..]).into_owned();
        (method, path, authorization, body)
    }

    /// Minimal single-threaded HTTP server that answers GET requests from a
    /// fixed route table. Enough to stand in for an Iceberg REST catalog.
    /// With `oauth` set it also serves the spec's `POST /v1/oauth/tokens`
    /// endpoint and turns away every request that lacks a valid token.
    fn spawn_catalog_with_oauth(
        routes: Vec<(&str, Value)>,
        auth_log: Arc<Mutex<Vec<String>>>,
        oauth: Option<Arc<MockOAuth>>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock catalog");
        let base = format!("http://{}", listener.local_addr().expect("local addr"));
        let routes: Vec<(String, String)> = routes
            .into_iter()
            .map(|(path, body)| (path.to_string(), body.to_string()))
            .collect();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let (method, path, authorization, body) = read_request(&mut stream);
                if let Some(value) = &authorization {
                    if let Ok(mut log) = auth_log.lock() {
                        log.push(value.clone());
                    }
                }
                let response = match &oauth {
                    Some(oauth) if method == "POST" && path == "/v1/oauth/tokens" => {
                        oauth.token_response(&body)
                    }
                    Some(oauth) if !oauth.accepts(authorization.as_deref()) => http_response(
                        "401 Unauthorized",
                        &json!({"error": "not authorized"}).to_string(),
                    ),
                    _ => match routes.iter().find(|(route, _)| *route == path) {
                        Some((_, body)) => http_response("200 OK", body),
                        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\
                                 Connection: close\r\n\r\n"
                            .to_string(),
                    },
                };
                let _ = stream.write_all(response.as_bytes());
            }
        });
        base
    }

    fn spawn_catalog(routes: Vec<(&str, Value)>, auth_log: Arc<Mutex<Vec<String>>>) -> String {
        spawn_catalog_with_oauth(routes, auth_log, None)
    }

    fn call(request: Value) -> Value {
        let payload = request.to_string();
        let buffer = IrodoriConnectorBuffer {
            ptr: payload.as_ptr(),
            len: payload.len(),
        };
        let response = call_json(buffer);
        let bytes = unsafe { std::slice::from_raw_parts(response.ptr, response.len) };
        let value: Value = serde_json::from_slice(bytes).expect("valid response JSON");
        abi::free_owned_buffer(response);
        value
    }

    fn catalog_routes() -> Vec<(&'static str, Value)> {
        vec![
            (
                "/v1/config",
                json!({"defaults": {}, "overrides": {"prefix": "demo"}}),
            ),
            (
                "/v1/demo/namespaces",
                json!({"namespaces": [["analytics"]]}),
            ),
            (
                "/v1/demo/namespaces?parent=analytics",
                json!({"namespaces": []}),
            ),
            (
                "/v1/demo/namespaces/analytics/tables",
                json!({"identifiers": [{"namespace": ["analytics"], "name": "events"}]}),
            ),
            (
                "/v1/demo/namespaces/analytics/tables/events",
                json!({
                    "metadata-location":
                        "/nonexistent/irodori-catalog-test/metadata/00000.metadata.json",
                    "metadata": {
                        "format-version": 2,
                        "current-schema-id": 0,
                        "schemas": [{
                            "schema-id": 0,
                            "fields": [
                                {"id": 1, "name": "id", "required": true, "type": "long"},
                                {"id": 2, "name": "name", "required": false, "type": "string"}
                            ]
                        }]
                    }
                }),
            ),
        ]
    }

    #[test]
    fn catalog_mode_browses_namespaces_and_tables() {
        let auth_log = Arc::new(Mutex::new(Vec::new()));
        let base = spawn_catalog(catalog_routes(), Arc::clone(&auth_log));

        let connect = call(json!({
            "method": "connect",
            "connectionId": "catalog-browse-test",
            "options": {"catalogUri": base, "catalogToken": "sekrit"}
        }));
        assert_eq!(connect["ok"], true, "connect failed: {connect}");

        let metadata = call(json!({
            "method": "metadata",
            "connectionId": "catalog-browse-test"
        }));
        assert_eq!(metadata["ok"], true, "metadata failed: {metadata}");
        let schemas = metadata["metadata"]["schemas"]
            .as_array()
            .expect("schemas array");
        assert_eq!(schemas.len(), 1);
        assert_eq!(schemas[0]["name"], "analytics");
        let objects = schemas[0]["objects"].as_array().expect("objects array");
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0]["name"], "events");
        assert_eq!(objects[0]["kind"], "table");
        let columns = objects[0]["columns"].as_array().expect("columns array");
        assert_eq!(columns[0]["name"], "id");
        assert_eq!(columns[0]["dataType"], "long");
        assert_eq!(columns[0]["nullable"], false);
        assert_eq!(columns[1]["name"], "name");

        // The fixture metadata location does not exist, so the view is not
        // queryable; that must degrade to a warning, not a failure.
        let warnings = metadata["warnings"].as_array().expect("warnings array");
        assert!(
            warnings
                .iter()
                .any(|warning| warning.as_str().unwrap_or("").contains("analytics.events")),
            "expected a warning about analytics.events, got: {warnings:?}"
        );

        let seen_auth = auth_log.lock().expect("auth log");
        assert!(
            seen_auth.iter().any(|value| value == "Bearer sekrit"),
            "expected bearer token on catalog requests, saw: {seen_auth:?}"
        );
        drop(seen_auth);

        call(json!({"method": "close", "connectionId": "catalog-browse-test"}));
    }

    #[test]
    fn catalog_connect_fails_fast_when_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("local addr"));
        drop(listener);

        let connect = call(json!({
            "method": "connect",
            "connectionId": "catalog-unreachable-test",
            "options": {"catalogUri": base}
        }));
        assert_eq!(connect["ok"], false);
        let message = connect["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("unreachable"),
            "expected an unreachable-catalog message, got: {message}"
        );
    }

    #[test]
    fn oauth2_client_credentials_authenticate_catalog_requests() {
        let auth_log = Arc::new(Mutex::new(Vec::new()));
        let oauth = MockOAuth::new("client-id", "client-secret");
        let base = spawn_catalog_with_oauth(
            catalog_routes(),
            Arc::clone(&auth_log),
            Some(Arc::clone(&oauth)),
        );

        let connect = call(json!({
            "method": "connect",
            "connectionId": "oauth-happy-test",
            "options": {"catalogUri": base, "credential": "client-id:client-secret"}
        }));
        assert_eq!(connect["ok"], true, "connect failed: {connect}");

        let metadata = call(json!({
            "method": "metadata",
            "connectionId": "oauth-happy-test"
        }));
        assert_eq!(metadata["ok"], true, "metadata failed: {metadata}");
        assert_eq!(metadata["metadata"]["schemas"][0]["name"], "analytics");
        assert_eq!(
            metadata["metadata"]["schemas"][0]["objects"][0]["name"],
            "events"
        );

        assert_eq!(oauth.issued_count(), 1, "expected a single token request");
        let bodies = oauth.token_request_bodies.lock().expect("token bodies");
        assert!(
            bodies[0].contains("grant_type=client_credentials")
                && bodies[0].contains("scope=catalog"),
            "unexpected token request body: {}",
            bodies[0]
        );
        drop(bodies);
        let seen_auth = auth_log.lock().expect("auth log");
        assert!(
            seen_auth.iter().any(|value| value == "Bearer mock-token-1"),
            "expected the issued token on catalog requests, saw: {seen_auth:?}"
        );
        drop(seen_auth);

        call(json!({"method": "close", "connectionId": "oauth-happy-test"}));
    }

    #[test]
    fn oauth2_rejects_bad_credentials_without_echoing_them() {
        let auth_log = Arc::new(Mutex::new(Vec::new()));
        let oauth = MockOAuth::new("client-id", "client-secret");
        let base = spawn_catalog_with_oauth(catalog_routes(), auth_log, Some(oauth));

        let connect = call(json!({
            "method": "connect",
            "connectionId": "oauth-bad-credential-test",
            "options": {"catalogUri": base, "credential": "client-id:wrong-secret"}
        }));
        assert_eq!(connect["ok"], false, "connect should fail: {connect}");
        let message = connect["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("OAuth2 token request") && message.contains("invalid_client"),
            "expected a clear OAuth2 rejection, got: {message}"
        );
        assert!(
            !message.contains("wrong-secret"),
            "client secret leaked into the error: {message}"
        );
    }

    #[test]
    fn oauth2_missing_client_secret_fails_with_guidance() {
        let connect = call(json!({
            "method": "connect",
            "connectionId": "oauth-no-secret-test",
            "options": {"catalogUri": "http://127.0.0.1:9", "oauth2ClientId": "client-id"}
        }));
        assert_eq!(connect["ok"], false);
        let message = connect["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("no client secret") && message.contains("password"),
            "expected guidance toward the password field, got: {message}"
        );
    }

    #[test]
    fn oauth2_refreshes_the_token_once_when_it_expires_mid_session() {
        let auth_log = Arc::new(Mutex::new(Vec::new()));
        let oauth = MockOAuth::new("client-id", "client-secret");
        let base = spawn_catalog_with_oauth(
            catalog_routes(),
            Arc::clone(&auth_log),
            Some(Arc::clone(&oauth)),
        );

        // The client id arrives via oauth2ClientId and the secret through the
        // profile's session-only password field — the desktop app's secret
        // channel — instead of the combined credential option.
        let connect = call(json!({
            "method": "connect",
            "connectionId": "oauth-expiry-test",
            "password": "client-secret",
            "options": {"catalogUri": base, "oauth2ClientId": "client-id"}
        }));
        assert_eq!(connect["ok"], true, "connect failed: {connect}");
        assert_eq!(oauth.issued_count(), 1);

        // Simulate token expiry between connect and the metadata sync.
        oauth.revoke_all_tokens();

        let metadata = call(json!({
            "method": "metadata",
            "connectionId": "oauth-expiry-test"
        }));
        assert_eq!(
            metadata["ok"], true,
            "metadata should succeed after a token refresh: {metadata}"
        );
        assert_eq!(metadata["metadata"]["schemas"][0]["name"], "analytics");
        assert_eq!(
            oauth.issued_count(),
            2,
            "expected exactly one refresh after expiry"
        );
        let seen_auth = auth_log.lock().expect("auth log");
        assert!(
            seen_auth.iter().any(|value| value == "Bearer mock-token-2"),
            "expected the refreshed token on catalog requests, saw: {seen_auth:?}"
        );
        drop(seen_auth);

        call(json!({"method": "close", "connectionId": "oauth-expiry-test"}));
    }

    #[test]
    fn static_bearer_token_takes_precedence_over_oauth2() {
        let auth_log = Arc::new(Mutex::new(Vec::new()));
        let oauth = Arc::new(MockOAuth {
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string(),
            accept_static: Some("static-token".to_string()),
            ..MockOAuth::default()
        });
        let base = spawn_catalog_with_oauth(
            catalog_routes(),
            Arc::clone(&auth_log),
            Some(Arc::clone(&oauth)),
        );

        let connect = call(json!({
            "method": "connect",
            "connectionId": "oauth-precedence-test",
            "options": {
                "catalogUri": base,
                "catalogToken": "static-token",
                "credential": "client-id:client-secret"
            }
        }));
        assert_eq!(connect["ok"], true, "connect failed: {connect}");
        assert_eq!(
            oauth.issued_count(),
            0,
            "static token must skip the OAuth2 token endpoint"
        );
        let seen_auth = auth_log.lock().expect("auth log");
        assert!(
            seen_auth.iter().any(|value| value == "Bearer static-token"),
            "expected the static token on the wire, saw: {seen_auth:?}"
        );
        drop(seen_auth);

        call(json!({"method": "close", "connectionId": "oauth-precedence-test"}));
    }

    #[test]
    fn catalog_rejects_non_rest_catalog_types() {
        let connect = call(json!({
            "method": "connect",
            "connectionId": "catalog-type-test",
            "options": {"catalogUri": "https://example.com", "catalogType": "glue"}
        }));
        assert_eq!(connect["ok"], false);
        let message = connect["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("only 'rest' catalogs"),
            "expected unsupported-catalog-type message, got: {message}"
        );
    }

    fn request(options: Value) -> Value {
        json!({ "profile": { "options": options } })
    }

    #[test]
    fn a_profile_with_no_credential_source_emits_no_secret() {
        // DuckDB's own defaults should stand; emitting an empty secret would
        // override them with nothing.
        assert!(secret_statements(&request(json!({}))).is_empty());
        assert!(secret_statements(&request(json!({ "region": "ap-northeast-1" }))).is_empty());
    }

    #[test]
    fn a_static_key_pair_becomes_a_config_secret() {
        let statements = secret_statements(&request(json!({
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "sessionToken": "FQoGZXIvYXdzEBYa",
            "region": "ap-northeast-1"
        })));
        assert_eq!(statements.len(), 1);
        let sql = &statements[0];
        assert!(sql.contains("TYPE s3"), "{sql}");
        assert!(sql.contains("PROVIDER config"), "{sql}");
        assert!(sql.contains("KEY_ID 'AKIAIOSFODNN7EXAMPLE'"), "{sql}");
        assert!(sql.contains("SESSION_TOKEN 'FQoGZXIvYXdzEBYa'"), "{sql}");
        assert!(sql.contains("REGION 'ap-northeast-1'"), "{sql}");
    }

    #[test]
    fn a_profile_name_becomes_a_credential_chain_secret() {
        // This is the path that carries SSO, web identity, ECS/IMDS, and a
        // profile's own role_arn — none of which a `SET s3_*` can express.
        let statements = secret_statements(&request(json!({ "awsProfile": "analytics" })));
        assert_eq!(statements.len(), 1);
        let sql = &statements[0];
        assert!(sql.contains("PROVIDER credential_chain"), "{sql}");
        assert!(sql.contains("PROFILE 'analytics'"), "{sql}");
    }

    #[test]
    fn an_explicit_chain_is_passed_through() {
        let statements = secret_statements(&request(json!({
            "awsCredentialChain": "sso;env;instance"
        })));
        assert!(
            statements[0].contains("CHAIN 'sso;env;instance'"),
            "{:?}",
            statements
        );
    }

    #[test]
    fn a_static_key_pair_wins_over_the_chain() {
        // Explicit credentials are an instruction, not a hint.
        let statements = secret_statements(&request(json!({
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "secretAccessKey": "secret",
            "awsProfile": "analytics"
        })));
        assert!(
            statements[0].contains("PROVIDER config"),
            "{:?}",
            statements
        );
        assert!(
            !statements[0].contains("credential_chain"),
            "{:?}",
            statements
        );
    }

    #[test]
    fn a_user_that_is_not_an_access_key_id_is_not_a_credential() {
        // The form overloads `user` for both a profile name and an access key
        // id; only the access-key shape may become KEY_ID.
        let statements = secret_statements(&request(json!({
            "user": "analytics", "password": "secret"
        })));
        assert!(statements.is_empty(), "{statements:?}");
        assert!(looks_like_access_key_id("ASIAIOSFODNN7EXAMPLE"));
        assert!(!looks_like_access_key_id("analytics"));
    }

    #[test]
    fn an_azure_service_principal_becomes_a_service_principal_secret() {
        let statements = secret_statements(&request(json!({
            "azureTenantId": "tenant",
            "azureClientId": "client",
            "azureClientSecret": "shh",
            "azureAccountName": "lakehouse"
        })));
        let sql = statements.last().expect("an azure secret");
        assert!(sql.contains("TYPE azure"), "{sql}");
        assert!(sql.contains("PROVIDER service_principal"), "{sql}");
        assert!(sql.contains("CLIENT_SECRET 'shh'"), "{sql}");
        assert!(sql.contains("ACCOUNT_NAME 'lakehouse'"), "{sql}");
    }

    #[test]
    fn an_azure_service_principal_can_authenticate_with_a_certificate() {
        let statements = secret_statements(&request(json!({
            "azureTenantId": "tenant",
            "azureClientId": "client",
            "azureClientCertificatePath": "/etc/ssl/sp.pem"
        })));
        let sql = statements.last().expect("an azure secret");
        assert!(
            sql.contains("CLIENT_CERTIFICATE_PATH '/etc/ssl/sp.pem'"),
            "{sql}"
        );
        assert!(!sql.contains("CLIENT_SECRET"), "{sql}");
    }

    #[test]
    fn an_azure_service_principal_without_a_credential_emits_nothing() {
        // Emitting a secret that cannot authenticate would replace whatever
        // DuckDB could otherwise have used, and fail later and less clearly.
        let statements = secret_statements(&request(json!({
            "azureTenantId": "tenant", "azureClientId": "client"
        })));
        assert!(statements.is_empty(), "{statements:?}");
    }

    #[test]
    fn an_azure_sas_token_becomes_a_connection_string_secret() {
        let statements = secret_statements(&request(json!({
            "azureSasToken": "BlobEndpoint=https://x.blob.core.windows.net/;SharedAccessSignature=sv=2022"
        })));
        let sql = statements.last().expect("an azure secret");
        assert!(sql.contains("PROVIDER config"), "{sql}");
        assert!(sql.contains("SharedAccessSignature=sv=2022"), "{sql}");
    }

    #[test]
    fn an_azure_chain_carries_managed_identity_and_cli_login() {
        let statements = secret_statements(&request(json!({
            "azureCredentialChain": "managed_identity;cli"
        })));
        let sql = statements.last().expect("an azure secret");
        assert!(sql.contains("PROVIDER credential_chain"), "{sql}");
        assert!(sql.contains("CHAIN 'managed_identity;cli'"), "{sql}");
    }

    #[test]
    fn s3_and_azure_credentials_coexist() {
        // A table can live in one store and its catalog in another.
        let statements = secret_statements(&request(json!({
            "awsProfile": "analytics",
            "azureCredentialChain": "cli"
        })));
        assert_eq!(statements.len(), 2, "{statements:?}");
        assert!(statements[0].contains("TYPE s3"));
        assert!(statements[1].contains("TYPE azure"));
    }

    #[test]
    fn secret_values_are_quoted_against_injection() {
        let statements = secret_statements(&request(json!({
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "secretAccessKey": "it's a secret"
        })));
        assert!(
            statements[0].contains("SECRET 'it''s a secret'"),
            "{:?}",
            statements
        );
    }
}
