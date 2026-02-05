use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

use super::{Root, Transport};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfigFile {
    pub(super) version: u32,
    #[serde(default)]
    pub(super) client: Option<ClientConfigFile>,
    pub(super) servers: BTreeMap<String, ServerConfigFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClientConfigFile {
    #[serde(default)]
    pub(super) protocol_version: Option<String>,
    #[serde(default)]
    pub(super) capabilities: Option<Value>,
    #[serde(default)]
    pub(super) roots: Option<Vec<Root>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerConfigFile {
    pub(super) transport: Transport,
    #[serde(default)]
    pub(super) argv: Option<Vec<String>>,
    #[serde(default)]
    pub(super) inherit_env: Option<bool>,
    #[serde(default)]
    pub(super) unix_path: Option<PathBuf>,
    #[serde(default)]
    pub(super) url: Option<String>,
    #[serde(default)]
    pub(super) sse_url: Option<String>,
    #[serde(default)]
    pub(super) http_url: Option<String>,
    #[serde(default)]
    pub(super) bearer_token_env_var: Option<String>,
    #[serde(default, alias = "headers")]
    pub(super) http_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) env_http_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) env: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) stdout_log: Option<StdoutLogConfigFile>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum ExternalCommandConfigFile {
    String(String),
    Array(Vec<String>),
}

#[derive(Debug, Deserialize)]
pub(super) struct ExternalServerConfigFile {
    #[serde(default)]
    pub(super) transport: Option<Transport>,
    #[serde(rename = "type", default)]
    pub(super) server_type: Option<String>,
    #[serde(default)]
    pub(super) command: Option<ExternalCommandConfigFile>,
    #[serde(default)]
    pub(super) args: Option<Vec<String>>,
    #[serde(default)]
    pub(super) argv: Option<Vec<String>>,
    #[serde(default)]
    pub(super) inherit_env: Option<bool>,
    #[serde(default)]
    pub(super) unix_path: Option<PathBuf>,
    #[serde(default)]
    pub(super) url: Option<String>,
    #[serde(default)]
    pub(super) sse_url: Option<String>,
    #[serde(default)]
    pub(super) http_url: Option<String>,
    #[serde(default)]
    pub(super) bearer_token_env_var: Option<String>,
    #[serde(default, alias = "headers")]
    pub(super) http_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) env_http_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) env: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) environment: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) stdout_log: Option<StdoutLogConfigFile>,
    #[serde(default)]
    pub(super) enabled: Option<bool>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(super) description: Option<String>,
    #[serde(flatten)]
    #[allow(dead_code)]
    pub(super) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StdoutLogConfigFile {
    pub(super) path: PathBuf,
    #[serde(default)]
    pub(super) max_bytes_per_part: Option<u64>,
    #[serde(default)]
    pub(super) max_parts: Option<u32>,
}
