use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MCP_CONFIG_VERSION: u32 = 1;
const DEFAULT_STDOUT_LOG_MAX_BYTES_PER_PART: u64 = 1024 * 1024;
const DEFAULT_STDOUT_LOG_MAX_PARTS: u32 = 32;
const DEFAULT_CONFIG_CANDIDATES: [&str; 2] = [".mcp.json", "mcp.json"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    version: u32,
    #[serde(default)]
    client: Option<ClientConfigFile>,
    servers: BTreeMap<String, ServerConfigFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfigFile {
    #[serde(default)]
    protocol_version: Option<String>,
    #[serde(default)]
    capabilities: Option<Value>,
    #[serde(default)]
    roots: Option<Vec<Root>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerConfigFile {
    transport: Transport,
    #[serde(default)]
    argv: Option<Vec<String>>,
    #[serde(default)]
    unix_path: Option<PathBuf>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    bearer_token_env_var: Option<String>,
    #[serde(default)]
    http_headers: BTreeMap<String, String>,
    #[serde(default)]
    env_http_headers: BTreeMap<String, String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    stdout_log: Option<StdoutLogConfigFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StdoutLogConfigFile {
    path: PathBuf,
    #[serde(default)]
    max_bytes_per_part: Option<u64>,
    #[serde(default)]
    max_parts: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Stdio,
    Unix,
    StreamableHttp,
}

#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    pub protocol_version: Option<String>,
    pub capabilities: Option<Value>,
    pub roots: Option<Vec<Root>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub uri: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StdoutLogConfig {
    pub path: PathBuf,
    pub max_bytes_per_part: u64,
    pub max_parts: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub path: Option<PathBuf>,
    pub client: ClientConfig,
    pub servers: BTreeMap<String, ServerConfig>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub transport: Transport,
    pub argv: Vec<String>,
    pub unix_path: Option<PathBuf>,
    pub url: Option<String>,
    pub bearer_token_env_var: Option<String>,
    pub http_headers: BTreeMap<String, String>,
    pub env_http_headers: BTreeMap<String, String>,
    pub env: BTreeMap<String, String>,
    pub stdout_log: Option<StdoutLogConfig>,
}

fn is_valid_server_name(name: &str) -> bool {
    let name = name.trim();
    if name.is_empty() {
        return false;
    }
    name.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

impl Config {
    pub async fn load(thread_root: &Path, override_path: Option<PathBuf>) -> anyhow::Result<Self> {
        let (path, contents) = match override_path {
            Some(path) => {
                let path = if path.is_absolute() {
                    path
                } else {
                    thread_root.join(path)
                };
                let contents = tokio::fs::read_to_string(&path)
                    .await
                    .with_context(|| format!("read {}", path.display()))?;
                (Some(path), contents)
            }
            None => {
                let mut found = None::<(PathBuf, String)>;
                for candidate in DEFAULT_CONFIG_CANDIDATES {
                    let candidate_path = thread_root.join(candidate);
                    match tokio::fs::read_to_string(&candidate_path).await {
                        Ok(contents) => {
                            found = Some((candidate_path, contents));
                            break;
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(err) => {
                            return Err(err)
                                .with_context(|| format!("read {}", candidate_path.display()));
                        }
                    }
                }

                match found {
                    Some((path, contents)) => (Some(path), contents),
                    None => {
                        return Ok(Self {
                            path: None,
                            client: ClientConfig::default(),
                            servers: BTreeMap::new(),
                        });
                    }
                }
            }
        };

        let cfg: ConfigFile = serde_json::from_str(&contents).with_context(|| match &path {
            Some(path) => format!("parse {}", path.display()),
            None => "parse mcp config".to_string(),
        })?;
        if cfg.version != MCP_CONFIG_VERSION {
            anyhow::bail!(
                "unsupported mcp.json version {} (expected {})",
                cfg.version,
                MCP_CONFIG_VERSION
            );
        }

        let client = match cfg.client {
            Some(client) => {
                if let Some(protocol_version) = &client.protocol_version {
                    if protocol_version.trim().is_empty() {
                        anyhow::bail!("mcp.json client.protocol_version must not be empty");
                    }
                }
                if let Some(capabilities) = &client.capabilities {
                    if !capabilities.is_object() {
                        anyhow::bail!("mcp.json client.capabilities must be a JSON object");
                    }
                }
                if let Some(roots) = &client.roots {
                    for (idx, root) in roots.iter().enumerate() {
                        if root.uri.trim().is_empty() {
                            anyhow::bail!("mcp.json client.roots[{idx}].uri must not be empty");
                        }
                        if let Some(name) = &root.name {
                            if name.trim().is_empty() {
                                anyhow::bail!(
                                    "mcp.json client.roots[{idx}].name must not be empty"
                                );
                            }
                        }
                    }
                }
                ClientConfig {
                    protocol_version: client.protocol_version,
                    capabilities: client.capabilities,
                    roots: client.roots,
                }
            }
            None => ClientConfig::default(),
        };

        let mut servers = BTreeMap::<String, ServerConfig>::new();
        for (name, server) in cfg.servers {
            if !is_valid_server_name(&name) {
                anyhow::bail!("invalid mcp server name: {name}");
            }

            let stdout_log = match server.stdout_log {
                Some(log) => {
                    if log.path.as_os_str().is_empty() {
                        anyhow::bail!("mcp server {name}: stdout_log.path must not be empty");
                    }
                    let path = if log.path.is_absolute() {
                        log.path
                    } else {
                        thread_root.join(log.path)
                    };
                    let max_bytes_per_part = log
                        .max_bytes_per_part
                        .unwrap_or(DEFAULT_STDOUT_LOG_MAX_BYTES_PER_PART)
                        .max(1);
                    let max_parts = log.max_parts.unwrap_or(DEFAULT_STDOUT_LOG_MAX_PARTS);
                    let max_parts = if max_parts == 0 {
                        None
                    } else {
                        Some(max_parts.max(1))
                    };
                    Some(StdoutLogConfig {
                        path,
                        max_bytes_per_part,
                        max_parts,
                    })
                }
                None => None,
            };

            let (argv, unix_path) = match server.transport {
                Transport::Stdio => {
                    if server.unix_path.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: unix_path is only valid for transport=unix"
                        );
                    }
                    if server.url.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: url is only valid for transport=streamable_http"
                        );
                    }
                    if server.bearer_token_env_var.is_some()
                        || !server.http_headers.is_empty()
                        || !server.env_http_headers.is_empty()
                    {
                        anyhow::bail!(
                            "mcp server {name}: http auth/headers are only valid for transport=streamable_http"
                        );
                    }
                    let argv = server.argv.ok_or_else(|| {
                        anyhow::anyhow!("mcp server {name}: argv must not be empty")
                    })?;
                    if argv.is_empty() {
                        anyhow::bail!("mcp server {name}: argv must not be empty");
                    }
                    for (idx, arg) in argv.iter().enumerate() {
                        if arg.trim().is_empty() {
                            anyhow::bail!("mcp server {name}: argv[{idx}] must not be empty");
                        }
                    }
                    (argv, None)
                }
                Transport::Unix => {
                    if server.argv.is_some() {
                        anyhow::bail!("mcp server {name}: argv is not allowed for transport=unix");
                    }
                    if server.url.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: url is only valid for transport=streamable_http"
                        );
                    }
                    if server.bearer_token_env_var.is_some()
                        || !server.http_headers.is_empty()
                        || !server.env_http_headers.is_empty()
                    {
                        anyhow::bail!(
                            "mcp server {name}: http auth/headers are only valid for transport=streamable_http"
                        );
                    }
                    if !server.env.is_empty() {
                        anyhow::bail!("mcp server {name}: env is not supported for transport=unix");
                    }
                    if stdout_log.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: stdout_log is not supported for transport=unix"
                        );
                    }
                    let unix_path = server.unix_path.ok_or_else(|| {
                        anyhow::anyhow!(
                            "mcp server {name}: unix_path is required for transport=unix"
                        )
                    })?;
                    if unix_path.as_os_str().is_empty() {
                        anyhow::bail!("mcp server {name}: unix_path must not be empty");
                    }
                    let unix_path = if unix_path.is_absolute() {
                        unix_path
                    } else {
                        thread_root.join(unix_path)
                    };
                    (Vec::new(), Some(unix_path))
                }
                Transport::StreamableHttp => {
                    if server.argv.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: argv is not allowed for transport=streamable_http"
                        );
                    }
                    if server.unix_path.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: unix_path is not allowed for transport=streamable_http"
                        );
                    }
                    if !server.env.is_empty() {
                        anyhow::bail!(
                            "mcp server {name}: env is not supported for transport=streamable_http"
                        );
                    }
                    if stdout_log.is_some() {
                        anyhow::bail!(
                            "mcp server {name}: stdout_log is not supported for transport=streamable_http"
                        );
                    }

                    let Some(url) = server.url else {
                        anyhow::bail!(
                            "mcp server {name}: url is required for transport=streamable_http"
                        );
                    };
                    if url.trim().is_empty() {
                        anyhow::bail!("mcp server {name}: url must not be empty");
                    }

                    if let Some(env_var) = &server.bearer_token_env_var {
                        if env_var.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server {name}: bearer_token_env_var must not be empty"
                            );
                        }
                    }

                    for (header, value) in server.http_headers.iter() {
                        if header.trim().is_empty() {
                            anyhow::bail!("mcp server {name}: http_headers key must not be empty");
                        }
                        if value.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server {name}: http_headers[{header}] must not be empty"
                            );
                        }
                    }
                    for (header, env_var) in server.env_http_headers.iter() {
                        if header.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server {name}: env_http_headers key must not be empty"
                            );
                        }
                        if env_var.trim().is_empty() {
                            anyhow::bail!(
                                "mcp server {name}: env_http_headers[{header}] must not be empty"
                            );
                        }
                    }

                    servers.insert(
                        name,
                        ServerConfig {
                            transport: Transport::StreamableHttp,
                            argv: Vec::new(),
                            unix_path: None,
                            url: Some(url),
                            bearer_token_env_var: server.bearer_token_env_var,
                            http_headers: server.http_headers,
                            env_http_headers: server.env_http_headers,
                            env: BTreeMap::new(),
                            stdout_log: None,
                        },
                    );
                    continue;
                }
            };

            servers.insert(
                name,
                ServerConfig {
                    transport: server.transport,
                    argv,
                    unix_path,
                    url: None,
                    bearer_token_env_var: None,
                    http_headers: BTreeMap::new(),
                    env_http_headers: BTreeMap::new(),
                    env: server.env,
                    stdout_log,
                },
            );
        }

        Ok(Self {
            path,
            client,
            servers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn load_defaults_to_empty_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::load(dir.path(), None).await.unwrap();
        assert!(cfg.path.is_none());
        assert!(cfg.client.protocol_version.is_none());
        assert!(cfg.client.capabilities.is_none());
        assert!(cfg.client.roots.is_none());
        assert!(cfg.servers.is_empty());
    }

    #[tokio::test]
    async fn load_discovers_dot_mcp_json_before_mcp_json() {
        let dir = tempfile::tempdir().unwrap();

        tokio::fs::write(
            dir.path().join(".mcp.json"),
            r#"{ "version": 1, "servers": { "a": { "transport": "stdio", "argv": ["mcp-a"] } } }"#,
        )
        .await
        .unwrap();

        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "b": { "transport": "stdio", "argv": ["mcp-b"] } } }"#,
        )
        .await
        .unwrap();

        let cfg = Config::load(dir.path(), None).await.unwrap();
        assert_eq!(cfg.path.as_ref().unwrap(), &dir.path().join(".mcp.json"));
        assert!(cfg.servers.contains_key("a"));
        assert!(!cfg.servers.contains_key("b"));
    }

    #[tokio::test]
    async fn load_discovers_mcp_json_when_dot_mcp_json_missing() {
        let dir = tempfile::tempdir().unwrap();

        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "a": { "transport": "stdio", "argv": ["mcp-a"] } } }"#,
        )
        .await
        .unwrap();

        let cfg = Config::load(dir.path(), None).await.unwrap();
        assert_eq!(cfg.path.as_ref().unwrap(), &dir.path().join("mcp.json"));
        assert!(cfg.servers.contains_key("a"));
    }

    #[tokio::test]
    async fn load_parses_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "rg": { "transport": "stdio", "argv": ["mcp-rg", "--stdio"], "env": { "NO_COLOR": "1" } } } }"#,
        )
        .await
        .unwrap();

        let cfg = Config::load(dir.path(), None).await.unwrap();
        assert!(cfg.path.is_some());
        assert_eq!(cfg.servers.len(), 1);
        let server = cfg.servers.get("rg").unwrap();
        assert_eq!(
            server.argv,
            vec!["mcp-rg".to_string(), "--stdio".to_string()]
        );
        assert!(server.env.contains_key("NO_COLOR"));
        assert!(server.stdout_log.is_none());
        assert!(server.unix_path.is_none());
    }

    #[tokio::test]
    async fn load_parses_client_section() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "client": { "protocol_version": "2025-06-18", "capabilities": { "roots": { "list_changed": true } } }, "servers": {} }"#,
        )
        .await
        .unwrap();

        let cfg = Config::load(dir.path(), None).await.unwrap();
        assert_eq!(cfg.client.protocol_version.as_deref(), Some("2025-06-18"));
        assert!(
            cfg.client
                .capabilities
                .as_ref()
                .expect("capabilities")
                .is_object()
        );
        assert!(cfg.client.roots.is_none());
    }

    #[tokio::test]
    async fn load_parses_client_roots() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "client": { "roots": [ { "uri": "file:///tmp", "name": "tmp" } ] }, "servers": {} }"#,
        )
        .await
        .unwrap();

        let cfg = Config::load(dir.path(), None).await.unwrap();
        let roots = cfg.client.roots.as_ref().expect("roots");
        assert_eq!(
            roots,
            &vec![Root {
                uri: "file:///tmp".to_string(),
                name: Some("tmp".to_string()),
            }]
        );
    }

    #[tokio::test]
    async fn load_denies_empty_root_uri() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "client": { "roots": [ { "uri": "   " } ] }, "servers": {} }"#,
        )
        .await
        .unwrap();

        let err = Config::load(dir.path(), None).await.unwrap_err();
        assert!(err.to_string().contains("client.roots"));
    }

    #[tokio::test]
    async fn load_denies_invalid_client_capabilities() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "client": { "capabilities": 123 }, "servers": {} }"#,
        )
        .await
        .unwrap();

        let err = Config::load(dir.path(), None).await.unwrap_err();
        assert!(err.to_string().contains("client.capabilities"));
    }

    #[tokio::test]
    async fn load_parses_stdout_log_and_resolves_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "rg": { "transport": "stdio", "argv": ["mcp-rg"], "stdout_log": { "path": "./logs/rg.stdout.log" } } } }"#,
        )
        .await
        .unwrap();

        let cfg = Config::load(dir.path(), None).await.unwrap();
        let server = cfg.servers.get("rg").unwrap();
        let stdout_log = server.stdout_log.as_ref().expect("stdout_log");
        assert_eq!(stdout_log.path, dir.path().join("./logs/rg.stdout.log"));
        assert_eq!(
            stdout_log.max_bytes_per_part,
            DEFAULT_STDOUT_LOG_MAX_BYTES_PER_PART
        );
        assert_eq!(stdout_log.max_parts, Some(DEFAULT_STDOUT_LOG_MAX_PARTS));
    }

    #[tokio::test]
    async fn load_stdout_log_max_parts_zero_means_unlimited() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "rg": { "transport": "stdio", "argv": ["mcp-rg"], "stdout_log": { "path": "./logs/rg.stdout.log", "max_parts": 0 } } } }"#,
        )
        .await
        .unwrap();

        let cfg = Config::load(dir.path(), None).await.unwrap();
        let server = cfg.servers.get("rg").unwrap();
        let stdout_log = server.stdout_log.as_ref().expect("stdout_log");
        assert_eq!(stdout_log.max_parts, None);
    }

    #[tokio::test]
    async fn load_parses_unix_transport_and_resolves_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "sock": { "transport": "unix", "unix_path": "./sock/mcp.sock" } } }"#,
        )
        .await
        .unwrap();

        let cfg = Config::load(dir.path(), None).await.unwrap();
        let server = cfg.servers.get("sock").unwrap();
        assert_eq!(server.transport, Transport::Unix);
        assert!(server.argv.is_empty());
        assert_eq!(
            server.unix_path.as_ref().unwrap(),
            &dir.path().join("./sock/mcp.sock")
        );
    }

    #[tokio::test]
    async fn load_parses_streamable_http_transport() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "remote": { "transport": "streamable_http", "url": "https://example.com/mcp" } } }"#,
        )
        .await
        .unwrap();

        let cfg = Config::load(dir.path(), None).await.unwrap();
        let server = cfg.servers.get("remote").unwrap();
        assert_eq!(server.transport, Transport::StreamableHttp);
        assert!(server.argv.is_empty());
        assert!(server.unix_path.is_none());
        assert_eq!(server.url.as_deref(), Some("https://example.com/mcp"));
        assert!(server.bearer_token_env_var.is_none());
        assert!(server.http_headers.is_empty());
        assert!(server.env_http_headers.is_empty());
        assert!(server.env.is_empty());
        assert!(server.stdout_log.is_none());
    }

    #[tokio::test]
    async fn load_denies_streamable_http_without_url() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "remote": { "transport": "streamable_http" } } }"#,
        )
        .await
        .unwrap();

        let err = Config::load(dir.path(), None).await.unwrap_err();
        assert!(err.to_string().contains("streamable_http"));
    }

    #[tokio::test]
    async fn load_denies_streamable_http_with_env() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "remote": { "transport": "streamable_http", "url": "https://example.com/mcp", "env": { "X": "1" } } } }"#,
        )
        .await
        .unwrap();

        let err = Config::load(dir.path(), None).await.unwrap_err();
        assert!(err.to_string().contains("transport=streamable_http"));
    }

    #[tokio::test]
    async fn load_denies_unix_transport_with_argv() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "sock": { "transport": "unix", "argv": ["x"], "unix_path": "/tmp/mcp.sock" } } }"#,
        )
        .await
        .unwrap();

        let err = Config::load(dir.path(), None).await.unwrap_err();
        assert!(err.to_string().contains("transport=unix"));
    }

    #[tokio::test]
    async fn load_denies_unix_transport_with_empty_argv() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "sock": { "transport": "unix", "argv": [], "unix_path": "/tmp/mcp.sock" } } }"#,
        )
        .await
        .unwrap();

        let err = Config::load(dir.path(), None).await.unwrap_err();
        assert!(err.to_string().contains("transport=unix"));
    }

    #[tokio::test]
    async fn load_denies_streamable_http_with_empty_argv() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "remote": { "transport": "streamable_http", "argv": [], "url": "https://example.com/mcp" } } }"#,
        )
        .await
        .unwrap();

        let err = Config::load(dir.path(), None).await.unwrap_err();
        assert!(err.to_string().contains("transport=streamable_http"));
    }

    #[tokio::test]
    async fn load_denies_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": {}, "extra": 123 }"#,
        )
        .await
        .unwrap();

        let err = Config::load(dir.path(), None).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("parse"), "err={msg}");
    }

    #[tokio::test]
    async fn load_denies_invalid_server_names() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "bad name": { "transport": "stdio", "argv": ["x"] } } }"#,
        )
        .await
        .unwrap();

        let err = Config::load(dir.path(), None).await.unwrap_err();
        assert!(err.to_string().contains("invalid mcp server name"));
    }

    #[tokio::test]
    async fn load_override_path_is_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let err = Config::load(dir.path(), Some(PathBuf::from("missing.json")))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("read"));
    }
}
