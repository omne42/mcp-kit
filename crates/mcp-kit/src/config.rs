use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

const MCP_CONFIG_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    version: u32,
    servers: BTreeMap<String, ServerConfigFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerConfigFile {
    transport: Transport,
    argv: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Stdio,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub path: Option<PathBuf>,
    pub servers: BTreeMap<String, ServerConfig>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub transport: Transport,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
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
        let from_override = override_path.is_some();
        let path = match override_path {
            Some(path) if path.is_absolute() => path,
            Some(path) => thread_root.join(path),
            None => thread_root
                .join(".codepm_data")
                .join("spec")
                .join("mcp.json"),
        };

        let contents = match tokio::fs::read_to_string(&path).await {
            Ok(contents) => contents,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && !from_override => {
                return Ok(Self {
                    path: None,
                    servers: BTreeMap::new(),
                });
            }
            Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
        };

        let cfg: ConfigFile =
            serde_json::from_str(&contents).with_context(|| format!("parse {}", path.display()))?;
        if cfg.version != MCP_CONFIG_VERSION {
            anyhow::bail!(
                "unsupported mcp.json version {} (expected {})",
                cfg.version,
                MCP_CONFIG_VERSION
            );
        }

        let mut servers = BTreeMap::<String, ServerConfig>::new();
        for (name, server) in cfg.servers {
            if !is_valid_server_name(&name) {
                anyhow::bail!("invalid mcp server name: {name}");
            }
            if server.argv.is_empty() {
                anyhow::bail!("mcp server {name}: argv must not be empty");
            }
            for (idx, arg) in server.argv.iter().enumerate() {
                if arg.trim().is_empty() {
                    anyhow::bail!("mcp server {name}: argv[{idx}] must not be empty");
                }
            }
            servers.insert(
                name,
                ServerConfig {
                    transport: server.transport,
                    argv: server.argv,
                    env: server.env,
                },
            );
        }

        Ok(Self {
            path: Some(path),
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
        assert!(cfg.servers.is_empty());
    }

    #[tokio::test]
    async fn load_parses_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let spec_dir = dir.path().join(".codepm_data").join("spec");
        tokio::fs::create_dir_all(&spec_dir).await.unwrap();
        tokio::fs::write(
            spec_dir.join("mcp.json"),
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
    }

    #[tokio::test]
    async fn load_denies_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let spec_dir = dir.path().join(".codepm_data").join("spec");
        tokio::fs::create_dir_all(&spec_dir).await.unwrap();
        tokio::fs::write(
            spec_dir.join("mcp.json"),
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
        let spec_dir = dir.path().join(".codepm_data").join("spec");
        tokio::fs::create_dir_all(&spec_dir).await.unwrap();
        tokio::fs::write(
            spec_dir.join("mcp.json"),
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
