use super::*;
use std::path::PathBuf;

#[cfg(unix)]
#[tokio::test]
async fn load_denies_mcpservers_indirection_via_symlink_file() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    tokio::fs::write(
        outside.path().join("servers.json"),
        r#"{ "mcpServers": { "a": { "command": "echo", "args": ["hi"] } } }"#,
    )
    .await
    .unwrap();

    let link = dir.path().join("servers.json");
    std::os::unix::fs::symlink(outside.path().join("servers.json"), &link).unwrap();

    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{ "mcpServers": "servers.json" }"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("escapes root"), "err={msg}");
}

#[cfg(unix)]
#[tokio::test]
async fn load_denies_mcpservers_indirection_via_symlink_dir() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    tokio::fs::write(
        outside.path().join("servers.json"),
        r#"{ "mcpServers": { "a": { "command": "echo", "args": ["hi"] } } }"#,
    )
    .await
    .unwrap();

    let link_dir = dir.path().join("linkdir");
    std::os::unix::fs::symlink(outside.path(), &link_dir).unwrap();

    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{ "mcpServers": "linkdir/servers.json" }"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("escapes root"), "err={msg}");
}

#[cfg(unix)]
#[tokio::test]
async fn load_allows_mcpservers_indirection_via_symlink_dir_within_root() {
    let dir = tempfile::tempdir().unwrap();

    let real_dir = dir.path().join("real_dir");
    tokio::fs::create_dir_all(&real_dir).await.unwrap();
    tokio::fs::write(
        real_dir.join("servers.json"),
        r#"{ "mcpServers": { "a": { "command": "echo", "args": ["hi"] } } }"#,
    )
    .await
    .unwrap();

    let link_dir = dir.path().join("linkdir");
    std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{ "mcpServers": "linkdir/servers.json" }"#,
    )
    .await
    .unwrap();

    let cfg = Config::load(dir.path(), None).await.unwrap();
    assert!(cfg.servers().contains_key("a"));
}

#[cfg(unix)]
#[tokio::test]
async fn load_denies_config_via_symlink_file() {
    let dir = tempfile::tempdir().unwrap();

    tokio::fs::write(
        dir.path().join("real.json"),
        r#"{ "version": 1, "servers": { "a": { "transport": "stdio", "argv": ["mcp-a"] } } }"#,
    )
    .await
    .unwrap();

    let link = dir.path().join("mcp.json");
    std::os::unix::fs::symlink(dir.path().join("real.json"), &link).unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("symlink"), "err={msg}");
}

#[cfg(unix)]
#[tokio::test]
async fn load_denies_config_via_symlink_dir() {
    let dir = tempfile::tempdir().unwrap();

    let real_dir = dir.path().join("real_dir");
    tokio::fs::create_dir(&real_dir).await.unwrap();

    let link = dir.path().join("mcp.json");
    std::os::unix::fs::symlink(&real_dir, &link).unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("symlink"), "err={msg}");
}

#[tokio::test]
async fn load_defaults_to_empty_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::load(dir.path(), None).await.unwrap();
    assert!(cfg.path().is_none());
    assert!(cfg.client().protocol_version.is_none());
    assert!(cfg.client().capabilities.is_none());
    assert!(cfg.client().roots.is_none());
    assert!(cfg.servers().is_empty());
}

#[tokio::test]
async fn load_required_errors_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let err = Config::load_required(dir.path(), None).await.unwrap_err();
    assert!(err.to_string().contains("not found"), "err={err:#}");
}

#[tokio::test]
async fn load_fails_closed_when_config_is_too_large() {
    let dir = tempfile::tempdir().unwrap();
    let big = "a".repeat((MAX_CONFIG_BYTES + 1) as usize);
    tokio::fs::write(dir.path().join("mcp.json"), big)
        .await
        .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(
        err.to_string().contains("too large"),
        "unexpected error: {err}"
    );
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
    assert_eq!(cfg.path().unwrap(), &dir.path().join(".mcp.json"));
    assert!(cfg.servers().contains_key("a"));
    assert!(!cfg.servers().contains_key("b"));
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
    assert_eq!(cfg.path().unwrap(), &dir.path().join("mcp.json"));
    assert!(cfg.servers().contains_key("a"));
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
    assert!(cfg.path().is_some());
    assert_eq!(cfg.servers().len(), 1);
    let server = cfg.servers().get("rg").unwrap();
    assert_eq!(
        server.argv(),
        &["mcp-rg".to_string(), "--stdio".to_string()]
    );
    assert!(server.env().contains_key("NO_COLOR"));
    assert!(server.stdout_log().is_none());
    assert!(server.unix_path().is_none());
}

#[tokio::test]
async fn load_denies_stdio_env_with_empty_key() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{ "version": 1, "servers": { "a": { "transport": "stdio", "argv": ["mcp-a"], "env": { "": "1" } } } }"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(
        err.to_string().contains("env key must not be empty"),
        "err={err:#}"
    );
}

#[tokio::test]
async fn load_denies_stdio_env_with_empty_value() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{ "version": 1, "servers": { "a": { "transport": "stdio", "argv": ["mcp-a"], "env": { "X": "" } } } }"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(
        err.to_string().contains("env[X] must not be empty"),
        "err={err:#}"
    );
}

#[test]
fn server_config_validate_rejects_stdio_http_auth_fields() {
    let mut cfg = ServerConfig::stdio(vec!["mcp-a".to_string()]).unwrap();
    assert!(
        cfg.set_bearer_token_env_var(Some("MCP_TOKEN".to_string()))
            .is_err()
    );
}

#[test]
fn server_config_validate_rejects_unix_env_fields() {
    let mut cfg = ServerConfig::unix(PathBuf::from("/tmp/mcp.sock")).unwrap();
    assert!(cfg.env_mut().is_err());
}

#[test]
fn server_config_validate_rejects_streamable_http_stdout_log() {
    let mut cfg = ServerConfig::streamable_http("https://example.com/mcp").unwrap();
    assert!(
        cfg.set_stdout_log(Some(StdoutLogConfig {
            path: PathBuf::from("logs/stdout.log"),
            max_bytes_per_part: 1,
            max_parts: None,
        }))
        .is_err()
    );
}

#[test]
fn client_config_validate_rejects_empty_protocol_version() {
    let cfg = ClientConfig {
        protocol_version: Some("   ".to_string()),
        ..Default::default()
    };
    assert!(cfg.validate().is_err());
}

#[test]
fn client_config_validate_rejects_non_object_capabilities() {
    let cfg = ClientConfig {
        capabilities: Some(serde_json::json!(1)),
        ..Default::default()
    };
    assert!(cfg.validate().is_err());
}

#[test]
fn config_validate_rejects_invalid_client_roots() {
    let client = ClientConfig {
        roots: Some(vec![Root {
            uri: " ".to_string(),
            name: None,
        }]),
        ..Default::default()
    };
    let cfg = Config::new(client, std::collections::BTreeMap::new());
    assert!(cfg.validate().is_err());
}

#[test]
fn server_config_validate_rejects_stdio_stdout_log_with_parent_dir() {
    let mut cfg = ServerConfig::stdio(vec!["mcp-a".to_string()]).unwrap();
    cfg.set_stdout_log(Some(StdoutLogConfig {
        path: PathBuf::from("../oops.log"),
        max_bytes_per_part: 1,
        max_parts: Some(1),
    }))
    .unwrap();
    assert!(cfg.validate().is_err());
}

#[test]
fn server_config_validate_rejects_stdio_stdout_log_with_zero_max_bytes() {
    let mut cfg = ServerConfig::stdio(vec!["mcp-a".to_string()]).unwrap();
    cfg.set_stdout_log(Some(StdoutLogConfig {
        path: PathBuf::from("logs/stdout.log"),
        max_bytes_per_part: 0,
        max_parts: Some(1),
    }))
    .unwrap();
    assert!(cfg.validate().is_err());
}

#[test]
fn server_config_validate_rejects_stdio_stdout_log_with_zero_max_parts() {
    let mut cfg = ServerConfig::stdio(vec!["mcp-a".to_string()]).unwrap();
    cfg.set_stdout_log(Some(StdoutLogConfig {
        path: PathBuf::from("logs/stdout.log"),
        max_bytes_per_part: 1,
        max_parts: Some(0),
    }))
    .unwrap();
    assert!(cfg.validate().is_err());
}

#[tokio::test]
async fn load_parses_stdio_inherit_env() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "a": { "transport": "stdio", "argv": ["mcp-a"], "inherit_env": false } } }"#,
        )
        .await
        .unwrap();

    let cfg = Config::load(dir.path(), None).await.unwrap();
    let server = cfg.servers().get("a").unwrap();
    assert!(!server.inherit_env());
}

#[tokio::test]
async fn load_denies_stdout_log_path_with_parent_dir() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "a": { "transport": "stdio", "argv": ["mcp-a"], "stdout_log": { "path": "../oops.log" } } } }"#,
        )
        .await
        .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(
        err.to_string().contains("stdout_log.path") && err.to_string().contains(".."),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn load_denies_stdout_log_with_zero_max_bytes_per_part() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{ "version": 1, "servers": { "a": { "transport": "stdio", "argv": ["mcp-a"], "stdout_log": { "path": "./logs/a.stdout.log", "max_bytes_per_part": 0 } } } }"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid stdout_log config"), "err={err:#}");
    assert!(msg.contains("max_bytes_per_part"), "err={err:#}");
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
    assert_eq!(cfg.client().protocol_version.as_deref(), Some("2025-06-18"));
    assert!(
        cfg.client()
            .capabilities
            .as_ref()
            .expect("capabilities")
            .is_object()
    );
    assert!(cfg.client().roots.is_none());
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
    let roots = cfg.client().roots.as_ref().expect("roots");
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
    let server = cfg.servers().get("rg").unwrap();
    let stdout_log = server.stdout_log().expect("stdout_log");
    assert_eq!(stdout_log.path, dir.path().join("./logs/rg.stdout.log"));
    assert_eq!(
        stdout_log.max_bytes_per_part,
        DEFAULT_STDOUT_LOG_MAX_BYTES_PER_PART
    );
    assert_eq!(stdout_log.max_parts, Some(DEFAULT_STDOUT_LOG_MAX_PARTS));
}

#[tokio::test]
async fn load_denies_stdout_log_with_empty_path() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{ "version": 1, "servers": { "rg": { "transport": "stdio", "argv": ["mcp-rg"], "stdout_log": { "path": "" } } } }"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(
        err.to_string().contains("stdout_log.path")
            && err.to_string().contains("must not be empty"),
        "unexpected error: {err}"
    );
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
    let server = cfg.servers().get("rg").unwrap();
    let stdout_log = server.stdout_log().expect("stdout_log");
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
    let server = cfg.servers().get("sock").unwrap();
    assert_eq!(server.transport(), Transport::Unix);
    assert!(server.argv().is_empty());
    assert_eq!(
        server.unix_path().as_ref().unwrap(),
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
    let server = cfg.servers().get("remote").unwrap();
    assert_eq!(server.transport(), Transport::StreamableHttp);
    assert!(server.argv().is_empty());
    assert!(server.unix_path().is_none());
    assert_eq!(server.url(), Some("https://example.com/mcp"));
    assert!(server.sse_url().is_none());
    assert!(server.http_url().is_none());
    assert!(server.bearer_token_env_var().is_none());
    assert!(server.http_headers().is_empty());
    assert!(server.env_http_headers().is_empty());
    assert!(server.env().is_empty());
    assert!(server.stdout_log().is_none());
}

#[tokio::test]
async fn load_parses_streamable_http_transport_with_split_urls() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "remote": { "transport": "streamable_http", "sse_url": "https://example.com/sse", "http_url": "https://example.com/mcp" } } }"#,
        )
        .await
        .unwrap();

    let cfg = Config::load(dir.path(), None).await.unwrap();
    let server = cfg.servers().get("remote").unwrap();
    assert_eq!(server.transport(), Transport::StreamableHttp);
    assert!(server.argv().is_empty());
    assert!(server.unix_path().is_none());
    assert!(server.url().is_none());
    assert_eq!(server.sse_url(), Some("https://example.com/sse"));
    assert_eq!(server.http_url(), Some("https://example.com/mcp"));
}

#[tokio::test]
async fn load_denies_streamable_http_with_url_and_split_urls() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "remote": { "transport": "streamable_http", "url": "https://example.com/mcp", "sse_url": "https://example.com/sse", "http_url": "https://example.com/mcp" } } }"#,
        )
        .await
        .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(err.to_string().contains("set either url or"));
}

#[tokio::test]
async fn load_denies_streamable_http_with_partial_split_urls() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
            dir.path().join("mcp.json"),
            r#"{ "version": 1, "servers": { "remote": { "transport": "streamable_http", "sse_url": "https://example.com/sse" } } }"#,
        )
        .await
        .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(err.to_string().contains("sse_url and http_url"));
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
async fn load_parses_claude_code_style_dot_mcp_json() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join(".mcp.json"),
        r#"{
  "filesystem": {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    "env": { "LOG_LEVEL": "debug" }
  }
}"#,
    )
    .await
    .unwrap();

    let cfg = Config::load(dir.path(), None).await.unwrap();
    let server = cfg.servers().get("filesystem").unwrap();
    assert_eq!(cfg.path().unwrap(), &dir.path().join(".mcp.json"));
    assert_eq!(server.transport(), Transport::Stdio);
    assert_eq!(
        server.argv(),
        &[
            "npx".to_string(),
            "-y".to_string(),
            "@modelcontextprotocol/server-filesystem".to_string(),
            "/tmp".to_string()
        ]
    );
    assert_eq!(
        server.env().get("LOG_LEVEL").map(String::as_str),
        Some("debug")
    );
}

#[tokio::test]
async fn load_parses_cursor_mcp_servers_wrapper() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{
  "$schema": "https://cursor.com/mcp.schema.json",
  "mcpServers": {
    "litellm": {
      "url": "http://example.com/mcp",
      "type": "http",
      "headers": { "X-Test": "1" }
    }
  }
}"#,
    )
    .await
    .unwrap();

    let cfg = Config::load(dir.path(), None).await.unwrap();
    let server = cfg.servers().get("litellm").unwrap();
    assert_eq!(server.transport(), Transport::StreamableHttp);
    assert_eq!(server.url(), Some("http://example.com/mcp"));
    assert_eq!(
        server.http_headers().get("X-Test").map(String::as_str),
        Some("1")
    );
}

#[tokio::test]
async fn load_denies_streamable_http_with_invalid_http_header_name() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{
  "$schema": "https://cursor.com/mcp.schema.json",
  "mcpServers": {
    "litellm": {
      "url": "http://example.com/mcp",
      "type": "http",
      "headers": { "Bad Header": "1" }
    }
  }
}"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(
        err.to_string().contains("invalid http_headers key"),
        "err={err:#}"
    );
}

#[tokio::test]
async fn load_denies_streamable_http_with_invalid_http_header_value() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{
  "$schema": "https://cursor.com/mcp.schema.json",
  "mcpServers": {
    "litellm": {
      "url": "http://example.com/mcp",
      "type": "http",
      "headers": { "X-Test": "1\n2" }
    }
  }
}"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("invalid http_headers[X-Test] value"),
        "err={err:#}"
    );
}

#[tokio::test]
async fn load_denies_streamable_http_with_invalid_env_http_header_name() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{
  "$schema": "https://cursor.com/mcp.schema.json",
  "mcpServers": {
    "litellm": {
      "url": "http://example.com/mcp",
      "type": "http",
      "env_http_headers": { "Bad Header": "TOKEN" }
    }
  }
}"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(
        err.to_string().contains("invalid env_http_headers key"),
        "err={err:#}"
    );
}

#[tokio::test]
async fn load_denies_unix_transport_with_stdout_log_in_v1_format() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{ "version": 1, "servers": { "sock": { "transport": "unix", "unix_path": "/tmp/mcp.sock", "stdout_log": { "path": "" } } } }"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("stdout_log is not supported for transport=unix"),
        "err={err:#}"
    );
    assert!(!msg.contains("invalid stdout_log config"), "err={err:#}");
}

#[tokio::test]
async fn load_denies_streamable_http_with_stdout_log_in_v1_format() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{ "version": 1, "servers": { "remote": { "transport": "streamable_http", "url": "https://example.com/mcp", "stdout_log": { "path": "" } } } }"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("stdout_log is not supported for transport=streamable_http"),
        "err={err:#}"
    );
    assert!(!msg.contains("invalid stdout_log config"), "err={err:#}");
}

#[tokio::test]
async fn load_denies_unix_transport_with_stdout_log_in_external_format() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{
  "mcpServers": {
    "sock": {
      "unix_path": "/tmp/mcp.sock",
      "stdout_log": { "path": "" }
    }
  }
}"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("stdout_log is not supported for transport=unix"),
        "err={err:#}"
    );
    assert!(!msg.contains("invalid stdout_log config"), "err={err:#}");
}

#[tokio::test]
async fn load_denies_streamable_http_with_stdout_log_in_external_format() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{
  "mcpServers": {
    "litellm": {
      "url": "http://example.com/mcp",
      "stdout_log": { "path": "" }
    }
  }
}"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("stdout_log is not supported for transport=streamable_http"),
        "err={err:#}"
    );
    assert!(!msg.contains("invalid stdout_log config"), "err={err:#}");
}

#[tokio::test]
async fn load_parses_mcp_servers_wrapper_even_with_version_string() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("plugin.json"),
        r#"{
  "name": "my-plugin",
  "version": "1.0.0",
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "echo", "hi"]
    }
  }
}"#,
    )
    .await
    .unwrap();

    let cfg = Config::load(dir.path(), Some(PathBuf::from("plugin.json")))
        .await
        .unwrap();
    assert_eq!(cfg.path().unwrap(), &dir.path().join("plugin.json"));
    let server = cfg.servers().get("filesystem").unwrap();
    assert_eq!(server.transport(), Transport::Stdio);
    assert_eq!(
        server.argv(),
        &[
            "npx".to_string(),
            "-y".to_string(),
            "echo".to_string(),
            "hi".to_string()
        ]
    );
}

#[tokio::test]
async fn load_parses_mcp_servers_wrapper_even_with_version_number() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("plugin.json"),
        r#"{
  "name": "my-plugin",
  "version": 1,
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "echo", "hi"]
    }
  }
}"#,
    )
    .await
    .unwrap();

    let cfg = Config::load(dir.path(), Some(PathBuf::from("plugin.json")))
        .await
        .unwrap();
    assert_eq!(cfg.path().unwrap(), &dir.path().join("plugin.json"));
    let server = cfg.servers().get("filesystem").unwrap();
    assert_eq!(server.transport(), Transport::Stdio);
    assert_eq!(
        server.argv(),
        &[
            "npx".to_string(),
            "-y".to_string(),
            "echo".to_string(),
            "hi".to_string()
        ]
    );
}

#[tokio::test]
async fn load_parses_mcp_servers_path_to_dot_mcp_json() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("plugin.json"),
        r#"{
  "name": "my-plugin",
  "version": "1.0.0",
  "mcpServers": "./.mcp.json"
}"#,
    )
    .await
    .unwrap();
    tokio::fs::write(
        dir.path().join(".mcp.json"),
        r#"{
  "filesystem": {
    "command": "npx",
    "args": ["-y", "echo", "hi"]
  }
}"#,
    )
    .await
    .unwrap();

    let cfg = Config::load(dir.path(), Some(PathBuf::from("plugin.json")))
        .await
        .unwrap();
    assert_eq!(cfg.path().unwrap(), &dir.path().join(".mcp.json"));
    let server = cfg.servers().get("filesystem").unwrap();
    assert_eq!(server.transport(), Transport::Stdio);
    assert_eq!(
        server.argv(),
        &[
            "npx".to_string(),
            "-y".to_string(),
            "echo".to_string(),
            "hi".to_string()
        ]
    );
}

#[tokio::test]
async fn load_denies_cursor_mcp_servers_type_transport_conflict() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{
  "$schema": "https://cursor.com/mcp.schema.json",
  "mcpServers": {
    "bad": {
      "type": "http",
      "command": "npx",
      "args": ["-y", "echo", "hi"]
    }
  }
}"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(err.to_string().contains("conflicts"));
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
async fn load_denies_duplicate_server_names_after_trim_in_v1() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{ "version": 1, "servers": { "srv": { "transport": "stdio", "argv": ["a"] }, " srv ": { "transport": "stdio", "argv": ["b"] } } }"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("duplicate mcp server name after normalization"),
        "err={err:#}"
    );
}

#[tokio::test]
async fn load_denies_duplicate_server_names_after_trim_in_external_format() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(
        dir.path().join("mcp.json"),
        r#"{
  "srv": { "command": "echo", "args": ["a"] },
  " srv ": { "command": "echo", "args": ["b"] }
}"#,
    )
    .await
    .unwrap();

    let err = Config::load(dir.path(), None).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("duplicate mcp server name after normalization"),
        "err={err:#}"
    );
}

#[tokio::test]
async fn load_override_path_is_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let err = Config::load(dir.path(), Some(PathBuf::from("missing.json")))
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("stat") || msg.contains("read"), "err={msg}");
}
