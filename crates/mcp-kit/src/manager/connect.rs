use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use tokio::process::{Child, Command};

use crate::{ServerConfig, Transport, TrustMode, UntrustedStreamableHttpPolicy};

use super::placeholders::{apply_stdio_baseline_env, expand_placeholders_trusted};
use super::streamable_http_validation::{
    validate_streamable_http_config, validate_streamable_http_url_untrusted_dns,
};

#[derive(Debug, Clone)]
pub(crate) struct ConnectContext {
    pub(crate) trust_mode: TrustMode,
    pub(crate) untrusted_streamable_http_policy: UntrustedStreamableHttpPolicy,
    pub(crate) allow_stdout_log_outside_root: bool,
    pub(crate) protocol_version: String,
    pub(crate) request_timeout: Duration,
}

#[derive(Debug, Clone)]
struct ResolvedStreamableHttpUrls {
    sse_url: String,
    post_url: String,
    sse_url_field: &'static str,
    post_url_field: &'static str,
}

pub(crate) async fn connect_transport(
    ctx: &ConnectContext,
    server_name: &str,
    server_cfg: &ServerConfig,
    cwd: &Path,
) -> anyhow::Result<(mcp_jsonrpc::Client, Option<Child>)> {
    match server_cfg.transport() {
        Transport::Stdio => connect_stdio_transport(ctx, server_name, server_cfg, cwd).await,
        Transport::Unix => connect_unix_transport(ctx, server_name, server_cfg).await,
        Transport::StreamableHttp => {
            connect_streamable_http_transport(ctx, server_name, server_cfg, cwd).await
        }
    }
}

async fn connect_stdio_transport(
    ctx: &ConnectContext,
    server_name: &str,
    server_cfg: &ServerConfig,
    cwd: &Path,
) -> anyhow::Result<(mcp_jsonrpc::Client, Option<Child>)> {
    if ctx.trust_mode == TrustMode::Untrusted {
        anyhow::bail!(
            "refusing to spawn mcp server in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
        );
    }

    let expanded_argv = server_cfg
        .argv()
        .iter()
        .enumerate()
        .map(|(idx, arg)| {
            let expanded = expand_placeholders_trusted(arg, cwd).with_context(|| {
                format!("expand argv placeholder (server={server_name} argv[{idx}] redacted)")
            })?;
            Ok::<_, anyhow::Error>(std::ffi::OsString::from(expanded))
        })
        .collect::<anyhow::Result<Vec<std::ffi::OsString>>>()?;

    let mut cmd = Command::new(&expanded_argv[0]);
    cmd.args(expanded_argv.iter().skip(1));
    cmd.current_dir(cwd);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());
    if !server_cfg.inherit_env() {
        cmd.env_clear();
        apply_stdio_baseline_env(&mut cmd);
    }
    for (key, value) in server_cfg.env().iter() {
        let value = expand_placeholders_trusted(value, cwd)
            .with_context(|| format!("expand env placeholder: {key}"))?;
        cmd.env(key, value);
    }
    cmd.kill_on_drop(true);

    let stdout_log = server_cfg.stdout_log().map(|log| {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let cwd_abs = absolutize_with_base(cwd, &current_dir);
        let resolved_log_path = absolutize_with_base(&log.path, &cwd_abs);
        if !ctx.allow_stdout_log_outside_root
            && !stdout_log_path_within_root(&resolved_log_path, &cwd_abs)
        {
            anyhow::bail!(
                "mcp server {server_name}: stdout_log.path must be within root (set Manager::with_allow_stdout_log_outside_root(true) to override): {}",
                log.path.display()
            );
        }
        Ok::<_, anyhow::Error>(mcp_jsonrpc::StdoutLog {
            path: resolved_log_path,
            max_bytes_per_part: log.max_bytes_per_part,
            max_parts: log.max_parts,
        })
    });
    let stdout_log = stdout_log.transpose()?;
    let mut client = mcp_jsonrpc::Client::spawn_command_with_options(
        cmd,
        mcp_jsonrpc::SpawnOptions {
            stdout_log,
            ..Default::default()
        },
    )
    .await
    .with_context(|| {
        format!(
            "spawn mcp server (server={server_name}) argv redacted (argc={})",
            server_cfg.argv().len()
        )
    })?;
    let child = client.take_child();
    Ok((client, child))
}

async fn connect_unix_transport(
    ctx: &ConnectContext,
    server_name: &str,
    server_cfg: &ServerConfig,
) -> anyhow::Result<(mcp_jsonrpc::Client, Option<Child>)> {
    if ctx.trust_mode == TrustMode::Untrusted {
        anyhow::bail!(
            "refusing to connect unix mcp server in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
        );
    }
    let unix_path = server_cfg.unix_path_required();
    let client = mcp_jsonrpc::Client::connect_unix(unix_path)
        .await
        .with_context(|| format!("connect unix mcp server path={}", unix_path.display()))?;
    Ok((client, None))
}

async fn connect_streamable_http_transport(
    ctx: &ConnectContext,
    server_name: &str,
    server_cfg: &ServerConfig,
    cwd: &Path,
) -> anyhow::Result<(mcp_jsonrpc::Client, Option<Child>)> {
    let resolved_urls = resolve_streamable_http_urls(ctx, server_name, server_cfg, cwd)?;

    validate_streamable_http_config(
        ctx.trust_mode,
        &ctx.untrusted_streamable_http_policy,
        server_name,
        resolved_urls.sse_url_field,
        &resolved_urls.sse_url,
        server_cfg,
    )?;
    if resolved_urls.post_url != resolved_urls.sse_url {
        validate_streamable_http_config(
            ctx.trust_mode,
            &ctx.untrusted_streamable_http_policy,
            server_name,
            resolved_urls.post_url_field,
            &resolved_urls.post_url,
            server_cfg,
        )?;
    }

    if ctx.trust_mode != TrustMode::Trusted {
        if server_cfg.bearer_token_env_var().is_some() {
            anyhow::bail!(
                "refusing to read bearer token env var in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
            );
        }
        if !server_cfg.env_http_headers().is_empty() {
            anyhow::bail!(
                "refusing to read http header env vars in untrusted mode: {server_name} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
            );
        }

        validate_streamable_http_url_untrusted_dns(
            &ctx.untrusted_streamable_http_policy,
            server_name,
            resolved_urls.sse_url_field,
            &resolved_urls.sse_url,
        )
        .await?;
        if resolved_urls.post_url != resolved_urls.sse_url {
            validate_streamable_http_url_untrusted_dns(
                &ctx.untrusted_streamable_http_policy,
                server_name,
                resolved_urls.post_url_field,
                &resolved_urls.post_url,
            )
            .await?;
        }
    }

    let headers = build_streamable_http_headers(ctx, server_name, server_cfg, cwd)?;
    let client = mcp_jsonrpc::Client::connect_streamable_http_split_with_options(
        &resolved_urls.sse_url,
        &resolved_urls.post_url,
        mcp_jsonrpc::StreamableHttpOptions {
            headers,
            request_timeout: Some(ctx.request_timeout),
            ..Default::default()
        },
        mcp_jsonrpc::SpawnOptions::default(),
    )
    .await
    .with_context(|| {
        if resolved_urls.sse_url == resolved_urls.post_url {
            format!(
                "connect streamable http mcp server (server={server_name} field={}) (url redacted)",
                resolved_urls.sse_url_field
            )
        } else {
            format!(
                "connect streamable http mcp server (server={server_name} fields={},{}) (urls redacted)",
                resolved_urls.sse_url_field, resolved_urls.post_url_field
            )
        }
    })?;

    Ok((client, None))
}

fn resolve_streamable_http_urls(
    ctx: &ConnectContext,
    server_name: &str,
    server_cfg: &ServerConfig,
    cwd: &Path,
) -> anyhow::Result<ResolvedStreamableHttpUrls> {
    let (sse_url_raw, post_url_raw) = match (
        server_cfg.url(),
        server_cfg.sse_url(),
        server_cfg.http_url(),
    ) {
        (Some(url), None, None) => (url, url),
        (None, Some(sse_url), Some(http_url)) => (sse_url, http_url),
        _ => {
            anyhow::bail!(
                "mcp server {server_name}: set url or (sse_url + http_url) for transport=streamable_http"
            )
        }
    };

    let (sse_url_field, post_url_field) = if server_cfg.url().is_some() {
        ("url", "url")
    } else {
        ("sse_url", "http_url")
    };

    let sse_url = if ctx.trust_mode == TrustMode::Trusted {
        expand_placeholders_trusted(sse_url_raw, cwd).with_context(|| {
            format!(
                "expand url placeholder (server={server_name} field={sse_url_field}) (url redacted)"
            )
        })?
    } else {
        sse_url_raw.to_string()
    };
    let post_url = if ctx.trust_mode == TrustMode::Trusted {
        expand_placeholders_trusted(post_url_raw, cwd).with_context(|| {
            format!(
                "expand url placeholder (server={server_name} field={post_url_field}) (url redacted)"
            )
        })?
    } else {
        post_url_raw.to_string()
    };

    Ok(ResolvedStreamableHttpUrls {
        sse_url,
        post_url,
        sse_url_field,
        post_url_field,
    })
}

fn build_streamable_http_headers(
    ctx: &ConnectContext,
    server_name: &str,
    server_cfg: &ServerConfig,
    cwd: &Path,
) -> anyhow::Result<HashMap<String, String>> {
    let capacity = server_cfg
        .http_headers()
        .len()
        .saturating_add(1)
        .saturating_add(usize::from(server_cfg.bearer_token_env_var().is_some()))
        .saturating_add(server_cfg.env_http_headers().len());
    let mut headers = HashMap::with_capacity(capacity);

    for (key, value) in server_cfg.http_headers() {
        let value = if ctx.trust_mode == TrustMode::Trusted {
            expand_placeholders_trusted(value, cwd).with_context(|| {
                format!("expand http_header placeholder: {server_name} header={key}")
            })?
        } else {
            value.to_string()
        };
        headers.insert(key.to_string(), value);
    }
    headers.insert(
        "MCP-Protocol-Version".to_string(),
        ctx.protocol_version.clone(),
    );

    if let Some(env_var) = server_cfg.bearer_token_env_var() {
        debug_assert_eq!(ctx.trust_mode, TrustMode::Trusted);
        let token = std::env::var(env_var)
            .with_context(|| format!("read bearer token env var: {env_var}"))?;
        headers.insert("Authorization".to_string(), format!("Bearer {token}"));
    }

    if !server_cfg.env_http_headers().is_empty() {
        debug_assert_eq!(ctx.trust_mode, TrustMode::Trusted);
        for (header, env_var) in server_cfg.env_http_headers().iter() {
            let value = std::env::var(env_var)
                .with_context(|| format!("read http header env var: {env_var}"))?;
            headers.insert(header.to_string(), value);
        }
    }

    Ok(headers)
}

pub(super) fn absolutize_with_base(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    base.join(path)
}

fn normalize_path_for_prefix_check(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

pub(super) fn stdout_log_path_within_root(stdout_log_path: &Path, root: &Path) -> bool {
    if !root.is_absolute() {
        return false;
    }

    let resolved_stdout_log_path = absolutize_with_base(stdout_log_path, root);
    let normalized_root = normalize_path_for_prefix_check(root);
    let normalized_stdout_log_path = normalize_path_for_prefix_check(&resolved_stdout_log_path);
    normalized_stdout_log_path.starts_with(&normalized_root)
}
