use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Context;

use crate::{ServerConfig, TrustMode, UntrustedStreamableHttpPolicy};

fn ends_with_ignore_ascii_case(haystack: &str, suffix: &str) -> bool {
    if suffix.len() > haystack.len() {
        return false;
    }
    haystack
        .get(haystack.len() - suffix.len()..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

pub(super) fn validate_streamable_http_config(
    trust_mode: TrustMode,
    policy: &UntrustedStreamableHttpPolicy,
    server_name: &str,
    url_field: &str,
    url: &str,
    server_cfg: &ServerConfig,
) -> anyhow::Result<()> {
    if trust_mode == TrustMode::Trusted {
        return Ok(());
    }

    validate_streamable_http_url_untrusted(policy, server_name, url_field, url)?;

    for header in server_cfg.http_headers().keys() {
        if is_untrusted_sensitive_http_header(header) {
            anyhow::bail!(
                "refusing to send sensitive http header in untrusted mode: {server_name} header={header} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
            );
        }
    }

    Ok(())
}

pub(super) fn validate_streamable_http_url_untrusted(
    policy: &UntrustedStreamableHttpPolicy,
    server_name: &str,
    url_field: &str,
    url: &str,
) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(url).with_context(|| {
        format!(
            "invalid streamable http url (server={server_name} field={url_field}) (url redacted)"
        )
    })?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!(
            "refusing to use url credentials in untrusted mode: {server_name} field={url_field} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
        );
    }

    match parsed.scheme() {
        "https" => {}
        "http" if !policy.require_https => {}
        _ => {
            anyhow::bail!(
                "refusing to connect non-https streamable http url in untrusted mode: {server_name} field={url_field} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
            );
        }
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("streamable http url must include a host (server={server_name} field={url_field}) (url redacted)"))?;
    let host = host.trim_end_matches('.');
    let host_for_ip = host.trim_start_matches('[').trim_end_matches(']');
    if !policy.allow_localhost {
        let is_ip_literal = host_for_ip.parse::<IpAddr>().is_ok();
        let is_single_label = !is_ip_literal && !host.contains('.');
        if host.eq_ignore_ascii_case("localhost")
            || host.eq_ignore_ascii_case("localhost.localdomain")
            || ends_with_ignore_ascii_case(host, ".localhost")
            || ends_with_ignore_ascii_case(host, ".local")
            || ends_with_ignore_ascii_case(host, ".localdomain")
            || is_single_label
        {
            anyhow::bail!(
                "refusing to connect localhost/local/single-label domain in untrusted mode: {server_name} host={host} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
            );
        }
    }

    if !policy.allowed_hosts.is_empty()
        && !policy
            .allowed_hosts
            .iter()
            .any(|allowed| host_matches_allowlist(host, allowed))
    {
        anyhow::bail!(
            "refusing to connect streamable http host not in allowlist in untrusted mode: {server_name} host={host} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
        );
    }

    if let Ok(ip) = host_for_ip.parse::<IpAddr>() {
        let ip = normalize_ip(ip);
        if is_untrusted_always_disallowed_ip(ip)
            || (!policy.allow_private_ips && is_untrusted_non_global_ip(ip))
        {
            anyhow::bail!(
                "refusing to connect non-global ip in untrusted mode: {server_name} host={host} (set Manager::with_trust_mode(TrustMode::Trusted) to override)"
            );
        }
    }

    Ok(())
}

pub(super) async fn validate_streamable_http_url_untrusted_dns(
    policy: &UntrustedStreamableHttpPolicy,
    server_name: &str,
    url_field: &str,
    url: &str,
) -> anyhow::Result<()> {
    if !policy.dns_check || policy.allow_private_ips {
        return Ok(());
    }

    let parsed = reqwest::Url::parse(url).with_context(|| {
        format!(
            "invalid streamable http url (server={server_name} field={url_field}) (url redacted)"
        )
    })?;

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("streamable http url must include a host (server={server_name} field={url_field}) (url redacted)"))?;
    let host = host.trim_end_matches('.');
    let host_for_ip = host.trim_start_matches('[').trim_end_matches(']');
    if host_for_ip.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    let port = parsed.port_or_known_default().ok_or_else(|| {
        anyhow::anyhow!(
            "streamable http url must include a port or known scheme (server={server_name} field={url_field}) (url redacted)"
        )
    })?;

    let addrs = match tokio::time::timeout(
        policy.dns_timeout,
        tokio::net::lookup_host((host_for_ip, port)),
    )
    .await
    {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(err)) => {
            if policy.dns_fail_open {
                return Ok(());
            }
            anyhow::bail!(
                "refusing to connect hostname with failed dns lookup in untrusted mode: {server_name} host={host} err={err}"
            );
        }
        Err(_) => {
            if policy.dns_fail_open {
                return Ok(());
            }
            anyhow::bail!(
                "refusing to connect hostname with timed out dns lookup in untrusted mode: {server_name} host={host}"
            );
        }
    };

    for addr in addrs {
        let ip = normalize_ip(addr.ip());
        if is_untrusted_always_disallowed_ip(ip) || is_untrusted_non_global_ip(ip) {
            anyhow::bail!(
                "refusing to connect hostname that resolves to non-global ip in untrusted mode: {server_name} host={host} ip={ip} (set Manager::with_trust_mode(TrustMode::Trusted) or allow_private_ips to override)"
            );
        }
    }

    Ok(())
}

fn host_matches_allowlist(host: &str, allowed: &str) -> bool {
    let host = host.trim().trim_end_matches('.');
    let allowed = allowed.trim().trim_end_matches('.');
    if allowed.is_empty() {
        return false;
    }
    if host.eq_ignore_ascii_case(allowed) {
        return true;
    }
    if host.len() <= allowed.len() + 1 {
        return false;
    }
    if !ends_with_ignore_ascii_case(host, allowed) {
        return false;
    }
    let boundary = host.len() - allowed.len() - 1;
    host.as_bytes().get(boundary).is_some_and(|ch| *ch == b'.')
}

fn is_untrusted_sensitive_http_header(header: &str) -> bool {
    let header = header.trim();
    header.eq_ignore_ascii_case("authorization")
        || header.eq_ignore_ascii_case("proxy-authorization")
        || header.eq_ignore_ascii_case("cookie")
}

pub(super) fn should_disconnect_after_jsonrpc_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<mcp_jsonrpc::Error>()
            .is_some_and(|err| {
                matches!(
                    err,
                    mcp_jsonrpc::Error::Io(_) | mcp_jsonrpc::Error::Protocol(_)
                )
            })
    })
}

fn is_untrusted_always_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_multicast() || ip.is_broadcast() || ip.is_unspecified(),
        IpAddr::V6(ip) => ip.is_multicast() || ip.is_unspecified(),
    }
}

fn is_untrusted_non_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_untrusted_non_global_ipv4(ip),
        IpAddr::V6(ip) => is_untrusted_non_global_ipv6(ip),
    }
}

fn is_untrusted_non_global_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
    {
        return true;
    }

    let [a, b, c, _d] = ip.octets();

    // 0.0.0.0/8
    if a == 0 {
        return true;
    }

    // 100.64.0.0/10 (shared address space / carrier-grade NAT)
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }

    // 192.0.0.0/24 (IETF Protocol Assignments)
    if a == 192 && b == 0 && c == 0 {
        return true;
    }

    // 198.18.0.0/15 (benchmarking)
    if a == 198 && (18..=19).contains(&b) {
        return true;
    }

    // 240.0.0.0/4 (reserved)
    if a >= 240 {
        return true;
    }

    false
}

fn is_untrusted_non_global_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
    {
        return true;
    }

    // 2001:db8::/32 (documentation)
    let segments = ip.segments();
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }

    false
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(ip) => IpAddr::V4(ip),
    }
}
