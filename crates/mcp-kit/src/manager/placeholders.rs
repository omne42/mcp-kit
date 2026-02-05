use std::path::Path;

use anyhow::Context;
use tokio::process::Command;

const STDIO_BASELINE_ENV_VARS: [&str; 8] = [
    "PATH",
    "HOME",
    "USERPROFILE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SystemRoot",
    "SYSTEMROOT",
];
pub(super) fn apply_stdio_baseline_env(cmd: &mut Command) {
    for key in STDIO_BASELINE_ENV_VARS {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
}

fn is_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

pub(super) fn expand_placeholders_trusted(template: &str, cwd: &Path) -> anyhow::Result<String> {
    if !template.contains("${") {
        return Ok(template.to_string());
    }

    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| anyhow::anyhow!("unterminated placeholder (missing `}}`)"))?;
        let name = &after[..end];
        if !is_env_var_name(name) {
            anyhow::bail!("invalid placeholder name: {name}");
        }
        let value = match name {
            "CLAUDE_PLUGIN_ROOT" | "MCP_ROOT" => cwd.display().to_string(),
            _ => std::env::var(name).with_context(|| format!("read env var: {name}"))?,
        };
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}
