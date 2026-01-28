#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrustMode {
    /// Default: treat local config as untrusted and refuse "unsafe" actions
    /// such as spawning processes or connecting to arbitrary unix sockets.
    #[default]
    Untrusted,
    /// Fully trust local config and allow spawning processes / unix socket connects.
    Trusted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedStreamableHttpPolicy {
    /// When true (default), only allow `https://` URLs in untrusted mode.
    pub require_https: bool,
    /// When false (default), reject `localhost`, `*.localhost`, and `*.local` domains.
    pub allow_localhost: bool,
    /// When false (default), reject loopback/link-local/private IP literals.
    pub allow_private_ips: bool,
    /// Optional host allowlist. When non-empty, only these hosts (or their subdomains)
    /// are allowed in untrusted mode.
    pub allowed_hosts: Vec<String>,
}

impl Default for UntrustedStreamableHttpPolicy {
    fn default() -> Self {
        Self {
            require_https: true,
            allow_localhost: false,
            allow_private_ips: false,
            allowed_hosts: Vec::new(),
        }
    }
}
