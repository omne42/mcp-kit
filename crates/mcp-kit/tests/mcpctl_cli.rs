#[cfg(feature = "cli")]
mod cli_tests {
    use assert_cmd::cargo::cargo_bin_cmd;
    use predicates::prelude::*;

    #[test]
    fn trust_requires_yes_trust() {
        let dir = tempfile::tempdir().unwrap();

        let mut cmd = cargo_bin_cmd!("mcpctl");
        cmd.arg("--root")
            .arg(dir.path())
            .arg("--trust")
            .arg("list-servers");
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("--yes-trust"));
    }

    #[test]
    fn allow_host_with_no_dns_check_warns() {
        let dir = tempfile::tempdir().unwrap();

        let mut cmd = cargo_bin_cmd!("mcpctl");
        cmd.arg("--root")
            .arg(dir.path())
            .arg("--allow-host")
            .arg("example.com")
            .arg("--no-dns-check")
            .arg("list-servers");
        cmd.assert()
            .success()
            .stderr(predicate::str::contains(
                "WARNING: --allow-host is set with DNS checks disabled (--no-dns-check).",
            ))
            .stderr(
                predicate::str::contains(
                    "NOTE: enabling DNS checks because --allow-host was provided.",
                )
                .not(),
            );
    }
}
