//! Black-box integration coverage for the public Egressy CLI.

use std::{fs, process::Command};

use tempfile::NamedTempFile;

fn egressy() -> Command {
    Command::new(env!("CARGO_BIN_EXE_egressy"))
}

#[test]
fn check_accepts_the_minimal_configuration() {
    let config = NamedTempFile::new().expect("temporary config");
    fs::write(config.path(), "{}\n").expect("write config");
    let output = egressy()
        .args(["--config", config.path().to_str().unwrap(), "check"])
        .output()
        .expect("run egressy check");
    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "configuration is valid"
    );
}

#[test]
fn check_rejects_unknown_configuration_fields() {
    let config = NamedTempFile::new().expect("temporary config");
    fs::write(config.path(), "unknown_field: true\n").expect("write config");
    let output = egressy()
        .args(["--config", config.path().to_str().unwrap(), "check"])
        .output()
        .expect("run egressy check");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown field") || stderr.contains("unknown_field"),
        "{stderr}"
    );
}

#[test]
fn render_commands_preserve_fail_closed_policy_contract() {
    let config = NamedTempFile::new().expect("temporary config");
    fs::write(config.path(), "{}\n").expect("write config");
    let host = egressy()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "render-host-setup",
        ])
        .output()
        .expect("render host setup");
    assert!(host.status.success());
    let host_rules = String::from_utf8_lossy(&host.stdout);
    assert!(host_rules.contains("ip rule add priority 100 from 172.30.0.0/24 lookup 200"));
    assert!(host_rules.contains("oifname != \"br-vpn-egress\""));
    let firewall = egressy()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "render-gateway-firewall",
        ])
        .output()
        .expect("render gateway firewall");
    assert!(firewall.status.success());
    let firewall_rules = String::from_utf8_lossy(&firewall.stdout);
    assert!(firewall_rules.contains("ip saddr 172.30.0.0/24 oifname \"wg0\" accept"));
    assert!(firewall_rules.contains("ip saddr 172.30.0.0/24 oifname \"wg0\" masquerade"));
}
