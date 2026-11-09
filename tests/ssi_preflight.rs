use anyhow::{Context, Result};
use serde_json::Value;
use sshpool::ssi::{self, Peer, Probe};

fn evidence() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "../docs/evidence/ssi-physical-preflight-20261107.json"
    ))?)
}

fn peers(label: &str) -> Result<Vec<Peer>> {
    let evidence = evidence()?;
    let row = evidence["runs"]
        .as_array()
        .context("missing runs")?
        .iter()
        .find(|row| row["label"] == label)
        .context("missing case")?;
    Ok(serde_json::from_value(row["report"]["peers"].clone())?)
}

#[test]
fn actual_kvm_frequencies_allow_control_and_refuse_physical_candidate() -> Result<()> {
    let control = ssi::assess(peers("esxi-control-final")?);
    assert!(control.native_tsc_precheck_passed);
    assert!(!control.running_clock_verified);
    assert!(!control.physical_topology_verified);
    assert!(!control.full_ssi_accepted);
    let cross = ssi::assess(peers("cross-physical-final")?);
    assert!(!cross.native_tsc_precheck_passed);
    assert_eq!(cross.blockers.len(), 1);
    assert!(cross.blockers[0].contains("[2095147, 2394374]"));
    for row in evidence()?["runs"].as_array().context("runs")? {
        let actual = ssi::assess(serde_json::from_value(row["report"]["peers"].clone())?);
        assert_eq!(serde_json::to_value(&actual)?, row["report"]);
        assert_eq!(
            row["exit"],
            if actual.native_tsc_precheck_passed {
                0
            } else {
                2
            }
        );
    }
    Ok(())
}

#[test]
fn scaling_capability_is_not_a_frequency_conversion_implementation() -> Result<()> {
    let mut cross = peers("cross-physical-final")?;
    for peer in &mut cross {
        peer.probe.as_mut().context("probe")?.tsc_control = 1;
    }
    assert!(!ssi::assess(cross).native_tsc_precheck_passed);
    Ok(())
}

#[test]
fn reinstalled_esxi_candidate_retains_actual_frequency_rejection() -> Result<()> {
    let evidence: Value = serde_json::from_str(include_str!(
        "../docs/evidence/ssi-tsc-frequency-candidate-20261109.json"
    ))?;
    let run = &evidence["preflight"];
    let report = ssi::assess(serde_json::from_value(run["report"]["peers"].clone())?);
    assert_eq!(serde_json::to_value(&report)?, run["report"]);
    assert_eq!(run["exit"], 2);
    assert!(!report.native_tsc_precheck_passed);
    assert_eq!(report.blockers.len(), 1);
    assert!(report.blockers[0].contains("[2095148, 2394374]"));
    let candidate = report.peers[1].probe.as_ref().context("candidate probe")?;
    assert_eq!(
        candidate.machine_id_sha256,
        evidence["identity_audits"]["after_reboot"]["machine"]
            .as_str()
            .context("candidate identity")?
    );
    Ok(())
}

#[test]
fn inconsistent_local_vcpu_frequencies_also_fail() -> Result<()> {
    let mut data = peers("esxi-control-final")?;
    data[0].probe.as_mut().context("probe")?.vcpus[1].tsc_khz += 1;
    assert!(!ssi::assess(data).native_tsc_precheck_passed);
    Ok(())
}

#[test]
fn incomplete_cleanup_capabilities_and_samples_cannot_pass() -> Result<()> {
    let changes: &[fn(&mut Probe)] = &[
        |p| p.closed_fds = 3,
        |p| p.errors.push("close interrupted".into()),
        |p| p.vcpus.clear(),
        |p| p.vcpus[1].index = 0,
        |p| p.vcpus[0].tsc_khz = 0,
        |p| p.vcpus[0].offset_supported = false,
        |p| p.tsc_adjust = false,
        |p| p.get_tsc_khz = 0,
        |p| p.adjust_clock = 0,
        |p| p.api_version = 11,
        |p| p.arch = "aarch64".into(),
        |p| p.system = "Darwin".into(),
        |p| p.machine_id_sha256.clear(),
        |p| p.memory_bytes = 0,
        |p| p.schema = 2,
    ];
    for change in changes {
        let mut data = peers("esxi-control-final")?;
        change(data[0].probe.as_mut().context("probe")?);
        assert!(!ssi::assess(data).native_tsc_precheck_passed);
    }
    let mut missing = peers("esxi-control-final")?;
    missing[0].probe = None;
    assert!(!ssi::assess(missing).native_tsc_precheck_passed);
    assert!(!ssi::assess(Vec::new()).native_tsc_precheck_passed);
    Ok(())
}

#[test]
fn duplicate_alias_and_failed_peer_stay_in_the_decision() -> Result<()> {
    for label in ["duplicate-alias-final", "unreachable-final"] {
        let decision = ssi::assess(peers(label)?);
        assert!(!decision.native_tsc_precheck_passed);
        assert_eq!(decision.peers.len(), 2);
        assert!(!decision.blockers.is_empty());
    }
    Ok(())
}

#[test]
fn missing_schema_fields_do_not_become_success_defaults() -> Result<()> {
    let data = peers("esxi-control-final")?;
    let mut value = serde_json::to_value(data[0].probe.as_ref().context("probe")?)?;
    value
        .as_object_mut()
        .context("object")?
        .remove("closed_fds");
    assert!(serde_json::from_value::<Probe>(value).is_err());
    Ok(())
}

#[tokio::test]
async fn invalid_targets_are_rejected_before_any_ssh_operation() {
    for targets in [
        vec![],
        vec!["one".into()],
        vec!["same".into(), "same".into()],
        vec!["-oProxyCommand=command".into(), "two".into()],
        vec!["one; command".into(), "two".into()],
    ] {
        assert!(ssi::preflight(&targets, None).await.is_err());
    }
}

#[test]
fn cli_preflight_rejects_invalid_input_without_initializing_a_workspace() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let home = temp.path().join("must-not-be-created");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sshpool"))
        .arg("--home")
        .arg(&home)
        .args(["ssi-preflight", "one; command", "two"])
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(!home.exists());
    Ok(())
}
