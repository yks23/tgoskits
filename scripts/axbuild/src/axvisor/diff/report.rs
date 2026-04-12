use std::{fs, path::Path};

use anyhow::Context;
use serde::Serialize;

use crate::axvisor::diff::{
    DiffPlan, RunArtifacts, build::PreparedCaseAssets, execute::RunExecution,
};

pub(super) fn write_summary(
    path: &Path,
    plan: &DiffPlan,
    artifacts: &RunArtifacts,
    prepared_cases: &[PreparedCaseAssets],
    execution: &RunExecution,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let summary = SummaryRecord {
        plan: plan.to_summary(artifacts),
        prepared_cases: prepared_cases
            .iter()
            .map(|prepared| PreparedCaseSummary {
                id: prepared.case_id.clone(),
                asset_key: prepared.asset_key.clone(),
                package: prepared.package.clone(),
                target: prepared.target.clone(),
                build_config: prepared.build_info_path.display().to_string(),
                runtime_artifact: prepared.runtime_artifact_path.display().to_string(),
                staged_kernel_host: prepared.staged_kernel_host_path.display().to_string(),
                rendered_vm_host: prepared.rendered_vm_host_path.display().to_string(),
                guest_kernel_path: prepared.guest_kernel_path.clone(),
                guest_vm_config_path: prepared.guest_vm_config_path.clone(),
                baseline_qemu_config: prepared.baseline_qemu_config.display().to_string(),
                weak_compare_executable: prepared
                    .weak_compare_executable
                    .as_ref()
                    .map(|path| path.display().to_string()),
            })
            .collect(),
        execution,
    };
    let content = serde_json::to_string_pretty(&summary).context("failed to serialize summary")?;
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct SummaryRecord<'a> {
    plan: crate::axvisor::diff::SummaryRecord<'a>,
    prepared_cases: Vec<PreparedCaseSummary>,
    execution: &'a RunExecution,
}

#[derive(Debug, Clone, Serialize)]
struct PreparedCaseSummary {
    id: String,
    asset_key: String,
    package: String,
    target: String,
    build_config: String,
    runtime_artifact: String,
    staged_kernel_host: String,
    rendered_vm_host: String,
    guest_kernel_path: String,
    guest_vm_config_path: String,
    baseline_qemu_config: String,
    weak_compare_executable: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use tempfile::tempdir;

    use super::*;
    use crate::axvisor::diff::{
        RunArtifacts, Selection,
        build::PreparedCaseAssets,
        execute::{ComparisonRecord, GuestResult, RunExecution, SideExecutionRecord, SideOutcome},
        manifest::{CaseManifest, CompareManifest, CompareMode, LoadedCase},
    };

    #[test]
    fn write_summary_writes_json_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("summary.json");
        let plan = DiffPlan {
            arch: "aarch64".to_string(),
            guest_log: true,
            selection: Selection::Case(PathBuf::from("/tmp/case")),
            suite_name: None,
            cases: vec![LoadedCase {
                case_dir: PathBuf::from("/tmp/case"),
                manifest: CaseManifest {
                    id: "timer.basic".to_string(),
                    interface: None,
                    arch: vec!["aarch64".to_string()],
                    timeout_secs: 3,
                    compare: CompareManifest {
                        mode: CompareMode::Strong,
                        command: None,
                    },
                },
            }],
        };
        let artifacts = RunArtifacts {
            run_id: "run-1".to_string(),
            run_dir: PathBuf::from("/tmp/run-1"),
            target_rootfs: PathBuf::from("/tmp/run-1/rootfs.img"),
            summary_path: path.clone(),
        };
        let prepared = vec![PreparedCaseAssets {
            case_id: "timer.basic".to_string(),
            asset_key: "timer.basic".to_string(),
            package: "axvisor-timer-basic".to_string(),
            target: "aarch64-unknown-none-softfloat".to_string(),
            build_info_path: PathBuf::from("/tmp/case/build-aarch64.toml"),
            host_case_dir: PathBuf::from("/tmp/run-1/cases/timer.basic"),
            staged_kernel_host_path: PathBuf::from("/tmp/run-1/cases/timer.basic/kernel.bin"),
            rendered_vm_host_path: PathBuf::from("/tmp/run-1/cases/timer.basic/vm.toml"),
            guest_kernel_path: "/axdiff/images/timer.basic/kernel.bin".to_string(),
            guest_vm_config_path: "/axdiff/vm/timer.basic.toml".to_string(),
            runtime_artifact_path: PathBuf::from("/tmp/target/kernel.bin"),
            baseline_qemu_config: PathBuf::from("/tmp/case/qemu/aarch64.toml"),
            weak_compare_executable: None,
        }];
        let execution = RunExecution {
            axvisor_build_config: "/tmp/run-1/axvisor-diff-aarch64.toml".to_string(),
            axvisor_host_log: "/tmp/run-1/target-host.raw.log".to_string(),
            passed: true,
            cases: vec![crate::axvisor::diff::execute::CaseExecutionRecord {
                id: "timer.basic".to_string(),
                asset_key: "timer.basic".to_string(),
                compare_mode: "strong".to_string(),
                baseline: SideExecutionRecord {
                    raw_log_path: "/tmp/run-1/cases/timer.basic/baseline.raw.log".to_string(),
                    result_path: Some(
                        "/tmp/run-1/cases/timer.basic/baseline.result.json".to_string(),
                    ),
                    outcome: SideOutcome::GuestResult {
                        result: GuestResult {
                            case_id: "timer.basic".to_string(),
                            status: "ok".to_string(),
                            diff: serde_json::json!({"value": 1}),
                        },
                    },
                },
                target: SideExecutionRecord {
                    raw_log_path: "/tmp/run-1/cases/timer.basic/target.raw.log".to_string(),
                    result_path: Some(
                        "/tmp/run-1/cases/timer.basic/target.result.json".to_string(),
                    ),
                    outcome: SideOutcome::GuestResult {
                        result: GuestResult {
                            case_id: "timer.basic".to_string(),
                            status: "ok".to_string(),
                            diff: serde_json::json!({"value": 1}),
                        },
                    },
                },
                comparison: ComparisonRecord {
                    passed: true,
                    detail: "strong diff matched".to_string(),
                    stdout_path: None,
                    stderr_path: None,
                },
            }],
        };

        write_summary(&path, &plan, &artifacts, &prepared, &execution).unwrap();

        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains("\"run_id\": \"run-1\""));
        assert!(body.contains("\"id\": \"timer.basic\""));
        assert!(body.contains("\"passed\": true"));
    }
}
