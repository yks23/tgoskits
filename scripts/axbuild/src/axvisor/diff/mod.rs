use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Serialize;

use crate::{
    axvisor::{cli::ArgsTestDiff, context::AxvisorContext},
    context::AppContext,
};

pub(crate) mod build;
pub(crate) mod execute;
pub(crate) mod manifest;
pub(crate) mod report;
pub(crate) mod rootfs;
pub(crate) mod session;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Selection {
    Suite(PathBuf),
    Case(PathBuf),
}

#[derive(Debug, Clone)]
pub(super) struct RunArtifacts {
    pub(super) run_id: String,
    pub(super) run_dir: PathBuf,
    pub(super) target_rootfs: PathBuf,
    pub(super) summary_path: PathBuf,
}

#[derive(Debug, Clone)]
pub(super) struct DiffPlan {
    pub(super) arch: String,
    pub(super) guest_log: bool,
    pub(super) selection: Selection,
    pub(super) suite_name: Option<String>,
    pub(super) cases: Vec<manifest::LoadedCase>,
}

pub(crate) async fn run(
    args: ArgsTestDiff,
    app: &mut AppContext,
    ctx: &AxvisorContext,
) -> anyhow::Result<()> {
    let plan = DiffPlan::from_args(args, ctx.workspace_root())?;
    let layouts = build::resolve_case_layouts(&plan.cases, &plan.arch)?;
    let artifacts = rootfs::prepare_run_artifacts(ctx, &plan.arch).await?;
    let prepared_cases =
        build::build_and_stage_cases(app, ctx, &plan.cases, &layouts, &artifacts, &plan.arch)
            .await?;
    let execution = execute::run(&plan, app, ctx, &artifacts, &prepared_cases).await?;

    report::write_summary(
        &artifacts.summary_path,
        &plan,
        &artifacts,
        &prepared_cases,
        &execution,
    )?;

    match &plan.selection {
        Selection::Suite(path) => {
            let suite_name = plan.suite_name.as_deref().unwrap_or("<unnamed>");
            println!(
                "validated axvisor diff suite: {} (arch={}, guest_log={}, cases={})",
                suite_name,
                plan.arch,
                plan.guest_log,
                plan.cases.len()
            );
            println!("suite manifest: {}", path.display());
        }
        Selection::Case(path) => {
            println!(
                "validated axvisor diff case run (arch={}, guest_log={}, cases={})",
                plan.arch,
                plan.guest_log,
                plan.cases.len()
            );
            println!("case dir: {}", path.display());
        }
    }

    for case in &plan.cases {
        println!(
            "- {} [{}] timeout={}s @ {}",
            case.manifest.id,
            case.manifest.compare.mode.as_str(),
            case.manifest.timeout_secs,
            case.case_dir.display()
        );
    }
    for (layout, prepared) in layouts.iter().zip(&prepared_cases) {
        println!(
            "  assets: vm_template={} baseline_qemu={}",
            layout.vm_template.display(),
            prepared.baseline_qemu_config.display()
        );
        println!(
            "    staged: case_id={} asset_key={} package={} target={} build_config={} case_dir={} \
             runtime={} kernel_host={} vm_host={} vm_guest={} kernel_guest={} weak_compare={}",
            prepared.case_id,
            prepared.asset_key,
            prepared.package,
            prepared.target,
            prepared.build_info_path.display(),
            prepared.host_case_dir.display(),
            prepared.runtime_artifact_path.display(),
            prepared.staged_kernel_host_path.display(),
            prepared.rendered_vm_host_path.display(),
            prepared.guest_vm_config_path,
            prepared.guest_kernel_path,
            prepared
                .weak_compare_executable
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "-".to_string())
        );
    }

    println!("run id: {}", artifacts.run_id);
    println!("run dir: {}", artifacts.run_dir.display());
    println!("target rootfs: {}", artifacts.target_rootfs.display());
    println!("summary: {}", artifacts.summary_path.display());
    println!("axvisor build config: {}", execution.axvisor_build_config);
    println!("host log: {}", execution.axvisor_host_log);

    let passed = execution
        .cases
        .iter()
        .filter(|record| record.comparison.passed)
        .count();
    let total = execution.cases.len();
    println!("diff result: {passed}/{total} case(s) passed");
    for record in &execution.cases {
        let status = if record.comparison.passed {
            "PASS"
        } else {
            "FAIL"
        };
        println!("  {} {}: {}", status, record.id, record.comparison.detail);
    }

    if execution.passed {
        Ok(())
    } else {
        bail!("axvisor diff run failed; see summary for details")
    }
}

impl DiffPlan {
    fn from_args(args: ArgsTestDiff, workspace_root: &Path) -> anyhow::Result<Self> {
        let arch = args.arch;
        let selection = if let Some(path) = args.suite {
            Selection::Suite(resolve_cli_path(workspace_root, &path))
        } else if let Some(path) = args.case {
            Selection::Case(resolve_cli_path(workspace_root, &path))
        } else {
            unreachable!("clap ensures either --suite or --case is present");
        };

        let guest_log = args
            .guest_log
            .unwrap_or(matches!(selection, Selection::Case(_)));

        let (suite_name, cases) = match &selection {
            Selection::Suite(path) => {
                let (suite, cases) = manifest::load_cases_from_suite(workspace_root, path, &arch)
                    .with_context(|| {
                    format!("failed to load diff suite manifest {}", path.display())
                })?;
                (Some(suite.name), cases)
            }
            Selection::Case(path) => (None, {
                let case = manifest::load_case_from_dir(path)
                    .with_context(|| format!("failed to load diff case from {}", path.display()))?;
                manifest::ensure_case_supports_arch(&case, &arch)?;
                vec![case]
            }),
        };

        Ok(Self {
            arch,
            guest_log,
            selection,
            suite_name,
            cases,
        })
    }
}

fn resolve_cli_path(workspace_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root.join(path)
    }
}

impl Selection {
    fn kind(&self) -> &'static str {
        match self {
            Self::Suite(_) => "suite",
            Self::Case(_) => "case",
        }
    }

    fn path(&self) -> &Path {
        match self {
            Self::Suite(path) | Self::Case(path) => path.as_path(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct SummaryCaseRecord<'a> {
    id: &'a str,
    case_dir: String,
    timeout_secs: u64,
    compare_mode: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct SummarySelectionRecord<'a> {
    kind: &'a str,
    path: String,
    suite_name: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
struct SummaryRecord<'a> {
    run_id: &'a str,
    arch: &'a str,
    guest_log: bool,
    run_dir: String,
    target_rootfs: String,
    selection: SummarySelectionRecord<'a>,
    cases: Vec<SummaryCaseRecord<'a>>,
}

impl DiffPlan {
    fn to_summary<'a>(&'a self, artifacts: &'a RunArtifacts) -> SummaryRecord<'a> {
        SummaryRecord {
            run_id: &artifacts.run_id,
            arch: &self.arch,
            guest_log: self.guest_log,
            run_dir: artifacts.run_dir.display().to_string(),
            target_rootfs: artifacts.target_rootfs.display().to_string(),
            selection: SummarySelectionRecord {
                kind: self.selection.kind(),
                path: self.selection.path().display().to_string(),
                suite_name: self.suite_name.as_deref(),
            },
            cases: self
                .cases
                .iter()
                .map(|case| SummaryCaseRecord {
                    id: &case.manifest.id,
                    case_dir: case.case_dir.display().to_string(),
                    timeout_secs: case.manifest.timeout_secs,
                    compare_mode: case.manifest.compare.mode.as_str(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::Value;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn diff_plan_defaults_guest_log_true_for_single_case() {
        let dir = tempdir().unwrap();
        let workspace_root = dir.path();
        let suite_root = workspace_root.join("test-suit/axvisor/cpu-state/tlb");
        fs::create_dir_all(&suite_root).unwrap();
        fs::write(
            suite_root.join("case.toml"),
            r#"
id = "cpu.tlb"
arch = ["aarch64"]
timeout_secs = 5

[compare]
mode = "strong"
"#,
        )
        .unwrap();

        let args = ArgsTestDiff {
            arch: "aarch64".to_string(),
            suite: None,
            case: Some(PathBuf::from("test-suit/axvisor/cpu-state/tlb")),
            guest_log: None,
        };

        let plan = DiffPlan::from_args(args, workspace_root).unwrap();
        assert!(plan.guest_log);
        assert_eq!(plan.cases.len(), 1);
    }

    #[test]
    fn diff_plan_defaults_guest_log_false_for_suite() {
        let dir = tempdir().unwrap();
        let workspace_root = dir.path();
        let case_dir = workspace_root.join("test-suit/axvisor/cpu-state/tlb");
        fs::create_dir_all(&case_dir).unwrap();
        fs::write(
            case_dir.join("case.toml"),
            r#"
id = "cpu.tlb"
arch = ["aarch64"]
timeout_secs = 5

[compare]
mode = "strong"
"#,
        )
        .unwrap();

        let suite_dir = workspace_root.join("test-suit/axvisor/suites");
        fs::create_dir_all(&suite_dir).unwrap();
        fs::write(
            suite_dir.join("smoke.toml"),
            r#"
name = "smoke"

[arches.aarch64]
cases = ["cpu-state/tlb"]
"#,
        )
        .unwrap();

        let args = ArgsTestDiff {
            arch: "aarch64".to_string(),
            suite: Some(PathBuf::from("test-suit/axvisor/suites/smoke.toml")),
            case: None,
            guest_log: None,
        };

        let plan = DiffPlan::from_args(args, workspace_root).unwrap();
        assert!(!plan.guest_log);
        assert_eq!(plan.suite_name.as_deref(), Some("smoke"));
        assert_eq!(plan.cases.len(), 1);
    }

    #[test]
    fn diff_plan_summary_contains_selection_and_case_metadata() {
        let plan = DiffPlan {
            arch: "aarch64".to_string(),
            guest_log: false,
            selection: Selection::Case(PathBuf::from("/tmp/case")),
            suite_name: None,
            cases: vec![manifest::LoadedCase {
                case_dir: PathBuf::from("/tmp/case"),
                manifest: manifest::CaseManifest {
                    id: "cpu.tlb".to_string(),
                    interface: Some("tlb".to_string()),
                    arch: vec!["aarch64".to_string()],
                    timeout_secs: 7,
                    compare: manifest::CompareManifest {
                        mode: manifest::CompareMode::Strong,
                        command: None,
                    },
                },
            }],
        };
        let artifacts = RunArtifacts {
            run_id: "run-1".to_string(),
            run_dir: PathBuf::from("/tmp/run-1"),
            target_rootfs: PathBuf::from("/tmp/run-1/rootfs.img"),
            summary_path: PathBuf::from("/tmp/run-1/summary.json"),
        };

        let summary = serde_json::to_value(plan.to_summary(&artifacts)).unwrap();
        assert_eq!(summary["run_id"], Value::String("run-1".to_string()));
        assert_eq!(
            summary["selection"]["kind"],
            Value::String("case".to_string())
        );
        assert_eq!(
            summary["cases"][0]["id"],
            Value::String("cpu.tlb".to_string())
        );
        assert_eq!(summary["cases"][0]["timeout_secs"], Value::from(7u64));
    }
}
