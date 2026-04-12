use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use crate::{
    axvisor::{
        build::{self as axvisor_build, AxvisorBoardFile},
        context::AxvisorContext,
        diff::{
            DiffPlan, RunArtifacts,
            build::{PreparedCaseAssets, resolve_runtime_artifact_path},
            manifest::{CompareMode, LoadedCase},
            session,
        },
        qemu,
    },
    context::{AppContext, AxvisorCliArgs},
};

const HOST_BOOT_TIMEOUT_SECS: u64 = 30;
const HOST_COMMAND_TIMEOUT_SECS: u64 = 5;
const HOST_VM_CREATE_TIMEOUT_SECS: u64 = 15;
const HOST_GUEST_EXIT_GRACE_SECS: u64 = 2;
const HOST_VM_STOP_TIMEOUT_SECS: u64 = 3;
const HOST_VM_STATE_POLL_INTERVAL_MILLIS: u64 = 200;
const AXVISOR_VCPU_BOOT_DELAY_STEP_SECS: u64 = 5;
const QEMU_ROOTFS_PLACEHOLDER_OLD: &str = "${workspaceFolder}/tmp/rootfs.img";
const QEMU_ROOTFS_PLACEHOLDER_NEW: &str = "${workspaceFolder}/os/axvisor/tmp/rootfs.img";

#[derive(Debug, Clone, Serialize)]
pub(super) struct RunExecution {
    pub(crate) axvisor_build_config: String,
    pub(crate) axvisor_host_log: String,
    pub(crate) cases: Vec<CaseExecutionRecord>,
    pub(crate) passed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CaseExecutionRecord {
    pub(crate) id: String,
    pub(crate) asset_key: String,
    pub(crate) compare_mode: String,
    pub(crate) baseline: SideExecutionRecord,
    pub(crate) target: SideExecutionRecord,
    pub(crate) comparison: ComparisonRecord,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SideExecutionRecord {
    pub(crate) raw_log_path: String,
    pub(crate) result_path: Option<String>,
    pub(crate) outcome: SideOutcome,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum SideOutcome {
    GuestResult { result: GuestResult },
    RunnerError { message: String },
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct GuestResult {
    pub(crate) case_id: String,
    pub(crate) status: String,
    pub(crate) diff: Value,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ComparisonRecord {
    pub(crate) passed: bool,
    pub(crate) detail: String,
    pub(crate) stdout_path: Option<String>,
    pub(crate) stderr_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct WeakCompareInput<'a> {
    target: &'a Value,
    baseline: &'a Value,
}

#[derive(Debug, Clone, Serialize)]
struct PersistedGuestResult<'a> {
    case_id: &'a str,
    status: &'a str,
    diff: &'a Value,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GuestResultPayload {
    case_id: String,
    status: String,
    diff: Value,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct QemuConfigFile {
    args: Vec<String>,
    #[serde(default)]
    to_bin: bool,
    #[serde(default)]
    uefi: bool,
}

#[derive(Debug, Clone)]
enum HostSessionAction {
    KeepAlive,
    RestartRequired { reason: String },
}

#[derive(Debug, Clone, Copy)]
enum VmCleanupStrategy {
    GuestShouldSelfExit,
    RunnerMustStop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmLifecycleState {
    Active,
    Stopped,
    Missing,
}

#[derive(Debug, serde::Deserialize)]
struct VmListResponse {
    vms: Vec<VmListEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct VmListEntry {
    id: usize,
    state: String,
}

pub(super) async fn run(
    plan: &DiffPlan,
    app: &mut AppContext,
    ctx: &AxvisorContext,
    artifacts: &RunArtifacts,
    prepared_cases: &[PreparedCaseAssets],
) -> anyhow::Result<RunExecution> {
    if plan.cases.len() != prepared_cases.len() {
        bail!(
            "internal error: case/prepared length mismatch (cases={}, prepared={})",
            plan.cases.len(),
            prepared_cases.len()
        );
    }

    let baseline_records = run_all_baselines(plan, prepared_cases)?;
    let (target_records, axvisor_host_log, axvisor_build_config) =
        run_all_targets(plan, app, ctx, artifacts, prepared_cases).await?;

    let mut cases = Vec::with_capacity(plan.cases.len());
    let mut passed = true;

    for (((case, prepared), baseline), target) in plan
        .cases
        .iter()
        .zip(prepared_cases)
        .zip(baseline_records)
        .zip(target_records)
    {
        let comparison = compare_case(case, prepared, &baseline, &target)?;
        passed &= comparison.passed;
        cases.push(CaseExecutionRecord {
            id: case.manifest.id.clone(),
            asset_key: prepared.asset_key.clone(),
            compare_mode: case.manifest.compare.mode.as_str().to_string(),
            baseline,
            target,
            comparison,
        });
    }

    Ok(RunExecution {
        axvisor_build_config: axvisor_build_config.display().to_string(),
        axvisor_host_log: axvisor_host_log.display().to_string(),
        cases,
        passed,
    })
}

fn run_all_baselines(
    plan: &DiffPlan,
    prepared_cases: &[PreparedCaseAssets],
) -> anyhow::Result<Vec<SideExecutionRecord>> {
    let mut records = Vec::with_capacity(plan.cases.len());
    for (case, prepared) in plan.cases.iter().zip(prepared_cases) {
        records.push(run_baseline_case(case, prepared, plan.guest_log)?);
    }
    Ok(records)
}

async fn run_all_targets(
    plan: &DiffPlan,
    app: &mut AppContext,
    ctx: &AxvisorContext,
    artifacts: &RunArtifacts,
    prepared_cases: &[PreparedCaseAssets],
) -> anyhow::Result<(Vec<SideExecutionRecord>, PathBuf, PathBuf)> {
    let axvisor_build_config = write_diff_axvisor_build_config(ctx, &artifacts.run_dir, &plan.arch)
        .with_context(|| {
            format!(
                "failed to prepare diff-specific AxVisor build config for arch `{}`",
                plan.arch
            )
        })?;

    let (request, _) = app.prepare_axvisor_request(
        AxvisorCliArgs {
            config: Some(axvisor_build_config.clone()),
            arch: Some(plan.arch.clone()),
            target: None,
            plat_dyn: None,
            debug: false,
            vmconfigs: vec![],
        },
        None,
        None,
    )?;
    let cargo = axvisor_build::load_cargo_config(&request)?;
    let built = app
        .build_with_artifacts(cargo, request.build_info_path.clone())
        .await
        .context("failed to build AxVisor host for diff run")?;
    let runtime = resolve_runtime_artifact_path(&built)
        .context("AxVisor host build finished without runtime artifact")?;
    let runtime = runtime.to_path_buf();
    let qemu_config_path =
        qemu::default_qemu_config_template_path(&request.axvisor_dir, &request.arch);
    let mut session = Some(spawn_prepared_target_session(
        &request.arch,
        &runtime,
        &qemu_config_path,
        &artifacts.target_rootfs,
        plan.guest_log,
        prepared_cases,
    )?);

    let mut records = Vec::with_capacity(plan.cases.len());
    let mut host_log = String::new();
    for (index, (case, prepared)) in plan.cases.iter().zip(prepared_cases).enumerate() {
        loop {
            let (record, action) = {
                let session_ref = session
                    .as_mut()
                    .expect("target session should always exist before running a case");
                run_target_case(case, prepared, session_ref)?
            };

            match action {
                HostSessionAction::KeepAlive => {
                    records.push(record);
                    break;
                }
                HostSessionAction::RestartRequired { reason } => {
                    records.push(record);

                    let mut current = session
                        .take()
                        .expect("target session should exist when restart is requested");
                    append_session_log(
                        &mut host_log,
                        current.buffer(),
                        Some(&format!("host session restart requested: {reason}")),
                    );
                    current.terminate()?;

                    if index + 1 < plan.cases.len() {
                        session = Some(
                            spawn_prepared_target_session(
                                &request.arch,
                                &runtime,
                                &qemu_config_path,
                                &artifacts.target_rootfs,
                                plan.guest_log,
                                prepared_cases,
                            )
                            .with_context(|| {
                                format!("failed to relaunch AxVisor host after: {reason}")
                            })?,
                        );
                    }
                    break;
                }
            }
        }
    }

    let host_log_path = artifacts.run_dir.join("target-host.raw.log");
    if let Some(mut session) = session {
        append_session_log(&mut host_log, session.buffer(), None);
        session.terminate()?;
    }
    persist_text(&host_log_path, &host_log)?;

    Ok((records, host_log_path, axvisor_build_config))
}

fn run_baseline_case(
    case: &LoadedCase,
    prepared: &PreparedCaseAssets,
    guest_log: bool,
) -> anyhow::Result<SideExecutionRecord> {
    let raw_log_path = prepared.host_case_dir.join("baseline.raw.log");
    let result_path = prepared.host_case_dir.join("baseline.result.json");
    let mut session = QemuSession::spawn(
        arch_from_target(&prepared.target)?,
        &prepared.runtime_artifact_path,
        load_qemu_args(&prepared.baseline_qemu_config, None, true)?,
        guest_log,
    )?;
    let outcome = match session.wait_for_result(Duration::from_secs(case.manifest.timeout_secs)) {
        Ok(payload) => {
            let result = parse_guest_result(&payload, &case.manifest.id)?;
            persist_guest_result(&result_path, &result)?;
            SideOutcome::GuestResult { result }
        }
        Err(err) => SideOutcome::RunnerError {
            message: err.to_string(),
        },
    };
    let raw_log = session.buffer().to_string();
    let outcome = upgrade_outcome_with_runtime_failures(outcome, &raw_log);
    persist_text(&raw_log_path, &raw_log)?;
    session.terminate()?;
    Ok(SideExecutionRecord {
        raw_log_path: raw_log_path.display().to_string(),
        result_path: matches!(&outcome, SideOutcome::GuestResult { .. })
            .then(|| result_path.display().to_string()),
        outcome,
    })
}

fn run_target_case(
    case: &LoadedCase,
    prepared: &PreparedCaseAssets,
    session: &mut QemuSession,
) -> anyhow::Result<(SideExecutionRecord, HostSessionAction)> {
    let raw_log_path = prepared.host_case_dir.join("target.raw.log");
    let result_path = prepared.host_case_dir.join("target.result.json");
    let log_start = session.buffer_len();
    let cleanup_vm_id = prepared.vm_id;
    let outcome = (|| -> anyhow::Result<SideOutcome> {
        let result_mark = session.buffer_len();
        session.send_line(&session::render_vm_start_cmd(cleanup_vm_id))?;
        let _ = session
            .wait_for_prompt_after(result_mark, Duration::from_secs(HOST_COMMAND_TIMEOUT_SECS));
        let result_timeout = Duration::from_secs(
            case.manifest.timeout_secs + axvisor_vm_boot_delay_secs(cleanup_vm_id) + 1,
        );

        match session.wait_for_result_after(result_mark, result_timeout) {
            Ok(payload) => {
                let result = parse_guest_result(&payload, &case.manifest.id)?;
                persist_guest_result(&result_path, &result)?;
                Ok(SideOutcome::GuestResult { result })
            }
            Err(err) => Ok(SideOutcome::RunnerError {
                message: err.to_string(),
            }),
        }
    })()
    .unwrap_or_else(|err| SideOutcome::RunnerError {
        message: err.to_string(),
    });

    let (cleanup_message, host_action) = {
        let strategy = match &outcome {
            SideOutcome::GuestResult { .. } => VmCleanupStrategy::GuestShouldSelfExit,
            SideOutcome::RunnerError { .. } => VmCleanupStrategy::RunnerMustStop,
        };
        match cleanup_vm(session, cleanup_vm_id, strategy) {
            Ok(note) => (note, HostSessionAction::KeepAlive),
            Err(err) => (
                Some(err.to_string()),
                HostSessionAction::RestartRequired {
                    reason: format!(
                        "failed to finalize VM[{cleanup_vm_id}] for `{}`",
                        case.manifest.id
                    ),
                },
            ),
        }
    };
    let log_end = session.buffer_len();
    let mut raw_log = session.slice(log_start, log_end).to_string();
    if let Some(message) = cleanup_message {
        raw_log.push_str("\n[axdiff cleanup warning] ");
        raw_log.push_str(&message);
    }
    let outcome = upgrade_outcome_with_runtime_failures(outcome, &raw_log);
    persist_text(&raw_log_path, &raw_log)?;

    Ok((
        SideExecutionRecord {
            raw_log_path: raw_log_path.display().to_string(),
            result_path: matches!(&outcome, SideOutcome::GuestResult { .. })
                .then(|| result_path.display().to_string()),
            outcome,
        },
        host_action,
    ))
}

fn cleanup_vm(
    session: &mut QemuSession,
    vm_id: usize,
    strategy: VmCleanupStrategy,
) -> anyhow::Result<Option<String>> {
    let mut note = None;
    match strategy {
        VmCleanupStrategy::GuestShouldSelfExit => {
            match wait_for_vm_terminal_state(
                session,
                vm_id,
                Duration::from_secs(HOST_GUEST_EXIT_GRACE_SECS),
            )? {
                VmLifecycleState::Stopped | VmLifecycleState::Missing => {}
                VmLifecycleState::Active => {
                    stop_vm(session, vm_id)?;
                    note = Some(format!(
                        "guest did not stop itself within {}s; runner issued `vm stop`",
                        HOST_GUEST_EXIT_GRACE_SECS
                    ));
                    wait_for_vm_terminal_state(
                        session,
                        vm_id,
                        Duration::from_secs(HOST_VM_STOP_TIMEOUT_SECS),
                    )?;
                }
            }
        }
        VmCleanupStrategy::RunnerMustStop => {
            stop_vm(session, vm_id)?;
            wait_for_vm_terminal_state(
                session,
                vm_id,
                Duration::from_secs(HOST_VM_STOP_TIMEOUT_SECS),
            )?;
        }
    }

    if query_vm_state(session, vm_id)? != VmLifecycleState::Missing {
        delete_vm(session, vm_id)?;
    }

    Ok(note)
}

fn stop_vm(session: &mut QemuSession, vm_id: usize) -> anyhow::Result<()> {
    let stop_mark = session.buffer_len();
    session.send_line(&session::render_vm_stop_cmd(vm_id))?;
    session
        .wait_for_prompt_after(stop_mark, Duration::from_secs(HOST_COMMAND_TIMEOUT_SECS))
        .context("timed out waiting for `vm stop` prompt")?;
    Ok(())
}

fn delete_vm(session: &mut QemuSession, vm_id: usize) -> anyhow::Result<()> {
    let delete_mark = session.buffer_len();
    session.send_line(&session::render_vm_delete_cmd(vm_id))?;
    session
        .wait_for_prompt_after(delete_mark, Duration::from_secs(HOST_COMMAND_TIMEOUT_SECS))
        .context("timed out waiting for `vm delete` prompt")?;
    Ok(())
}

fn wait_for_vm_terminal_state(
    session: &mut QemuSession,
    vm_id: usize,
    timeout: Duration,
) -> anyhow::Result<VmLifecycleState> {
    let deadline = Instant::now() + timeout;
    loop {
        let state = query_vm_state(session, vm_id)?;
        if matches!(state, VmLifecycleState::Stopped | VmLifecycleState::Missing) {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            bail!(
                "VM[{vm_id}] did not reach a terminal state within {}s",
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(HOST_VM_STATE_POLL_INTERVAL_MILLIS));
    }
}

fn query_vm_state(session: &mut QemuSession, vm_id: usize) -> anyhow::Result<VmLifecycleState> {
    let mark = session.buffer_len();
    session.send_line(session::render_vm_list_json_cmd())?;
    let output = session
        .wait_for_prompt_after(mark, Duration::from_secs(HOST_COMMAND_TIMEOUT_SECS))
        .context("timed out waiting for `vm list --format json` prompt")?;
    parse_vm_state_from_vm_list_output(&output, vm_id)
}

fn parse_vm_state_from_vm_list_output(
    output: &str,
    vm_id: usize,
) -> anyhow::Result<VmLifecycleState> {
    if output.contains("No virtual machines found.") {
        return Ok(VmLifecycleState::Missing);
    }

    let json = vm_list_json_regex()
        .find_iter(output)
        .last()
        .map(|m| m.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("failed to extract JSON payload from `vm list --format json` output")
        })?;
    let parsed: VmListResponse =
        serde_json::from_str(json).context("failed to parse `vm list --format json` output")?;

    let Some(entry) = parsed.vms.into_iter().find(|entry| entry.id == vm_id) else {
        return Ok(VmLifecycleState::Missing);
    };
    let state = entry.state.to_ascii_lowercase();
    if state == "stopped" {
        Ok(VmLifecycleState::Stopped)
    } else {
        Ok(VmLifecycleState::Active)
    }
}

fn vm_list_json_regex() -> &'static Regex {
    static REGEX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"(?s)\{\s*"vms"\s*:\s*\[.*?\]\s*\}"#).unwrap())
}

fn spawn_target_session(
    arch: &str,
    runtime: &Path,
    qemu_config_path: &Path,
    rootfs: &Path,
    guest_log: bool,
) -> anyhow::Result<QemuSession> {
    let mut session = QemuSession::spawn(
        arch,
        runtime,
        load_qemu_args(qemu_config_path, Some(rootfs), false)?,
        guest_log,
    )
    .with_context(|| format!("failed to launch AxVisor host QEMU for arch `{arch}`"))?;

    session
        .wait_for_prompt(Duration::from_secs(HOST_BOOT_TIMEOUT_SECS))
        .context("AxVisor host did not reach shell prompt in time")?;
    Ok(session)
}

fn spawn_prepared_target_session(
    arch: &str,
    runtime: &Path,
    qemu_config_path: &Path,
    rootfs: &Path,
    guest_log: bool,
    prepared_cases: &[PreparedCaseAssets],
) -> anyhow::Result<QemuSession> {
    let mut session = spawn_target_session(arch, runtime, qemu_config_path, rootfs, guest_log)?;
    prepare_target_vms(&mut session, prepared_cases)?;
    Ok(session)
}

fn axvisor_vm_boot_delay_secs(vm_id: usize) -> u64 {
    vm_id.saturating_sub(1) as u64 * AXVISOR_VCPU_BOOT_DELAY_STEP_SECS
}

fn prepare_target_vms(
    session: &mut QemuSession,
    prepared_cases: &[PreparedCaseAssets],
) -> anyhow::Result<()> {
    for prepared in prepared_cases {
        let create_mark = session.buffer_len();
        session.send_line(&session::render_vm_create_cmd(Path::new(
            &prepared.guest_vm_config_path,
        )))?;
        let create_output = session
            .wait_for_prompt_after(
                create_mark,
                Duration::from_secs(HOST_VM_CREATE_TIMEOUT_SECS),
            )
            .map_err(|err| {
                err.context(format!(
                    "timed out waiting for `vm create` prompt while preparing `{}`\nrecent host \
                     output:\n{}",
                    prepared.case_id,
                    recent_output_tail(&session.buffer()[create_mark..], 24)
                ))
            })?;
        let created_ids = session::parse_created_vm_ids(&create_output);
        if !created_ids.contains(&prepared.vm_id) {
            bail!(
                "failed to observe prepared VM id {} while creating `{}`",
                prepared.vm_id,
                prepared.case_id
            );
        }
    }
    Ok(())
}

fn append_session_log(host_log: &mut String, session_log: &str, header: Option<&str>) {
    if host_log.is_empty() {
        if let Some(header) = header {
            host_log.push_str("[axdiff host note] ");
            host_log.push_str(header);
            host_log.push('\n');
        }
        host_log.push_str(session_log);
        return;
    }

    host_log.push_str("\n\n[axdiff host session boundary]\n");
    if let Some(header) = header {
        host_log.push_str("[axdiff host note] ");
        host_log.push_str(header);
        host_log.push('\n');
    }
    host_log.push_str(session_log);
}

fn recent_output_tail(output: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = output.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

fn compare_case(
    case: &LoadedCase,
    prepared: &PreparedCaseAssets,
    baseline: &SideExecutionRecord,
    target: &SideExecutionRecord,
) -> anyhow::Result<ComparisonRecord> {
    let (baseline_result, target_result) = match (&baseline.outcome, &target.outcome) {
        (
            SideOutcome::GuestResult {
                result: baseline_result,
            },
            SideOutcome::GuestResult {
                result: target_result,
            },
        ) => (baseline_result, target_result),
        _ => {
            let mut failures = Vec::new();
            if let Some(detail) = describe_non_guest_outcome("baseline", &baseline.outcome) {
                failures.push(detail);
            }
            if let Some(detail) = describe_non_guest_outcome("target", &target.outcome) {
                failures.push(detail);
            }
            return Ok(ComparisonRecord {
                passed: false,
                detail: if failures.is_empty() {
                    "baseline or target execution did not produce a guest result".to_string()
                } else {
                    failures.join("; ")
                },
                stdout_path: None,
                stderr_path: None,
            });
        }
    };

    if baseline_result.status != target_result.status {
        return Ok(ComparisonRecord {
            passed: false,
            detail: format!(
                "guest status mismatch: baseline=`{}` target=`{}`",
                baseline_result.status, target_result.status
            ),
            stdout_path: None,
            stderr_path: None,
        });
    }

    match case.manifest.compare.mode {
        CompareMode::Strong => Ok(ComparisonRecord {
            passed: baseline_result.diff == target_result.diff,
            detail: if baseline_result.diff == target_result.diff {
                "strong diff matched".to_string()
            } else {
                "strong diff mismatch".to_string()
            },
            stdout_path: None,
            stderr_path: None,
        }),
        CompareMode::Weak => run_weak_compare(case, prepared, baseline_result, target_result),
    }
}

fn describe_non_guest_outcome(side: &str, outcome: &SideOutcome) -> Option<String> {
    match outcome {
        SideOutcome::GuestResult { .. } => None,
        SideOutcome::RunnerError { message } => Some(format!("{side} execution failed: {message}")),
    }
}

fn run_weak_compare(
    case: &LoadedCase,
    prepared: &PreparedCaseAssets,
    baseline: &GuestResult,
    target: &GuestResult,
) -> anyhow::Result<ComparisonRecord> {
    let command = case
        .manifest
        .compare
        .command
        .as_ref()
        .expect("weak compare command must be present");
    let first = prepared
        .weak_compare_executable
        .as_ref()
        .cloned()
        .unwrap_or_else(|| PathBuf::from(&command[0]));
    let mut process = Command::new(first);
    process.args(&command[1..]);
    process.current_dir(&case.case_dir);
    process.stdin(Stdio::piped());
    process.stdout(Stdio::piped());
    process.stderr(Stdio::piped());

    let mut child = process.spawn().with_context(|| {
        format!(
            "failed to spawn weak compare command for case `{}`",
            case.manifest.id
        )
    })?;
    let input = serde_json::to_vec_pretty(&WeakCompareInput {
        target: &target.diff,
        baseline: &baseline.diff,
    })?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("weak compare stdin is unavailable"))?
        .write_all(&input)
        .with_context(|| {
            format!(
                "failed to write weak compare stdin for case `{}`",
                case.manifest.id
            )
        })?;
    let output = child.wait_with_output().with_context(|| {
        format!(
            "failed to wait on weak compare process for `{}`",
            case.manifest.id
        )
    })?;

    let stdout_path = prepared.host_case_dir.join("compare.stdout.log");
    let stderr_path = prepared.host_case_dir.join("compare.stderr.log");
    fs::write(&stdout_path, &output.stdout)
        .with_context(|| format!("failed to write {}", stdout_path.display()))?;
    fs::write(&stderr_path, &output.stderr)
        .with_context(|| format!("failed to write {}", stderr_path.display()))?;

    Ok(ComparisonRecord {
        passed: output.status.success(),
        detail: format!(
            "weak compare exited with {}",
            render_exit_status(output.status)
        ),
        stdout_path: Some(stdout_path.display().to_string()),
        stderr_path: Some(stderr_path.display().to_string()),
    })
}

fn parse_guest_result(payload: &str, expected_case_id: &str) -> anyhow::Result<GuestResult> {
    let parsed: GuestResultPayload =
        serde_json::from_str(payload).context("failed to parse guest result payload as JSON")?;
    if parsed.case_id != expected_case_id {
        bail!(
            "guest result case_id mismatch: expected `{expected_case_id}`, got `{}`",
            parsed.case_id
        );
    }
    Ok(GuestResult {
        case_id: parsed.case_id,
        status: parsed.status,
        diff: parsed.diff,
    })
}

fn persist_guest_result(path: &Path, result: &GuestResult) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let content = serde_json::to_string_pretty(&PersistedGuestResult {
        case_id: &result.case_id,
        status: &result.status,
        diff: &result.diff,
    })?;
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))
}

fn persist_text(path: &Path, content: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))
}

fn upgrade_outcome_with_runtime_failures(outcome: SideOutcome, raw_log: &str) -> SideOutcome {
    match outcome {
        SideOutcome::GuestResult { .. } if contains_runtime_failure(raw_log) => {
            SideOutcome::RunnerError {
                message: "runtime failure pattern detected in console log".to_string(),
            }
        }
        other => other,
    }
}

fn contains_runtime_failure(raw_log: &str) -> bool {
    runtime_failure_regex().is_match(&normalize_console_for_failure_scan(raw_log))
}

fn runtime_failure_regex() -> &'static Regex {
    static REGEX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?i)panicked?\s+at|kernel panic").unwrap())
}

fn normalize_console_for_failure_scan(raw_log: &str) -> String {
    ansi_escape_regex().replace_all(raw_log, "").into_owned()
}

fn ansi_escape_regex() -> &'static Regex {
    static REGEX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\x1b\[[0-?]*[ -/]*[@-~]").unwrap())
}

fn load_qemu_args(
    path: &Path,
    rootfs_override: Option<&Path>,
    force_tcg: bool,
) -> anyhow::Result<Vec<String>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let config: QemuConfigFile =
        toml::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))?;
    if config.uefi {
        bail!(
            "diff runner does not support UEFI QEMU configs yet: {}",
            path.display()
        );
    }

    let mut args = config.args;
    if let Some(rootfs) = rootfs_override {
        let rootfs = rootfs.display().to_string();
        for arg in &mut args {
            if arg.contains(QEMU_ROOTFS_PLACEHOLDER_OLD) {
                *arg = arg.replace(QEMU_ROOTFS_PLACEHOLDER_OLD, &rootfs);
            }
            if arg.contains(QEMU_ROOTFS_PLACEHOLDER_NEW) {
                *arg = arg.replace(QEMU_ROOTFS_PLACEHOLDER_NEW, &rootfs);
            }
        }
    }
    if force_tcg {
        force_tcg_acceleration(&mut args);
    }
    if config.to_bin { Ok(args) } else { Ok(args) }
}

fn force_tcg_acceleration(args: &mut Vec<String>) {
    for index in 0..args.len() {
        if args[index] == "-accel" && index + 1 < args.len() {
            args[index + 1] = "tcg".to_string();
            return;
        }
    }
    args.push("-accel".to_string());
    args.push("tcg".to_string());
}

fn write_diff_axvisor_build_config(
    ctx: &AxvisorContext,
    run_dir: &Path,
    arch: &str,
) -> anyhow::Result<PathBuf> {
    let board_path = ctx
        .axvisor_dir()
        .join("configs/board")
        .join(format!("qemu-{arch}.toml"));
    let mut board_file: AxvisorBoardFile = axvisor_build::load_board_file(&board_path)?;
    board_file.config.arceos.log = axvisor_build::LogLevel::Warn;
    if !board_file
        .config
        .arceos
        .features
        .iter()
        .any(|feature| feature == "fs")
    {
        board_file.config.arceos.features.push("fs".to_string());
    }
    board_file.config.arceos.features.sort();
    board_file.config.arceos.features.dedup();
    board_file.config.vm_configs.clear();

    let path = run_dir.join(format!("axvisor-diff-{arch}.toml"));
    fs::write(&path, toml::to_string_pretty(&board_file)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn arch_from_target(target: &str) -> anyhow::Result<&str> {
    if target.starts_with("aarch64-") {
        Ok("aarch64")
    } else if target.starts_with("x86_64-") {
        Ok("x86_64")
    } else if target.starts_with("riscv64") {
        Ok("riscv64")
    } else {
        bail!("unsupported target `{target}` for diff runner")
    }
}

fn qemu_binary_for_arch(arch: &str) -> anyhow::Result<&'static str> {
    match arch {
        "aarch64" => Ok("qemu-system-aarch64"),
        "x86_64" => Ok("qemu-system-x86_64"),
        "riscv64" => Ok("qemu-system-riscv64"),
        _ => bail!("unsupported diff QEMU arch `{arch}`"),
    }
}

fn render_exit_status(status: ExitStatus) -> String {
    status
        .code()
        .map(|code| format!("exit code {code}"))
        .unwrap_or_else(|| "signal".to_string())
}

struct QemuSession {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<String>,
    buffer: String,
    echo: bool,
}

impl QemuSession {
    fn spawn(arch: &str, kernel: &Path, args: Vec<String>, echo: bool) -> anyhow::Result<Self> {
        let mut command = Command::new(qemu_binary_for_arch(arch)?);
        command.arg("-kernel").arg(kernel);
        command.args(args);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command.spawn().with_context(|| {
            format!(
                "failed to spawn {} for kernel {}",
                qemu_binary_for_arch(arch).unwrap_or("qemu"),
                kernel.display()
            )
        })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to take QEMU stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to take QEMU stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to take QEMU stderr"))?;
        let (tx, rx) = mpsc::channel();
        spawn_reader(stdout, tx.clone());
        spawn_reader(stderr, tx);

        Ok(Self {
            child,
            stdin,
            rx,
            buffer: String::new(),
            echo,
        })
    }

    fn send_line(&mut self, line: &str) -> anyhow::Result<()> {
        self.stdin
            .write_all(line.as_bytes())
            .context("failed to write QEMU stdin")?;
        self.stdin
            .write_all(b"\r")
            .context("failed to write QEMU carriage return")?;
        self.stdin.flush().context("failed to flush QEMU stdin")
    }

    fn wait_for_prompt(&mut self, timeout: Duration) -> anyhow::Result<String> {
        self.wait_until(0, timeout, |slice| {
            session::contains_shell_prompt(slice).then(|| slice.to_string())
        })
    }

    fn wait_for_prompt_after(&mut self, start: usize, timeout: Duration) -> anyhow::Result<String> {
        self.wait_until(start, timeout, |slice| {
            session::contains_shell_prompt(slice).then(|| slice.to_string())
        })
    }

    fn wait_for_result(&mut self, timeout: Duration) -> anyhow::Result<String> {
        self.wait_for_result_after(0, timeout)
    }

    fn wait_for_result_after(&mut self, start: usize, timeout: Duration) -> anyhow::Result<String> {
        self.wait_until(start, timeout, session::extract_result_payload)
    }

    fn wait_until<T, F>(
        &mut self,
        start: usize,
        timeout: Duration,
        predicate: F,
    ) -> anyhow::Result<T>
    where
        F: Fn(&str) -> Option<T>,
    {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(value) = predicate(&self.buffer[start..]) {
                return Ok(value);
            }

            if let Some(status) = self.child.try_wait().context("failed to poll QEMU child")? {
                if let Some(value) = predicate(&self.buffer[start..]) {
                    return Ok(value);
                }
                bail!(
                    "QEMU exited before expected output ({})",
                    render_exit_status(status)
                );
            }

            let now = Instant::now();
            if now >= deadline {
                bail!("timed out waiting for QEMU output");
            }

            let wait = deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(100));
            match self.rx.recv_timeout(wait) {
                Ok(chunk) => self.append_chunk(&chunk),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    if let Some(status) =
                        self.child.try_wait().context("failed to poll QEMU child")?
                    {
                        if let Some(value) = predicate(&self.buffer[start..]) {
                            return Ok(value);
                        }
                        bail!(
                            "QEMU output closed before expected output ({})",
                            render_exit_status(status)
                        );
                    }
                }
            }
        }
    }

    fn append_chunk(&mut self, chunk: &str) {
        self.buffer.push_str(chunk);
        if self.echo {
            print!("{chunk}");
            let _ = std::io::stdout().flush();
        }
    }

    fn terminate(&mut self) -> anyhow::Result<()> {
        if self.child.try_wait()?.is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        Ok(())
    }

    fn buffer(&self) -> &str {
        &self.buffer
    }

    fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    fn slice(&self, start: usize, end: usize) -> &str {
        &self.buffer[start..end]
    }
}

impl Drop for QemuSession {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

fn spawn_reader<R>(mut reader: R, tx: mpsc::Sender<String>)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => {
                    let chunk = String::from_utf8_lossy(&buf[..read]).into_owned();
                    if tx.send(chunk).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn force_tcg_acceleration_rewrites_existing_accel() {
        let mut args = vec![
            "-machine".to_string(),
            "virt".to_string(),
            "-accel".to_string(),
            "kvm".to_string(),
        ];
        force_tcg_acceleration(&mut args);
        assert_eq!(args[3], "tcg");
    }

    #[test]
    fn force_tcg_acceleration_appends_when_missing() {
        let mut args = vec!["-machine".to_string(), "virt".to_string()];
        force_tcg_acceleration(&mut args);
        assert_eq!(
            args,
            vec![
                "-machine".to_string(),
                "virt".to_string(),
                "-accel".to_string(),
                "tcg".to_string()
            ]
        );
    }

    #[test]
    fn write_diff_axvisor_build_config_enables_fs_and_clears_vm_configs() {
        let dir = tempdir().unwrap();
        let axvisor_dir = dir.path().join("os/axvisor");
        fs::create_dir_all(axvisor_dir.join("configs/board")).unwrap();
        fs::write(
            axvisor_dir.join("configs/board/qemu-aarch64.toml"),
            r#"
target = "aarch64-unknown-none-softfloat"
env = { AX_IP = "10.0.2.15", AX_GW = "10.0.2.2" }
features = ["ax-std/bus-mmio"]
log = "Info"
plat_dyn = true
vm_configs = ["old.toml"]
"#,
        )
        .unwrap();
        let ctx = AxvisorContext::new_in(dir.path().to_path_buf(), axvisor_dir.clone());

        let output = write_diff_axvisor_build_config(&ctx, dir.path(), "aarch64").unwrap();
        let body = fs::read_to_string(output).unwrap();

        assert!(body.contains("\"fs\"") || body.contains("fs"));
        assert!(body.contains("vm_configs = []"));
    }

    #[test]
    fn parse_guest_result_requires_expected_case_id() {
        let err = parse_guest_result(
            r#"{"case_id":"other.case","status":"ok","diff":{"value":1}}"#,
            "expected.case",
        )
        .unwrap_err();

        assert!(err.to_string().contains("case_id mismatch"));
    }

    #[test]
    fn contains_runtime_failure_matches_ansi_prefixed_panics() {
        let raw_log = "\u{1b}[mpanicked at os/arceos/modules/axtask/src/api.rs:256:5:";
        assert!(contains_runtime_failure(raw_log));
    }

    #[test]
    fn upgrade_outcome_with_runtime_failures_downgrades_guest_result() {
        let outcome = SideOutcome::GuestResult {
            result: GuestResult {
                case_id: "cpu.currentel.read".to_string(),
                status: "ok".to_string(),
                diff: serde_json::json!({"raw": 4, "decoded_el": 1}),
            },
        };
        let upgraded = upgrade_outcome_with_runtime_failures(
            outcome,
            "\u{1b}[mpanicked at os/arceos/modules/axtask/src/api.rs:256:5:",
        );

        assert!(matches!(upgraded, SideOutcome::RunnerError { .. }));
    }

    #[test]
    fn compare_case_surfaces_runner_error_side_and_message() {
        let dir = tempdir().unwrap();
        let case = LoadedCase {
            case_dir: dir.path().join("case"),
            manifest: crate::axvisor::diff::manifest::CaseManifest {
                id: "cpu.currentel.read".to_string(),
                interface: None,
                arch: vec!["aarch64".to_string()],
                timeout_secs: 5,
                compare: crate::axvisor::diff::manifest::CompareManifest {
                    mode: CompareMode::Strong,
                    command: None,
                },
            },
        };
        let prepared = PreparedCaseAssets {
            case_id: "cpu.currentel.read".to_string(),
            asset_key: "cpu.currentel.read".to_string(),
            vm_id: 1,
            package: "axvisor-currentel-read".to_string(),
            target: "aarch64-unknown-none-softfloat".to_string(),
            build_info_path: dir.path().join("build-aarch64.toml"),
            host_case_dir: dir.path().join("host-case"),
            staged_kernel_host_path: dir.path().join("kernel.bin"),
            rendered_vm_host_path: dir.path().join("vm.toml"),
            guest_kernel_path: "/axdiff/images/cpu.currentel.read/kernel.bin".to_string(),
            guest_vm_config_path: "/axdiff/vm/cpu.currentel.read.toml".to_string(),
            runtime_artifact_path: dir.path().join("runtime.bin"),
            baseline_qemu_config: dir.path().join("qemu-aarch64.toml"),
            weak_compare_executable: None,
        };
        let baseline = SideExecutionRecord {
            raw_log_path: dir.path().join("baseline.raw.log").display().to_string(),
            result_path: Some(
                dir.path()
                    .join("baseline.result.json")
                    .display()
                    .to_string(),
            ),
            outcome: SideOutcome::GuestResult {
                result: GuestResult {
                    case_id: "cpu.currentel.read".to_string(),
                    status: "ok".to_string(),
                    diff: serde_json::json!({"raw": 4, "decoded_el": 1}),
                },
            },
        };
        let target = SideExecutionRecord {
            raw_log_path: dir.path().join("target.raw.log").display().to_string(),
            result_path: None,
            outcome: SideOutcome::RunnerError {
                message: "runtime failure pattern detected in console log".to_string(),
            },
        };

        let comparison = compare_case(&case, &prepared, &baseline, &target).unwrap();

        assert!(!comparison.passed);
        assert_eq!(
            comparison.detail,
            "target execution failed: runtime failure pattern detected in console log"
        );
    }

    #[test]
    fn parse_vm_state_from_vm_list_output_handles_stopped_and_missing() {
        let stopped = r#"
{
  "vms": [
    {
      "id": 3,
      "name": "axdiff-case",
      "state": "Stopped",
      "vcpu": 1,
      "memory": "1GB"
    }
  ]
}
axvisor:/$
"#;
        assert_eq!(
            parse_vm_state_from_vm_list_output(stopped, 3).unwrap(),
            VmLifecycleState::Stopped
        );

        let empty = "No virtual machines found.\naxvisor:/$ ";
        assert_eq!(
            parse_vm_state_from_vm_list_output(empty, 3).unwrap(),
            VmLifecycleState::Missing
        );
    }
}
