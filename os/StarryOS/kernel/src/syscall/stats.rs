//! Per-raw-syscall invocation counters (see `/proc/syscall_stats`).
//!
//! 每次进入 `handle_syscall` 时同步更新：
//! - 按号桶 `COUNTERS`（供完整 `cat /proc/syscall_stats`）
//! - 4KiB 对齐 **SHM 页**（`total` + `last_sysno`），供 `/dev/syscall_stats_mm` mmap：
//!   **内核在 syscall 入口主动更新，用户态可直接 volatile 读内存**。

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt::Write as _,
    sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering, Ordering::Relaxed},
};

use ax_hal::{
    mem::{PhysAddrRange, VirtAddr, virt_to_phys},
    time::monotonic_time_nanos,
};
use ax_sync::Mutex;
use ax_task::{AxTaskRef, current};
use syscalls::Sysno;

use crate::task::{AsThread, tasks, try_tasks};

pub const SYSCALL_STATS_SLOTS: usize = 520;
const OVERFLOW_IDX: usize = 519;
const TRACE_RING_CAP: usize = 256;
const DEEP_RING_CAP: usize = 384;
const INFLIGHT_CAP: usize = 512;
const TASK_SYSCALL_CAP: usize = 64;
const TASK_TOP_SYSCALLS: usize = 8;
const TASK_WINDOW_NS: u64 = 5_000_000_000;
const TASK_NAME_MAX: usize = 16;
const SIGNAL_SLOTS: usize = 32; // signo 1..31 + margin
const ERRNO_HISTOGRAM_SLOTS: usize = 128; // errno 1..127

/// 与 mmap 页布局一致，用户态可按 `u64` + `u32` + `u32` 解析前 16 字节。
#[repr(C, align(4096))]
struct SyscallStatsShm {
    total: AtomicU64,
    last_sysno: AtomicU32,
    _pad: u32,
    _reserved: [u8; 4096 - 16],
}

static SYSCALL_STATS_SHM: SyscallStatsShm = SyscallStatsShm {
    total: AtomicU64::new(0),
    last_sysno: AtomicU32::new(0),
    _pad: 0,
    _reserved: [0; 4096 - 16],
};

static COUNTERS: [AtomicU64; SYSCALL_STATS_SLOTS] =
    [const { AtomicU64::new(0) }; SYSCALL_STATS_SLOTS];
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static SNAPSHOT_ENABLED: AtomicBool = AtomicBool::new(false);
static DEEP_TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE_SEQ: AtomicU64 = AtomicU64::new(0);
static DEEP_SEQ: AtomicU64 = AtomicU64::new(0);
static DEEP_PATH_SEQ: AtomicU64 = AtomicU64::new(0);
static TASK_SAMPLE_SEQ: AtomicU64 = AtomicU64::new(0);
static DEEP_TIMER_LAST_SEC: AtomicU64 = AtomicU64::new(0);
static DEEP_TIMER_SNAPSHOT_LAST_SEC: AtomicU64 = AtomicU64::new(0);
// ── Error counters ── per-syscall error count + errno histogram
static ERROR_COUNTERS: [AtomicU64; SYSCALL_STATS_SLOTS] =
    [const { AtomicU64::new(0) }; SYSCALL_STATS_SLOTS];
static ERRNO_HISTOGRAM: [AtomicU64; ERRNO_HISTOGRAM_SLOTS] =
    [const { AtomicU64::new(0) }; ERRNO_HISTOGRAM_SLOTS];
static TOTAL_ERRORS: AtomicU64 = AtomicU64::new(0);
static LAST_ERROR_NR: AtomicU32 = AtomicU32::new(0);
static LAST_ERROR_RET: AtomicI64 = AtomicI64::new(0);

// ── Page fault counters ──
static PF_TOTAL: AtomicU64 = AtomicU64::new(0);
static PF_HANDLED: AtomicU64 = AtomicU64::new(0);
static PF_SIGSEGV: AtomicU64 = AtomicU64::new(0);

// ── Signal delivery counters ── indexed by signo (1-based)
static SIGNAL_COUNTERS: [AtomicU64; SIGNAL_SLOTS] =
    [const { AtomicU64::new(0) }; SIGNAL_SLOTS];

// ── Syscall latency: per-syscall total_ns and invocation count (for avg) ──
static LATENCY_TOTAL_NS: [AtomicU64; SYSCALL_STATS_SLOTS] =
    [const { AtomicU64::new(0) }; SYSCALL_STATS_SLOTS];
static LATENCY_COUNT: [AtomicU64; SYSCALL_STATS_SLOTS] =
    [const { AtomicU64::new(0) }; SYSCALL_STATS_SLOTS];
static LATENCY_MAX_NS: [AtomicU64; SYSCALL_STATS_SLOTS] =
    [const { AtomicU64::new(0) }; SYSCALL_STATS_SLOTS];

static TRACE_RING: Mutex<Vec<SyscallTraceEvent>> = Mutex::new(Vec::new());
static DEEP_RING: Mutex<Vec<DeepTraceEvent>> = Mutex::new(Vec::new());
static INFLIGHT: Mutex<Vec<SyscallInflight>> = Mutex::new(Vec::new());
static TASK_SYSCALLS: Mutex<Vec<TaskSyscallWindow>> = Mutex::new(Vec::new());

#[derive(Clone, Copy)]
enum SyscallTracePhase {
    Enter,
    Exit,
}

#[derive(Clone, Copy)]
struct TaskIdent {
    cpu: usize,
    pid: u32,
    tid: u64,
    name: [u8; TASK_NAME_MAX],
}

#[derive(Clone, Copy)]
struct SyscallTraceEvent {
    seq: u64,
    ts_ns: u64,
    task: TaskIdent,
    nr: u32,
    args: [usize; 6],
    ret: isize,
    phase: SyscallTracePhase,
}

#[derive(Clone, Copy)]
struct SyscallInflight {
    seq: u64,
    enter_ts_ns: u64,
    task: TaskIdent,
    nr: u32,
    args: [usize; 6],
}

#[derive(Clone)]
struct DeepTraceEvent {
    seq: u64,
    ts_ns: u64,
    task: TaskIdent,
    category: &'static str,
    detail: String,
}

#[derive(Clone, Copy, Default)]
struct TaskSyscallTop {
    nr: u32,
    count: u64,
}

#[derive(Clone)]
struct TaskSyscallWindow {
    window_start_ns: u64,
    task: TaskIdent,
    total: u64,
    top: [TaskSyscallTop; TASK_TOP_SYSCALLS],
}

/// 物理连续 4KiB，供 `/dev/syscall_stats_mm` mmap；内核在每次 syscall 入口更新。
pub fn syscall_stats_shm_phys_range() -> PhysAddrRange {
    let va = VirtAddr::from_usize(core::ptr::addr_of!(SYSCALL_STATS_SHM) as usize);
    PhysAddrRange::from_start_size(virt_to_phys(va), 4096)
}

#[inline]
pub fn total_invocations() -> u64 {
    SYSCALL_STATS_SHM.total.load(Relaxed)
}

#[inline]
pub fn last_raw_sysno() -> u32 {
    SYSCALL_STATS_SHM.last_sysno.load(Relaxed)
}

pub fn record_raw_syscall(nr: u32) {
    let idx = if nr >= SYSCALL_STATS_SLOTS as u32 {
        OVERFLOW_IDX
    } else {
        nr as usize
    };
    COUNTERS[idx].fetch_add(1, Relaxed);
    SYSCALL_STATS_SHM.total.fetch_add(1, Relaxed);
    SYSCALL_STATS_SHM.last_sysno.store(nr, Relaxed);
}

/// Record a syscall error: increments per-syscall error counter + errno histogram.
/// Called after `record_syscall_exit` when `retval < 0`.
pub fn record_syscall_error(nr: u32, retval: isize) {
    let idx = if nr >= SYSCALL_STATS_SLOTS as u32 {
        OVERFLOW_IDX
    } else {
        nr as usize
    };
    ERROR_COUNTERS[idx].fetch_add(1, Relaxed);
    TOTAL_ERRORS.fetch_add(1, Relaxed);
    LAST_ERROR_NR.store(nr, Relaxed);
    LAST_ERROR_RET.store(retval as i64, Relaxed);
    // errno = -retval (Linux convention: retval = -errno on error)
    let errno = (-retval) as usize;
    if errno > 0 && errno < ERRNO_HISTOGRAM_SLOTS {
        ERRNO_HISTOGRAM[errno].fetch_add(1, Relaxed);
    }
}

/// Record page fault. `handled` = true if resolved, false if SIGSEGV sent.
pub fn record_page_fault(handled: bool) {
    PF_TOTAL.fetch_add(1, Relaxed);
    if handled {
        PF_HANDLED.fetch_add(1, Relaxed);
    } else {
        PF_SIGSEGV.fetch_add(1, Relaxed);
    }
}

/// Record signal delivery. `signo` is 1-based (SIGSEGV=11, SIGBUS=7, etc.).
pub fn record_signal_delivery(signo: u32) {
    let idx = signo as usize;
    if idx > 0 && idx < SIGNAL_SLOTS {
        SIGNAL_COUNTERS[idx].fetch_add(1, Relaxed);
    }
}

/// Record syscall latency (exit timestamp - enter timestamp).
/// Called from `record_syscall_exit` when snapshot mode captured an enter_ts.
pub fn record_syscall_latency(nr: u32, elapsed_ns: u64) {
    let idx = if nr >= SYSCALL_STATS_SLOTS as u32 {
        OVERFLOW_IDX
    } else {
        nr as usize
    };
    LATENCY_TOTAL_NS[idx].fetch_add(elapsed_ns, Relaxed);
    LATENCY_COUNT[idx].fetch_add(1, Relaxed);
    // Update max with CAS loop
    let mut cur = LATENCY_MAX_NS[idx].load(Relaxed);
    while elapsed_ns > cur {
        match LATENCY_MAX_NS[idx].compare_exchange_weak(cur, elapsed_ns, Relaxed, Relaxed) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }
}

#[inline]
pub fn trace_enabled() -> bool {
    TRACE_ENABLED.load(Relaxed)
}

pub fn set_trace_enabled(enabled: bool) {
    TRACE_ENABLED.store(enabled, Relaxed);
}

pub fn format_trace_control() -> &'static str {
    if trace_enabled() { "1\n" } else { "0\n" }
}

pub fn write_trace_control(data: &[u8]) -> bool {
    match core::str::from_utf8(data).map(|s| s.trim()) {
        Ok("") => true,
        Ok("1" | "on" | "true" | "enable" | "enabled") => {
            set_trace_enabled(true);
            true
        }
        Ok("0" | "off" | "false" | "disable" | "disabled") => {
            set_trace_enabled(false);
            true
        }
        _ => false,
    }
}

#[inline]
pub fn snapshot_enabled() -> bool {
    SNAPSHOT_ENABLED.load(Relaxed)
}

pub fn set_snapshot_enabled(enabled: bool) {
    SNAPSHOT_ENABLED.store(enabled, Relaxed);
}

pub fn format_snapshot_control() -> &'static str {
    if snapshot_enabled() { "1\n" } else { "0\n" }
}

pub fn write_snapshot_control(data: &[u8]) -> bool {
    match core::str::from_utf8(data).map(|s| s.trim()) {
        Ok("") => true,
        Ok("1" | "on" | "true" | "enable" | "enabled") => {
            set_snapshot_enabled(true);
            true
        }
        Ok("0" | "off" | "false" | "disable" | "disabled") => {
            set_snapshot_enabled(false);
            true
        }
        _ => false,
    }
}

#[inline]
pub fn deep_trace_enabled() -> bool {
    DEEP_TRACE_ENABLED.load(Relaxed)
}

pub fn set_deep_trace_enabled(enabled: bool) {
    DEEP_TRACE_ENABLED.store(enabled, Relaxed);
}

pub fn format_deep_trace_control() -> &'static str {
    if deep_trace_enabled() { "1\n" } else { "0\n" }
}

pub fn write_deep_trace_control(data: &[u8]) -> bool {
    match core::str::from_utf8(data).map(|s| s.trim()) {
        Ok("") => true,
        Ok("1" | "on" | "true" | "enable" | "enabled") => {
            set_deep_trace_enabled(true);
            true
        }
        Ok("0" | "off" | "false" | "disable" | "disabled") => {
            set_deep_trace_enabled(false);
            true
        }
        _ => false,
    }
}

fn current_task_ident() -> TaskIdent {
    let curr = current();
    let mut name = [0; TASK_NAME_MAX];
    let task_name = curr.name();
    let bytes = task_name.as_bytes();
    let copy_len = bytes.len().min(TASK_NAME_MAX);
    name[..copy_len].copy_from_slice(&bytes[..copy_len]);

    TaskIdent {
        cpu: curr.cpu_id() as usize,
        pid: curr.as_thread().proc_data.proc.pid(),
        tid: curr.id().as_u64(),
        name,
    }
}

fn task_name(name: &[u8; TASK_NAME_MAX]) -> &str {
    let len = name.iter().position(|b| *b == 0).unwrap_or(TASK_NAME_MAX);
    core::str::from_utf8(&name[..len]).unwrap_or("?")
}

fn syscall_name(nr: u32) -> String {
    Sysno::new(nr as _)
        .map(|sysno| format!("{sysno:?}"))
        .unwrap_or_else(|| "invalid".to_string())
}

fn record_task_syscall(task: TaskIdent, nr: u32, ts_ns: u64) {
    let Some(mut windows) = TASK_SYSCALLS.try_lock() else {
        return;
    };
    let slot = if let Some(pos) = windows.iter().position(|slot| slot.task.tid == task.tid) {
        &mut windows[pos]
    } else {
        if windows.len() == TASK_SYSCALL_CAP {
            windows.remove(0);
        }
        windows.push(TaskSyscallWindow {
            window_start_ns: ts_ns,
            task,
            total: 0,
            top: [TaskSyscallTop::default(); TASK_TOP_SYSCALLS],
        });
        windows.last_mut().unwrap()
    };
    if ts_ns.saturating_sub(slot.window_start_ns) > TASK_WINDOW_NS {
        slot.window_start_ns = ts_ns;
        slot.task = task;
        slot.total = 0;
        slot.top = [TaskSyscallTop::default(); TASK_TOP_SYSCALLS];
    }
    slot.task = task;
    slot.total = slot.total.saturating_add(1);
    if let Some(existing) = slot
        .top
        .iter_mut()
        .find(|item| item.count != 0 && item.nr == nr)
    {
        existing.count = existing.count.saturating_add(1);
        return;
    }
    if let Some(empty) = slot.top.iter_mut().find(|item| item.count == 0) {
        *empty = TaskSyscallTop { nr, count: 1 };
        return;
    }
    if let Some(min) = slot.top.iter_mut().min_by_key(|item| item.count) {
        *min = TaskSyscallTop { nr, count: 1 };
    }
}

fn push_trace_event(event: SyscallTraceEvent) {
    let Some(mut ring) = TRACE_RING.try_lock() else {
        return;
    };
    if ring.len() == TRACE_RING_CAP {
        ring.remove(0);
    }
    ring.push(event);
}

pub fn record_syscall_enter(nr: u32, args: [usize; 6]) {
    let snapshot = snapshot_enabled();
    let deep = deep_trace_enabled();
    if !snapshot && !deep {
        return;
    }
    if !snapshot {
        if TASK_SAMPLE_SEQ.fetch_add(1, Relaxed).is_multiple_of(64) {
            record_task_syscall(current_task_ident(), nr, monotonic_time_nanos());
        }
        return;
    }

    let seq = TRACE_SEQ.fetch_add(1, Relaxed).wrapping_add(1);
    let ts_ns = monotonic_time_nanos();
    let task = current_task_ident();
    record_task_syscall(task, nr, ts_ns);
    if !snapshot_enabled() {
        return;
    }
    let event = SyscallTraceEvent {
        seq,
        ts_ns,
        task,
        nr,
        args,
        ret: 0,
        phase: SyscallTracePhase::Enter,
    };
    push_trace_event(event);

    let Some(mut inflight) = INFLIGHT.try_lock() else {
        return;
    };
    if let Some(slot) = inflight.iter_mut().find(|slot| slot.task.tid == task.tid) {
        *slot = SyscallInflight {
            seq,
            enter_ts_ns: ts_ns,
            task,
            nr,
            args,
        };
    } else {
        if inflight.len() == INFLIGHT_CAP {
            inflight.remove(0);
        }
        inflight.push(SyscallInflight {
            seq,
            enter_ts_ns: ts_ns,
            task,
            nr,
            args,
        });
    }
}

pub fn record_deep_event(category: &'static str, args: core::fmt::Arguments<'_>) {
    if !deep_trace_enabled() {
        return;
    }
    if category == "path" && !DEEP_PATH_SEQ.fetch_add(1, Relaxed).is_multiple_of(64) {
        return;
    }
    let mut detail = String::new();
    let _ = detail.write_fmt(args);
    let event = DeepTraceEvent {
        seq: DEEP_SEQ.fetch_add(1, Relaxed).wrapping_add(1),
        ts_ns: monotonic_time_nanos(),
        task: current_task_ident(),
        category,
        detail,
    };
    let Some(mut ring) = DEEP_RING.try_lock() else {
        return;
    };
    if ring.len() == DEEP_RING_CAP {
        ring.remove(0);
    }
    ring.push(event);
}

pub fn record_syscall_exit(nr: u32, retval: isize) {
    // Record error if negative return
    if retval < 0 {
        record_syscall_error(nr, retval);
    }

    if !snapshot_enabled() {
        return;
    }

    let now_ns = monotonic_time_nanos();
    let task = current_task_ident();
    let (args, enter_ts_ns) = {
        if let Some(mut inflight) = INFLIGHT.try_lock() {
            inflight
                .iter()
                .position(|slot| slot.task.tid == task.tid)
                .map(|pos| {
                    let entry = inflight.remove(pos);
                    (entry.args, Some(entry.enter_ts_ns))
                })
                .unwrap_or(([0; 6], None))
        } else {
            ([0; 6], None)
        }
    };
    // Track latency even without snapshot (using inflight enter_ts from enter path)
    if let Some(enter_ts) = enter_ts_ns {
        let elapsed = now_ns.saturating_sub(enter_ts);
        record_syscall_latency(nr, elapsed);
    }
    let event = SyscallTraceEvent {
        seq: TRACE_SEQ.fetch_add(1, Relaxed).wrapping_add(1),
        ts_ns: now_ns,
        task,
        nr,
        args,
        ret: retval,
        phase: SyscallTracePhase::Exit,
    };
    push_trace_event(event);
}

fn format_args(args: &[usize; 6]) -> String {
    format!(
        "[{:#x},{:#x},{:#x},{:#x},{:#x},{:#x}]",
        args[0], args[1], args[2], args[3], args[4], args[5]
    )
}

fn format_trace_event(event: &SyscallTraceEvent, out: &mut String) {
    let phase = match event.phase {
        SyscallTracePhase::Enter => "enter",
        SyscallTracePhase::Exit => "exit",
    };
    let ret = match event.phase {
        SyscallTracePhase::Enter => "-".to_string(),
        SyscallTracePhase::Exit => event.ret.to_string(),
    };
    let _ = writeln!(
        out,
        "seq={} ts_ns={} cpu={} pid={} tid={} task={} phase={} nr={} name={} args={} ret={}",
        event.seq,
        event.ts_ns,
        event.task.cpu,
        event.task.pid,
        event.task.tid,
        task_name(&event.task.name),
        phase,
        event.nr,
        syscall_name(event.nr),
        format_args(&event.args),
        ret,
    );
}

pub fn format_trace_recent_text() -> String {
    let mut out = format!(
        "enabled {} cap {} total_seq {}\n",
        snapshot_enabled() as u8,
        TRACE_RING_CAP,
        TRACE_SEQ.load(Relaxed)
    );
    let Some(ring) = TRACE_RING.try_lock() else {
        let _ = writeln!(out, "busy");
        return out;
    };
    for event in ring.iter() {
        format_trace_event(event, &mut out);
    }
    out
}

pub fn format_deep_trace_recent_text() -> String {
    let mut out = format!(
        "enabled {} cap {} total_seq {}\n",
        deep_trace_enabled() as u8,
        DEEP_RING_CAP,
        DEEP_SEQ.load(Relaxed)
    );
    let Some(ring) = DEEP_RING.try_lock() else {
        let _ = writeln!(out, "busy");
        return out;
    };
    for event in ring.iter() {
        let _ = writeln!(
            out,
            "seq={} ts_ns={} cpu={} pid={} tid={} task={} category={} detail={}",
            event.seq,
            event.ts_ns,
            event.task.cpu,
            event.task.pid,
            event.task.tid,
            task_name(&event.task.name),
            event.category,
            event.detail,
        );
    }
    out
}

fn format_task_rate(tid: u64, now: u64) -> String {
    let Some(windows) = TASK_SYSCALLS.try_lock() else {
        return "busy".to_string();
    };
    let Some(window) = windows.iter().find(|window| window.task.tid == tid) else {
        return "-".to_string();
    };
    let age_ns = now.saturating_sub(window.window_start_ns).max(1);
    let mut tops = window
        .top
        .iter()
        .copied()
        .filter(|item| item.count != 0)
        .collect::<Vec<_>>();
    tops.sort_by_key(|item| core::cmp::Reverse(item.count));
    let mut text = format!(
        "window_ms={} total={} rate_per_s={}",
        age_ns / 1_000_000,
        window.total,
        window.total.saturating_mul(1_000_000_000) / age_ns,
    );
    for item in tops {
        let _ = write!(
            text,
            ",{}:{}={}",
            item.nr,
            syscall_name(item.nr),
            item.count
        );
    }
    text
}

pub fn format_inflight_text() -> String {
    let now = monotonic_time_nanos();
    let Some(inflight) = INFLIGHT.try_lock() else {
        return format!("enabled {} count busy\n", snapshot_enabled() as u8);
    };
    let mut out = format!(
        "enabled {} count {}\n",
        snapshot_enabled() as u8,
        inflight.len()
    );
    for item in inflight.iter() {
        let _ = writeln!(
            out,
            "seq={} age_ns={} enter_ts_ns={} cpu={} pid={} tid={} task={} nr={} name={} args={}",
            item.seq,
            now.saturating_sub(item.enter_ts_ns),
            item.enter_ts_ns,
            item.task.cpu,
            item.task.pid,
            item.task.tid,
            task_name(&item.task.name),
            item.nr,
            syscall_name(item.nr),
            format_args(&item.args),
        );
    }
    out
}

pub fn format_task_snapshot_text() -> String {
    let inflight = INFLIGHT
        .try_lock()
        .map(|inflight| inflight.clone())
        .unwrap_or_default();
    let ring = TRACE_RING
        .try_lock()
        .map(|ring| ring.clone())
        .unwrap_or_default();
    let now = monotonic_time_nanos();
    let mut out = String::from(
        "pid tid cpu state task user_pc user_sp user_ra user_tp inflight last_syscall \
         recent_rate\n",
    );
    for task in tasks() {
        let Some(thread) = task.try_as_thread() else {
            continue;
        };
        let user_regs = thread.user_regs_snapshot();
        let tid = task.id().as_u64();
        let inflight_syscall = inflight
            .iter()
            .rev()
            .find(|item| item.task.tid == tid)
            .map(|item| format!("{}:{}", item.nr, syscall_name(item.nr)))
            .unwrap_or_else(|| "-".to_string());
        let last_syscall = ring
            .iter()
            .rev()
            .find(|event| event.task.tid == tid)
            .map(|event| {
                let phase = match event.phase {
                    SyscallTracePhase::Enter => "enter",
                    SyscallTracePhase::Exit => "exit",
                };
                format!("{}:{}:{phase}", event.nr, syscall_name(event.nr))
            })
            .unwrap_or_else(|| "-".to_string());
        let _ = writeln!(
            out,
            "{} {} {} {:?} {} {:#x} {:#x} {:#x} {:#x} {} {} {}",
            thread.proc_data.proc.pid(),
            tid,
            task.cpu_id(),
            task.state(),
            task.name(),
            user_regs.pc,
            user_regs.sp,
            user_regs.ra,
            user_regs.tp,
            inflight_syscall,
            last_syscall,
            format_task_rate(tid, now),
        );
    }
    out
}

fn format_task_block_snapshot_for(task_list: Vec<AxTaskRef>) -> String {
    let now = monotonic_time_nanos();
    let inflight = INFLIGHT
        .try_lock()
        .map(|inflight| inflight.clone())
        .unwrap_or_default();
    let ring = TRACE_RING
        .try_lock()
        .map(|ring| ring.clone())
        .unwrap_or_default();
    let mut out = String::from(
        "pid tid cpu state task user_pc user_sp user_ra user_tp reason inflight_age_ns \
         last_syscall recent_rate\n",
    );
    for task in task_list {
        let Some(thread) = task.try_as_thread() else {
            continue;
        };
        let user_regs = thread.user_regs_snapshot();
        let tid = task.id().as_u64();
        let inflight_item = inflight.iter().rev().find(|item| item.task.tid == tid);
        let (reason, age_ns) = if let Some(item) = inflight_item {
            (
                format!("in_syscall:{}:{}", item.nr, syscall_name(item.nr)),
                now.saturating_sub(item.enter_ts_ns),
            )
        } else {
            ("-".to_string(), 0)
        };
        let last_syscall = ring
            .iter()
            .rev()
            .find(|event| event.task.tid == tid)
            .map(|event| {
                let phase = match event.phase {
                    SyscallTracePhase::Enter => "enter",
                    SyscallTracePhase::Exit => "exit",
                };
                format!("{}:{}:{phase}", event.nr, syscall_name(event.nr))
            })
            .unwrap_or_else(|| "-".to_string());
        let _ = writeln!(
            out,
            "{} {} {} {:?} {} {:#x} {:#x} {:#x} {:#x} {} {} {} {}",
            thread.proc_data.proc.pid(),
            tid,
            task.cpu_id(),
            task.state(),
            task.name(),
            user_regs.pc,
            user_regs.sp,
            user_regs.ra,
            user_regs.tp,
            reason,
            age_ns,
            last_syscall,
            format_task_rate(tid, now),
        );
    }
    out
}

pub fn format_task_block_snapshot_text() -> String {
    format_task_block_snapshot_for(tasks())
}

pub fn record_deep_timer_tick(now_sec: u64) {
    if !deep_trace_enabled() {
        return;
    }
    if DEEP_TIMER_LAST_SEC.swap(now_sec, Ordering::Relaxed) == now_sec {
        return;
    }
    let curr = current();
    let (pid, tid) = curr
        .try_as_thread()
        .map(|thread| (thread.proc_data.proc.pid(), curr.id().as_u64()))
        .unwrap_or((0, curr.id().as_u64()));
    warn!(
        "deep_timer_sample sec={} cpu={} pid={} tid={} task={} state={:?} total_syscalls={} \
         last_sysno={} deep_seq={}",
        now_sec,
        curr.cpu_id(),
        pid,
        tid,
        curr.name(),
        curr.state(),
        total_invocations(),
        last_raw_sysno(),
        DEEP_SEQ.load(Relaxed),
    );
    if now_sec.is_multiple_of(30)
        && DEEP_TIMER_SNAPSHOT_LAST_SEC.swap(now_sec, Ordering::Relaxed) != now_sec
    {
        if let Some(task_list) = try_tasks() {
            for line in format_task_block_snapshot_for(task_list).lines().take(32) {
                warn!("deep_task_snapshot {}", line);
            }
        } else {
            warn!("deep_task_snapshot busy");
        }
    }
}

pub fn trace_syscall(nr: u32, name: impl core::fmt::Debug, retval: isize) {
    if !trace_enabled() {
        return;
    }
    let curr = current();
    let tid = curr.id().as_u64();
    let pid = curr.as_thread().proc_data.proc.pid();
    info!("syscall_trace pid={pid} tid={tid} nr={nr} name={name:?} ret={retval}");
}

pub fn reset_stats() {
    for c in &COUNTERS {
        c.store(0, Relaxed);
    }
    for c in &ERROR_COUNTERS {
        c.store(0, Relaxed);
    }
    for c in &ERRNO_HISTOGRAM {
        c.store(0, Relaxed);
    }
    for c in &SIGNAL_COUNTERS {
        c.store(0, Relaxed);
    }
    for c in &LATENCY_TOTAL_NS {
        c.store(0, Relaxed);
    }
    for c in &LATENCY_COUNT {
        c.store(0, Relaxed);
    }
    for c in &LATENCY_MAX_NS {
        c.store(0, Relaxed);
    }
    SYSCALL_STATS_SHM.total.store(0, Relaxed);
    SYSCALL_STATS_SHM.last_sysno.store(0, Relaxed);
    TOTAL_ERRORS.store(0, Relaxed);
    LAST_ERROR_NR.store(0, Relaxed);
    LAST_ERROR_RET.store(0, Relaxed);
    PF_TOTAL.store(0, Relaxed);
    PF_HANDLED.store(0, Relaxed);
    PF_SIGSEGV.store(0, Relaxed);
}

pub fn format_stats_text() -> String {
    let total = SYSCALL_STATS_SHM.total.load(Relaxed);
    let mut body = String::new();
    for i in 0..SYSCALL_STATS_SLOTS {
        let c = COUNTERS[i].load(Relaxed);
        if c > 0 {
            let _ = writeln!(body, "{i} {c}");
        }
    }
    format!("total {total}\n{body}")
}

/// 仅一行十进制 total，供高频轮询（避免格式化整表）。
pub fn format_stats_total_line() -> String {
    format!("{}\n", SYSCALL_STATS_SHM.total.load(Relaxed))
}

/// Format per-syscall error counts + errno histogram.
pub fn format_error_stats_text() -> String {
    let total_errors = TOTAL_ERRORS.load(Relaxed);
    let last_nr = LAST_ERROR_NR.load(Relaxed);
    let last_ret = LAST_ERROR_RET.load(Relaxed);
    let mut body = format!("total_errors {total_errors}\nlast_error_nr {last_nr} last_error_ret {last_ret}\n");
    // Per-syscall errors (only non-zero)
    for i in 0..SYSCALL_STATS_SLOTS {
        let c = ERROR_COUNTERS[i].load(Relaxed);
        if c > 0 {
            let _ = writeln!(body, "errors {i} {} {}", c, syscall_name(i as u32));
        }
    }
    // Errno histogram (only non-zero)
    body.push_str("errno_histogram\n");
    for i in 1..ERRNO_HISTOGRAM_SLOTS {
        let c = ERRNO_HISTOGRAM[i].load(Relaxed);
        if c > 0 {
            let name = linux_errno_name(i as i32);
            let _ = writeln!(body, "  errno {i} ({name}) count {c}");
        }
    }
    body
}

/// Format page fault statistics.
pub fn format_page_fault_stats_text() -> String {
    let total = PF_TOTAL.load(Relaxed);
    let handled = PF_HANDLED.load(Relaxed);
    let sigsegv = PF_SIGSEGV.load(Relaxed);
    format!("total {total}\nhandled {handled}\nsigsegv {sigsegv}\n")
}

/// Format signal delivery statistics.
pub fn format_signal_stats_text() -> String {
    let mut body = String::new();
    for i in 1..SIGNAL_SLOTS {
        let c = SIGNAL_COUNTERS[i].load(Relaxed);
        if c > 0 {
            let name = signal_name(i as u32);
            let _ = writeln!(body, "signal {i} ({name}) count {c}");
        }
    }
    if body.is_empty() {
        body.push_str("(no signals delivered)\n");
    }
    body
}

/// Format per-syscall latency summary (avg_ns, max_ns for non-zero entries).
pub fn format_latency_stats_text() -> String {
    let mut body = String::new();
    for i in 0..SYSCALL_STATS_SLOTS {
        let count = LATENCY_COUNT[i].load(Relaxed);
        if count > 0 {
            let total_ns = LATENCY_TOTAL_NS[i].load(Relaxed);
            let max_ns = LATENCY_MAX_NS[i].load(Relaxed);
            let avg_ns = total_ns / count;
            let _ = writeln!(
                body,
                "latency {} {} avg_ns={avg_ns} max_ns={max_ns} total_ns={total_ns} {}",
                i,
                count,
                syscall_name(i as u32),
            );
        }
    }
    if body.is_empty() {
        body.push_str("(no latency data)\n");
    }
    body
}

/// Combined diagnostic summary — one-shot dump of all counters.
pub fn format_diagnostic_summary() -> String {
    let mut out = String::new();
    let total = SYSCALL_STATS_SHM.total.load(Relaxed);
    let total_errors = TOTAL_ERRORS.load(Relaxed);
    let pf_total = PF_TOTAL.load(Relaxed);
    let pf_handled = PF_HANDLED.load(Relaxed);
    let pf_sigsegv = PF_SIGSEGV.load(Relaxed);
    let _ = writeln!(out, "===DIAGNOSTIC_SUMMARY===");
    let _ = writeln!(out, "syscalls_total {total}");
    let _ = writeln!(out, "syscalls_errors {total_errors}");
    let _ = writeln!(out, "page_faults_total {pf_total} handled {pf_handled} sigsegv {pf_sigsegv}");
    // Top-10 syscalls by count
    let mut top: Vec<(usize, u64)> = (0..SYSCALL_STATS_SLOTS)
        .map(|i| (i, COUNTERS[i].load(Relaxed)))
        .filter(|(_, c)| *c > 0)
        .collect();
    top.sort_by_key(|(_, c)| core::cmp::Reverse(*c));
    out.push_str("top_syscalls");
    for (nr, count) in top.iter().take(10) {
        let _ = write!(out, " {}:{count}", syscall_name(*nr as u32));
    }
    out.push('\n');
    // Top-10 syscalls by error count
    let mut top_err: Vec<(usize, u64)> = (0..SYSCALL_STATS_SLOTS)
        .map(|i| (i, ERROR_COUNTERS[i].load(Relaxed)))
        .filter(|(_, c)| *c > 0)
        .collect();
    top_err.sort_by_key(|(_, c)| core::cmp::Reverse(*c));
    if !top_err.is_empty() {
        out.push_str("top_errors");
        for (nr, count) in top_err.iter().take(10) {
            let _ = write!(out, " {}:{count}", syscall_name(*nr as u32));
        }
        out.push('\n');
    }
    // Top-5 slowest syscalls by avg latency
    let mut top_lat: Vec<(usize, u64, u64)> = (0..SYSCALL_STATS_SLOTS)
        .filter_map(|i| {
            let count = LATENCY_COUNT[i].load(Relaxed);
            if count > 0 {
                let total_ns = LATENCY_TOTAL_NS[i].load(Relaxed);
                Some((i, total_ns / count, LATENCY_MAX_NS[i].load(Relaxed)))
            } else {
                None
            }
        })
        .collect();
    top_lat.sort_by_key(|(_, avg, _)| core::cmp::Reverse(*avg));
    if !top_lat.is_empty() {
        out.push_str("slowest_syscalls");
        for (nr, avg, max) in top_lat.iter().take(5) {
            let _ = write!(out, " {}:avg={avg}ns/max={max}ns", syscall_name(*nr as u32));
        }
        out.push('\n');
    }
    // Top errno
    let mut top_errno: Vec<(usize, u64)> = (1..ERRNO_HISTOGRAM_SLOTS)
        .map(|i| (i, ERRNO_HISTOGRAM[i].load(Relaxed)))
        .filter(|(_, c)| *c > 0)
        .collect();
    top_errno.sort_by_key(|(_, c)| core::cmp::Reverse(*c));
    if !top_errno.is_empty() {
        out.push_str("top_errno");
        for (errno, count) in top_errno.iter().take(5) {
            let name = linux_errno_name(*errno as i32);
            let _ = write!(out, " {name}:{count}");
        }
        out.push('\n');
    }
    // Non-zero signals
    let sigs: Vec<(usize, u64)> = (1..SIGNAL_SLOTS)
        .map(|i| (i, SIGNAL_COUNTERS[i].load(Relaxed)))
        .filter(|(_, c)| *c > 0)
        .collect();
    if !sigs.is_empty() {
        out.push_str("signals");
        for (signo, count) in &sigs {
            let _ = write!(out, " {}:{count}", signal_name(*signo as u32));
        }
        out.push('\n');
    }
    out.push_str("===DIAGNOSTIC_SUMMARY_END===\n");
    out
}

fn linux_errno_name(errno: i32) -> &'static str {
    match errno {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
        6 => "ENXIO",
        7 => "E2BIG",
        8 => "ENOEXEC",
        9 => "EBADF",
        10 => "ECHILD",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        16 => "EBUSY",
        17 => "EEXIST",
        18 => "EXDEV",
        19 => "ENODEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        25 => "ENOTTY",
        27 => "EFBIG",
        28 => "ENOSPC",
        29 => "ESPIPE",
        30 => "EROFS",
        31 => "EMLINK",
        32 => "EPIPE",
        33 => "EDOM",
        34 => "ERANGE",
        35 => "EDEADLK",
        36 => "ENAMETOOLONG",
        38 => "ENOSYS",
        39 => "ENOTEMPTY",
        40 => "ELOOP",
        42 => "ENOMSG",
        60 => "ENOSR",
        61 => "ETIME",
        62 => "ETIMEDOUT",
        88 => "ENOTSOCK",
        93 => "EPROTONOSUPPORT",
        95 => "EOPNOTSUPP",
        98 => "EADDRINUSE",
        99 => "EADDRNOTAVAIL",
        104 => "ECONNRESET",
        105 => "EISCONN",
        106 => "ENOTCONN",
        110 => "ETIMEDOUT_CONN",
        111 => "ECONNREFUSED",
        112 => "EHOSTDOWN",
        113 => "EHOSTUNREACH",
        _ => "UNKNOWN",
    }
}

fn signal_name(signo: u32) -> &'static str {
    match signo {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        16 => "SIGSTKFLT",
        17 => "SIGCHLD",
        18 => "SIGCONT",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        21 => "SIGTTIN",
        22 => "SIGTTOU",
        23 => "SIGURG",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        26 => "SIGVTALRM",
        27 => "SIGPROF",
        28 => "SIGWINCH",
        29 => "SIGIO",
        31 => "SIGSYS",
        _ => "SIG?",
    }
}
