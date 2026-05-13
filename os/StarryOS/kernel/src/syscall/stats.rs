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
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering, Ordering::Relaxed},
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
    if !snapshot_enabled() {
        return;
    }

    let task = current_task_ident();
    let args = {
        if let Some(mut inflight) = INFLIGHT.try_lock() {
            inflight
                .iter()
                .position(|slot| slot.task.tid == task.tid)
                .map(|pos| inflight.remove(pos).args)
                .unwrap_or([0; 6])
        } else {
            [0; 6]
        }
    };
    let event = SyscallTraceEvent {
        seq: TRACE_SEQ.fetch_add(1, Relaxed).wrapping_add(1),
        ts_ns: monotonic_time_nanos(),
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
    SYSCALL_STATS_SHM.total.store(0, Relaxed);
    SYSCALL_STATS_SHM.last_sysno.store(0, Relaxed);
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
