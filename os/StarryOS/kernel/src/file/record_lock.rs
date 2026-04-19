//! POSIX / OFD byte-range record locks (`fcntl`).

use alloc::{sync::Arc, vec, vec::Vec};

use ax_errno::{AxError, AxResult};
use ax_kspin::SpinNoIrq;
use ax_sync::Mutex;
use hashbrown::HashMap;
use linux_raw_sys::general::{F_RDLCK, F_UNLCK, F_WRLCK, flock64};

use crate::task::WaitQueue;

pub type InodeKey = (u64, u64);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RLKind {
    Read,
    Write,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RLOwner {
    Posix(u32),
    Ofd(usize),
}

#[derive(Clone, Debug)]
struct Seg {
    start: u64,
    end: u64,
    kind: RLKind,
    owner: RLOwner,
}

struct RLInode {
    segs: Vec<Seg>,
    wq: WaitQueue,
}

impl RLInode {
    fn new() -> Self {
        Self {
            segs: Vec::new(),
            wq: WaitQueue::new(),
        }
    }
}

lazy_static::lazy_static! {
    static ref RECORD_INODES: SpinNoIrq<HashMap<InodeKey, Arc<Mutex<RLInode>>>> = SpinNoIrq::new(HashMap::new());
}

fn bucket(key: InodeKey) -> Arc<Mutex<RLInode>> {
    let mut g = RECORD_INODES.lock();
    g.entry(key)
        .or_insert_with(|| Arc::new(Mutex::new(RLInode::new())))
        .clone()
}

fn overlaps(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

fn conflicts_range(
    probe_kind: RLKind,
    probe_owner: RLOwner,
    range: (u64, u64),
    seg: &Seg,
) -> bool {
    if probe_owner == seg.owner || !overlaps(range, (seg.start, seg.end)) {
        return false;
    }
    matches!(
        (probe_kind, seg.kind),
        (RLKind::Write, _) | (_, RLKind::Write)
    )
}

fn merge_segments(segs: &mut Vec<Seg>) {
    if segs.is_empty() {
        return;
    }
    segs.sort_by_key(|s| s.start);
    let mut out: Vec<Seg> = Vec::new();
    for s in segs.drain(..) {
        if let Some(last) = out.last_mut()
            && last.owner == s.owner
            && last.kind == s.kind
            && last.end >= s.start
        {
            last.end = last.end.max(s.end);
        } else {
            out.push(s);
        }
    }
    *segs = out;
}

/// Remove every segment owned by `owner` overlapping `range`, then merge.
fn punch_owner_range(segs: &mut Vec<Seg>, owner: RLOwner, range: (u64, u64)) {
    let mut out = Vec::new();
    for s in segs.drain(..) {
        if s.owner != owner || !overlaps((s.start, s.end), range) {
            out.push(s);
            continue;
        }
        if s.start < range.0 {
            let mut left = s.clone();
            left.end = range.0.min(s.end);
            if left.start < left.end {
                out.push(left);
            }
        }
        if s.end > range.1 {
            let s_start = s.start;
            let mut right = s;
            right.start = range.1.max(s_start);
            if right.start < right.end {
                out.push(right);
            }
        }
    }
    *segs = out;
    merge_segments(segs);
}

fn first_conflict(
    segs: &[Seg],
    probe_kind: RLKind,
    probe_owner: RLOwner,
    range: (u64, u64),
) -> Option<Seg> {
    let mut best: Option<Seg> = None;
    for s in segs {
        if !conflicts_range(probe_kind, probe_owner, range, s) {
            continue;
        }
        let take = match &best {
            None => true,
            Some(b) => s.start < b.start,
        };
        if take {
            best = Some(s.clone());
        }
    }
    best
}

fn would_block_without_change(
    segs: &[Seg],
    probe_kind: RLKind,
    probe_owner: RLOwner,
    range: (u64, u64),
) -> bool {
    first_conflict(segs, probe_kind, probe_owner, range).is_some()
}

fn maybe_remove_bucket(key: InodeKey, b: &Arc<Mutex<RLInode>>) {
    if let Some(ino) = b.try_lock() {
        if ino.segs.is_empty() && ino.wq.is_empty() {
            drop(ino);
            let mut g = RECORD_INODES.lock();
            let should_remove = if let Some(ent) = g.get(&key) {
                if Arc::ptr_eq(ent, b)
                    && let Some(ino2) = ent.try_lock()
                    && ino2.segs.is_empty()
                    && ino2.wq.is_empty()
                {
                    drop(ino2);
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if should_remove {
                g.remove(&key);
            }
        }
    }
}

fn rl_kind_from_i16(l_type: i16) -> AxResult<Option<RLKind>> {
    Ok(match l_type as u32 {
        F_UNLCK => None,
        F_RDLCK => Some(RLKind::Read),
        F_WRLCK => Some(RLKind::Write),
        _ => return Err(AxError::InvalidInput),
    })
}

/// `F_GETLK` / `F_OFD_GETLK`: if `out.l_type` is not `F_UNLCK`, treat as probe request.
pub fn getlk(key: InodeKey, owner: RLOwner, range: (u64, u64), out: &mut flock64) -> AxResult<()> {
    let probe = rl_kind_from_i16(out.l_type)?.ok_or(AxError::InvalidInput)?;
    let b = bucket(key);
    let ino = b.lock();
    if let Some(seg) = first_conflict(&ino.segs, probe, owner, range) {
        out.l_type = match seg.kind {
            RLKind::Read => F_RDLCK as _,
            RLKind::Write => F_WRLCK as _,
        };
        out.l_whence = 0; // SEEK_SET
        out.l_start = seg.start as i64;
        out.l_len = if seg.end == u64::MAX {
            0
        } else {
            (seg.end - seg.start) as i64
        };
        out.l_pid = match seg.owner {
            RLOwner::Posix(pid) => pid as _,
            RLOwner::Ofd(_) => -1,
        };
    } else {
        out.l_type = F_UNLCK as _;
    }
    Ok(())
}

/// Apply `F_SETLK` / `F_SETLKW` / `F_OFD_SETLK` / `F_OFD_SETLKW`.
pub fn setlk(
    key: InodeKey,
    owner: RLOwner,
    range: (u64, u64),
    l_type: i16,
    blocking: bool,
) -> AxResult<()> {
    let kind = rl_kind_from_i16(l_type)?;
    let b = bucket(key);

    if kind.is_none() {
        let mut ino = b.lock();
        punch_owner_range(&mut ino.segs, owner, range);
        let woke = ino.wq.wake(usize::MAX, u32::MAX);
        drop(ino);
        if woke > 0 {
            ax_task::yield_now();
        }
        maybe_remove_bucket(key, &b);
        return Ok(());
    }
    let k = kind.unwrap();

    loop {
        let need_sleep = {
            let mut ino = b.lock();
            if !would_block_without_change(&ino.segs, k, owner, range) {
                punch_owner_range(&mut ino.segs, owner, range);
                ino.segs.push(Seg {
                    start: range.0,
                    end: range.1,
                    kind: k,
                    owner,
                });
                merge_segments(&mut ino.segs);
                let woke = ino.wq.wake(usize::MAX, u32::MAX);
                drop(ino);
                if woke > 0 {
                    ax_task::yield_now();
                }
                return Ok(());
            }
            if !blocking {
                return Err(AxError::WouldBlock);
            }
            true
        };

        if need_sleep {
            let wq_ptr = &b.lock().wq as *const WaitQueue;
            let wq = unsafe { &*wq_ptr };
            wq.wait_if(u32::MAX, None, || {
                let ino = b.lock();
                would_block_without_change(&ino.segs, k, owner, range)
            })?;
            ax_task::yield_now();
        }
    }
}

/// Drop all POSIX locks held by `pid`.
pub fn release_posix_for_pid(pid: u32) {
    let keys: Vec<InodeKey> = RECORD_INODES.lock().keys().copied().collect();
    for key in keys {
        let Some(ent) = RECORD_INODES.lock().get(&key).cloned() else {
            continue;
        };
        let mut ino = ent.lock();
        ino.segs.retain(|s| match s.owner {
            RLOwner::Posix(p) => p != pid,
            _ => true,
        });
        merge_segments(&mut ino.segs);
        let woke = ino.wq.wake(usize::MAX, u32::MAX);
        drop(ino);
        if woke > 0 {
            ax_task::yield_now();
        }
        maybe_remove_bucket(key, &ent);
    }
}

/// Drop all OFD locks for this open file description pointer.
pub fn release_ofd(ptr: usize) {
    let keys: Vec<InodeKey> = RECORD_INODES.lock().keys().copied().collect();
    for key in keys {
        let Some(ent) = RECORD_INODES.lock().get(&key).cloned() else {
            continue;
        };
        let mut ino = ent.lock();
        ino.segs.retain(|s| match s.owner {
            RLOwner::Ofd(p) => p != ptr,
            _ => true,
        });
        merge_segments(&mut ino.segs);
        let woke = ino.wq.wake(usize::MAX, u32::MAX);
        drop(ino);
        if woke > 0 {
            ax_task::yield_now();
        }
        maybe_remove_bucket(key, &ent);
    }
}
