//! BSD `flock(2)` advisory locks, keyed by `(st_dev, st_ino)` and open file description.

use alloc::{sync::Arc, vec, vec::Vec};

use ax_errno::{AxError, AxResult};
use ax_kspin::SpinNoIrq;
use ax_sync::Mutex;
use ax_task::current;
use hashbrown::HashMap;

use crate::task::{AsThread, WaitQueue};

type InodeKey = (u64, u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FlockOwner {
    /// `Arc::as_ptr` of the `Arc<dyn FileLike>` for this open file description.
    desc: usize,
    pid: u32,
}

#[derive(Debug)]
enum FlockState {
    Unlocked,
    Shared(Vec<FlockOwner>),
    Exclusive(FlockOwner),
}

struct FlockInode {
    state: FlockState,
    wq: WaitQueue,
}

impl FlockInode {
    fn new() -> Self {
        Self {
            state: FlockState::Unlocked,
            wq: WaitQueue::new(),
        }
    }

    fn remove_owner(&mut self, o: FlockOwner) {
        match &mut self.state {
            FlockState::Unlocked => {}
            FlockState::Exclusive(x) if *x == o => self.state = FlockState::Unlocked,
            FlockState::Exclusive(_) => {}
            FlockState::Shared(v) => {
                v.retain(|x| *x != o);
                if v.is_empty() {
                    self.state = FlockState::Unlocked;
                }
            }
        }
    }

    /// Returns `Ok(true)` if lock granted, `Ok(false)` if caller should sleep, `Err` for `LOCK_NB`.
    fn try_lock_sh(&mut self, o: FlockOwner, nb: bool) -> AxResult<bool> {
        match &mut self.state {
            FlockState::Unlocked => {
                self.state = FlockState::Shared(vec![o]);
                Ok(true)
            }
            FlockState::Shared(v) => {
                if v.contains(&o) {
                    return Ok(true);
                }
                v.push(o);
                Ok(true)
            }
            FlockState::Exclusive(x) if *x == o => {
                self.state = FlockState::Shared(vec![o]);
                Ok(true)
            }
            FlockState::Exclusive(_) => {
                if nb {
                    Err(AxError::WouldBlock)
                } else {
                    Ok(false)
                }
            }
        }
    }

    fn try_lock_ex(&mut self, o: FlockOwner, nb: bool) -> AxResult<bool> {
        match &mut self.state {
            FlockState::Unlocked => {
                self.state = FlockState::Exclusive(o);
                Ok(true)
            }
            FlockState::Exclusive(x) if *x == o => Ok(true),
            FlockState::Exclusive(_) => {
                if nb {
                    Err(AxError::WouldBlock)
                } else {
                    Ok(false)
                }
            }
            FlockState::Shared(v) => {
                if v.len() == 1 && v[0] == o {
                    self.state = FlockState::Exclusive(o);
                    Ok(true)
                } else if v.is_empty() {
                    self.state = FlockState::Exclusive(o);
                    Ok(true)
                } else {
                    if nb {
                        Err(AxError::WouldBlock)
                    } else {
                        Ok(false)
                    }
                }
            }
        }
    }

    fn needs_block_sh(&self, o: FlockOwner) -> bool {
        matches!(&self.state, FlockState::Exclusive(x) if *x != o)
    }

    fn needs_block_ex(&self, o: FlockOwner) -> bool {
        match &self.state {
            FlockState::Unlocked => false,
            FlockState::Exclusive(x) => *x != o,
            FlockState::Shared(v) => !(v.len() == 1 && v[0] == o),
        }
    }
}

lazy_static::lazy_static! {
    static ref FLOCK_INODES: SpinNoIrq<HashMap<InodeKey, Arc<Mutex<FlockInode>>>> = SpinNoIrq::new(HashMap::new());
}

fn bucket(key: InodeKey) -> Arc<Mutex<FlockInode>> {
    let mut g = FLOCK_INODES.lock();
    g.entry(key)
        .or_insert_with(|| Arc::new(Mutex::new(FlockInode::new())))
        .clone()
}

fn maybe_remove_bucket(key: InodeKey, b: &Arc<Mutex<FlockInode>>) {
    if let Some(ino) = b.try_lock() {
        if matches!(ino.state, FlockState::Unlocked) && ino.wq.is_empty() {
            drop(ino);
            let mut g = FLOCK_INODES.lock();
            let should_remove = if let Some(ent) = g.get(&key) {
                if Arc::ptr_eq(ent, b)
                    && let Some(ino2) = ent.try_lock()
                    && matches!(ino2.state, FlockState::Unlocked)
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

/// Called from `close_file_like` when the last `Arc` reference to this file is about to be dropped.
pub fn on_last_file_ref_drop(st: (u64, u64), file: &Arc<dyn super::FileLike>) {
    let owner = FlockOwner {
        desc: Arc::as_ptr(file) as *const () as usize,
        pid: current().as_thread().proc_data.proc.pid(),
    };
    let key = st;
    let bucket = FLOCK_INODES.lock().get(&key).cloned();
    if let Some(b) = bucket {
        let mut ino = b.lock();
        ino.remove_owner(owner);
        let woke = ino.wq.wake(usize::MAX, u32::MAX);
        drop(ino);
        if woke > 0 {
            ax_task::yield_now();
        }
        maybe_remove_bucket(key, &b);
    }
}

/// Release every flock held by `pid` (last-resort cleanup on process exit).
pub fn release_all_for_pid(pid: u32) {
    let keys: Vec<InodeKey> = FLOCK_INODES.lock().keys().copied().collect();
    for key in keys {
        let Some(bucket) = FLOCK_INODES.lock().get(&key).cloned() else {
            continue;
        };
        let mut ino = bucket.lock();
        match &mut ino.state {
            FlockState::Unlocked => {}
            FlockState::Exclusive(x) if x.pid == pid => {
                ino.state = FlockState::Unlocked;
            }
            FlockState::Exclusive(_) => {}
            FlockState::Shared(v) => {
                v.retain(|o| o.pid != pid);
                if v.is_empty() {
                    ino.state = FlockState::Unlocked;
                }
            }
        }
        let woke = ino.wq.wake(usize::MAX, u32::MAX);
        drop(ino);
        if woke > 0 {
            ax_task::yield_now();
        }
        maybe_remove_bucket(key, &bucket);
    }
}

/// Apply `flock(2)` for a regular file.
pub fn flock_inode(
    st: (u64, u64),
    file: &Arc<dyn super::FileLike>,
    operation: i32,
) -> AxResult<()> {
    let op = operation as u32;
    const LOCK_SH: u32 = linux_raw_sys::general::LOCK_SH;
    const LOCK_EX: u32 = linux_raw_sys::general::LOCK_EX;
    const LOCK_UN: u32 = linux_raw_sys::general::LOCK_UN;
    const LOCK_NB: u32 = linux_raw_sys::general::LOCK_NB;

    let nb = op & LOCK_NB != 0;
    let owner = FlockOwner {
        desc: Arc::as_ptr(file) as *const () as usize,
        pid: current().as_thread().proc_data.proc.pid(),
    };
    let key = st;
    let bucket = bucket(key);

    if op & LOCK_UN != 0 {
        let mut ino = bucket.lock();
        ino.remove_owner(owner);
        let woke = ino.wq.wake(usize::MAX, u32::MAX);
        drop(ino);
        if woke > 0 {
            ax_task::yield_now();
        }
        maybe_remove_bucket(key, &bucket);
        return Ok(());
    }

    let want_ex = op & LOCK_EX != 0;
    let want_sh = op & LOCK_SH != 0;
    if !want_ex && !want_sh {
        return Err(AxError::InvalidInput);
    }

    loop {
        let got = {
            let mut ino = bucket.lock();
            if want_ex {
                ino.try_lock_ex(owner, nb)?
            } else {
                ino.try_lock_sh(owner, nb)?
            }
        };
        if got {
            return Ok(());
        }
        let wq_ptr = {
            let ino = bucket.lock();
            let wait = if want_ex {
                ino.needs_block_ex(owner)
            } else {
                ino.needs_block_sh(owner)
            };
            let ptr = &ino.wq as *const WaitQueue;
            (wait, ptr)
        };
        if !wq_ptr.0 {
            continue;
        }
        // SAFETY: `bucket` keeps `FlockInode` alive; we do not remove it while sleeping.
        let wq = unsafe { &*wq_ptr.1 };
        wq.wait_if(u32::MAX, None, || {
            let ino = bucket.lock();
            if want_ex {
                ino.needs_block_ex(owner)
            } else {
                ino.needs_block_sh(owner)
            }
        })?;
        ax_task::yield_now();
    }
}
