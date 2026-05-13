//! Futex implementation.

use alloc::{
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    future::poll_fn,
    ops::Deref,
    sync::atomic::{AtomicBool, Ordering},
    task::{Poll, Waker},
    time::Duration,
};

use ax_errno::AxResult;
use ax_kspin::SpinNoIrq;
use ax_memory_addr::VirtAddr;
use ax_sync::Mutex;
use ax_task::{
    current,
    future::{self, block_on, interruptible},
};
use hashbrown::HashMap;

use crate::{
    mm::{AddrSpace, Backend, SharedPages},
    task::AsThread,
};

/// Wait queue used by futex.
#[derive(Default)]
pub struct WaitQueue {
    queue: SpinNoIrq<VecDeque<(Waker, u32, Arc<AtomicBool>)>>,
}
impl WaitQueue {
    /// Creates a new `WaitQueue`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Waits if the given condition is met.
    ///
    /// Returns `false` if the condition is not met and no actual waiting
    /// occurs.
    ///
    /// **Important:** `condition` must **not** be evaluated while holding
    /// `self.queue`'s [`SpinNoIrq`] lock: callers often take blocking
    /// [`ax_sync::Mutex`] inside the closure (e.g. record/flock paths). Doing
    /// that with IRQs disabled would trip `ax_task::WaitQueue::wait_until` /
    /// `might_sleep` panics.
    pub fn wait_if(
        &self,
        bitset: u32,
        timeout: Option<Duration>,
        mut condition: impl FnMut() -> bool,
    ) -> AxResult<bool> {
        if !condition() {
            return Ok(false);
        }
        let mut armed = false;
        let woken = Arc::new(AtomicBool::new(false));
        let result = block_on(interruptible(future::timeout(
            timeout,
            poll_fn(|cx| {
                if armed {
                    if woken.load(Ordering::Acquire) {
                        return Poll::Ready(Ok(true));
                    }
                    // Re-check outside the futex queue lock (see module doc).
                    if !condition() {
                        return Poll::Ready(Ok(false));
                    }
                    return Poll::Pending;
                }
                if !condition() {
                    return Poll::Ready(Ok(false));
                }
                {
                    let mut queue = self.queue.lock();
                    queue.push_back((cx.waker().clone(), bitset, woken.clone()));
                }
                armed = true;
                if woken.load(Ordering::Acquire) {
                    return Poll::Ready(Ok(true));
                }
                if !condition() {
                    self.remove_waiter(&woken);
                    return Poll::Ready(Ok(false));
                }
                Poll::Pending
            }),
        )));

        match result {
            Ok(Ok(waited)) => waited,
            Ok(Err(err)) => {
                self.remove_waiter(&woken);
                Err(err.into())
            }
            Err(err) => {
                self.remove_waiter(&woken);
                Err(err.into())
            }
        }
    }

    /// Wakes up at most `count` tasks whose bitset intersects with the given
    /// bitmask.
    ///
    /// **Important:** Do not call [`Waker::wake_by_ref`] while holding
    /// `self.queue`'s [`SpinNoIrq`] lock: a synchronous wake can resume a
    /// waiter whose `wait_if` closure uses blocking primitives (e.g.
    /// [`ax_sync::Mutex`], page faults via [`VmPtr::vm_read`]), which requires
    /// IRQs enabled and trips [`ax_task::api::might_sleep`] panics.
    pub fn wake(&self, count: usize, mask: u32) -> usize {
        let mut to_wake: Vec<Waker> = Vec::new();
        let mut woke = 0;
        {
            let mut q = self.queue.lock();
            q.retain(|(waker, bitset, woken)| {
                if woke >= count || (bitset & mask) == 0 {
                    true
                } else {
                    woken.store(true, Ordering::Release);
                    to_wake.push(waker.clone());
                    woke += 1;
                    false
                }
            });
        }
        for w in to_wake {
            w.wake_by_ref();
        }
        woke
    }

    /// Checks if the wait queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }

    fn remove_waiter(&self, needle: &Arc<AtomicBool>) {
        self.queue
            .lock()
            .retain(|(_, _, woken)| !Arc::ptr_eq(woken, needle));
    }

    /// Requeue at most `count` tasks to the target wait queue.
    pub fn requeue(&self, mut count: usize, target: &WaitQueue) -> usize {
        let tasks: Vec<_> = {
            let mut wq = self.queue.lock();
            count = count.min(wq.len());
            wq.drain(..count).collect()
        };
        if !tasks.is_empty() {
            let mut wq = target.queue.lock();
            wq.extend(tasks);
        }
        count
    }
}

/// A key that uniquely identifies a futex in the system.
pub enum FutexKey {
    /// A futex that is private to the current process.
    Private {
        /// The memory address of the futex.
        address: usize,
    },

    /// A futex in a shared memory region.
    Shared {
        /// The offset of the futex within the shared memory region.
        offset: usize,
        /// The shared memory region.
        region: Result<Weak<SharedPages>, Weak<()>>,
    },
}

impl FutexKey {
    /// Creates a new `FutexKey`.
    pub fn new(aspace: &AddrSpace, address: usize) -> Self {
        if let Some(area) = aspace.find_area(VirtAddr::from_usize(address)) {
            match area.backend() {
                Backend::Shared(backend) => {
                    return Self::Shared {
                        offset: address - area.start().as_usize(),
                        region: Ok(Arc::downgrade(backend.pages())),
                    };
                }
                Backend::File(file) => {
                    return Self::Shared {
                        offset: address - area.start().as_usize(),
                        region: Err(file.futex_handle()),
                    };
                }
                _ => {}
            }
        }
        Self::Private { address }
    }

    /// Shortcut to create a `FutexKey` for the current task's address space.
    pub fn new_current(address: usize) -> Self {
        Self::new(&current().as_thread().proc_data.aspace.lock(), address)
    }

    fn as_usize(&self) -> usize {
        match self {
            FutexKey::Private { address } => *address,
            FutexKey::Shared { offset, .. } => *offset,
        }
    }
}

/// The futex entry structure
pub struct FutexEntry {
    /// The wait queue associated with this futex.
    pub wq: WaitQueue,

    /// Used by robust list, indicates if the owner of this futex is dead.
    pub owner_dead: AtomicBool,
}

impl FutexEntry {
    fn new() -> Self {
        Self {
            wq: WaitQueue::new(),
            owner_dead: AtomicBool::new(false),
        }
    }
}

/// A table mapping memory addresses to futex wait queues.
pub struct FutexTable(Mutex<HashMap<usize, Arc<FutexEntry>>>);

impl FutexTable {
    /// Creates a new `FutexTable`.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    /// Checks if the futex table is empty.
    pub fn is_empty(&self) -> bool {
        self.0.lock().is_empty()
    }

    /// Gets the wait queue associated with the given address.
    pub fn get(&self, key: &FutexKey) -> Option<FutexGuard<'_>> {
        let key = key.as_usize();
        let entry = self.0.lock().get(&key).cloned()?;
        Some(FutexGuard {
            table: self,
            key,
            inner: entry,
        })
    }

    /// Gets the wait queue associated with the given address, or inserts a a
    /// new one if it doesn't exist.
    pub fn get_or_insert(&self, key: &FutexKey) -> FutexGuard<'_> {
        let key = key.as_usize();
        let mut table = self.0.lock();
        let entry = table
            .entry(key)
            .or_insert_with(|| Arc::new(FutexEntry::new()));
        FutexGuard {
            table: self,
            key,
            inner: entry.clone(),
        }
    }
}

#[doc(hidden)]
pub struct FutexGuard<'a> {
    table: &'a FutexTable,
    key: usize,
    inner: Arc<FutexEntry>,
}

impl Deref for FutexGuard<'_> {
    type Target = Arc<FutexEntry>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for FutexGuard<'_> {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) <= 2 && self.inner.wq.is_empty() {
            self.table.0.lock().remove(&self.key);
        }
    }
}

struct FutexTables {
    map: BTreeMap<usize, Arc<FutexTable>>,
    operations: usize,
}
impl FutexTables {
    const fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            operations: 0,
        }
    }

    fn get_or_insert(&mut self, key: usize) -> Arc<FutexTable> {
        self.operations += 1;
        if self.operations == 100 {
            self.operations = 0;
            self.map
                .retain(|_, table| Arc::strong_count(table) > 1 || !table.is_empty());
        }
        self.map
            .entry(key)
            .or_insert_with(|| Arc::new(FutexTable::new()))
            .clone()
    }
}

static SHARED_FUTEX_TABLES: Mutex<FutexTables> = Mutex::new(FutexTables::new());

/// Returns the futex table for the given key.
pub fn futex_table_for(key: &FutexKey) -> Arc<FutexTable> {
    match key {
        FutexKey::Private { .. } => current().as_thread().proc_data.futex_table.clone(),
        FutexKey::Shared { region, .. } => {
            let ptr = match region {
                Ok(pages) => Weak::as_ptr(pages) as usize,
                Err(key) => Weak::as_ptr(key) as usize,
            };
            SHARED_FUTEX_TABLES.lock().get_or_insert(ptr)
        }
    }
}
