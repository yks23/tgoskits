//! User task management.

mod futex;
mod ops;
mod resources;
mod signal;
mod stat;
mod timer;
mod user;

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::{
    cell::RefCell,
    ops::Deref,
    sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering},
};

use ax_sync::{Mutex, spin::SpinNoIrq};
use ax_task::{TaskExt, TaskInner};
use axpoll::PollSet;
use extern_trait::extern_trait;
use scope_local::{ActiveScope, Scope};
use spin::RwLock;
use starry_process::Process;
use starry_signal::{
    Signo,
    api::{ProcessSignalManager, SignalActions, ThreadSignalManager},
};

pub use self::{futex::*, ops::*, resources::*, signal::*, stat::*, timer::*, user::*};
use crate::mm::AddrSpace;

///  A wrapper type that assumes the inner type is `Sync`.
#[repr(transparent)]
pub struct AssumeSync<T>(pub T);

unsafe impl<T> Sync for AssumeSync<T> {}

impl<T> Deref for AssumeSync<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Last user-mode register sample observed when this thread trapped into the kernel.
#[derive(Clone, Copy, Default)]
pub struct UserRegsSnapshot {
    pub pc: usize,
    pub sp: usize,
    pub ra: usize,
    pub tp: usize,
}

/// The inner data of a thread.
pub struct Thread {
    /// The process data shared by all threads in the process.
    pub proc_data: Arc<ProcessData>,

    /// The clear thread tid field
    ///
    /// See <https://manpages.debian.org/unstable/manpages-dev/set_tid_address.2.en.html#clear_child_tid>
    ///
    /// When the thread exits, the kernel clears the word at this address if it
    /// is not NULL.
    clear_child_tid: AtomicUsize,

    /// The head of the robust list
    robust_list_head: AtomicUsize,

    /// The thread-level signal manager
    pub signal: Arc<ThreadSignalManager>,

    /// Time manager
    ///
    /// This is assumed to be `Sync` because it's only borrowed mutably during
    /// context switches, which is exclusive to the current thread.
    pub time: AssumeSync<RefCell<TimeManager>>,

    /// The OOM score adjustment value.
    oom_score_adj: AtomicI32,

    /// Ready to exit
    pub exit: Arc<AtomicBool>,

    /// Set by `execve` de-thread to force this thread to exit alone (no group exit).
    pub execve_kill: AtomicBool,

    /// Indicates whether the thread is currently accessing user memory.
    accessing_user_memory: AtomicBool,

    /// Self exit event
    pub exit_event: Arc<PollSet>,

    /// The registered rseq area pointer (user address) for restartable
    /// sequences.
    rseq_area: AtomicUsize,

    /// Set when the thread was created via `clone(CLONE_VFORK)` or `vfork(2)`.
    /// While non-`None`, the parent task is blocked on this `PollSet` waiting
    /// for the child to release its hold on the parent's address space (i.e.
    /// to call `execve(2)` or `_exit(2)`). The child wakes & clears it on
    /// either of those events.
    pub vfork_done: spin::Mutex<Option<Arc<PollSet>>>,

    user_pc: AtomicUsize,
    user_sp: AtomicUsize,
    user_ra: AtomicUsize,
    user_tp: AtomicUsize,
}

impl Thread {
    /// Create a new [`Thread`].
    pub fn new(tid: u32, proc_data: Arc<ProcessData>) -> Box<Self> {
        Box::new(Thread {
            signal: ThreadSignalManager::new(tid, proc_data.signal.clone()),
            proc_data,
            clear_child_tid: AtomicUsize::new(0),
            robust_list_head: AtomicUsize::new(0),
            time: AssumeSync(RefCell::new(TimeManager::new())),
            exit: Arc::new(AtomicBool::new(false)),
            execve_kill: AtomicBool::new(false),
            oom_score_adj: AtomicI32::new(200),
            accessing_user_memory: AtomicBool::new(false),
            exit_event: Arc::default(),
            rseq_area: AtomicUsize::new(0),
            vfork_done: spin::Mutex::new(None),
            user_pc: AtomicUsize::new(0),
            user_sp: AtomicUsize::new(0),
            user_ra: AtomicUsize::new(0),
            user_tp: AtomicUsize::new(0),
        })
    }

    /// Take the vfork-done PollSet (consumes it) and wake whoever is waiting.
    /// Called from `execve` (after the new image is loaded) and from `do_exit`
    /// to release the vfork parent.
    pub fn release_vfork_parent(&self) {
        if let Some(ev) = self.vfork_done.lock().take() {
            ev.wake();
        }
    }

    /// Get the clear child tid field.
    pub fn clear_child_tid(&self) -> usize {
        self.clear_child_tid.load(Ordering::Relaxed)
    }

    /// Set the clear child tid field.
    pub fn set_clear_child_tid(&self, clear_child_tid: usize) {
        self.clear_child_tid
            .store(clear_child_tid, Ordering::Relaxed);
    }

    /// Get the robust list head.
    pub fn robust_list_head(&self) -> usize {
        self.robust_list_head.load(Ordering::SeqCst)
    }

    /// Set the robust list head.
    pub fn set_robust_list_head(&self, robust_list_head: usize) {
        self.robust_list_head
            .store(robust_list_head, Ordering::SeqCst);
    }

    /// Get the oom score adjustment value.
    pub fn oom_score_adj(&self) -> i32 {
        self.oom_score_adj.load(Ordering::SeqCst)
    }

    /// Set the oom score adjustment value.
    pub fn set_oom_score_adj(&self, value: i32) {
        self.oom_score_adj.store(value, Ordering::SeqCst);
    }

    /// Check if the thread is ready to exit.
    pub fn pending_exit(&self) -> bool {
        self.exit.load(Ordering::Acquire)
    }

    /// Set the thread to exit.
    pub fn set_exit(&self) {
        self.exit.store(true, Ordering::Release);
    }

    /// Request this thread to exit for `execve` sibling teardown (checked in the user loop).
    pub fn request_execve_kill(&self) {
        self.execve_kill.store(true, Ordering::Release);
    }

    /// Check if the thread is accessing user memory.
    pub fn is_accessing_user_memory(&self) -> bool {
        self.accessing_user_memory.load(Ordering::Acquire)
    }

    /// Set the accessing user memory flag.
    pub fn set_accessing_user_memory(&self, accessing: bool) {
        self.accessing_user_memory
            .store(accessing, Ordering::Release);
    }

    /// Get the registered rseq area pointer.
    pub fn rseq_area(&self) -> usize {
        self.rseq_area.load(Ordering::SeqCst)
    }

    /// Set the registered rseq area pointer.
    pub fn set_rseq_area(&self, addr: usize) {
        self.rseq_area.store(addr, Ordering::SeqCst);
    }

    pub fn record_user_regs(&self, pc: usize, sp: usize, ra: usize, tp: usize) {
        self.user_pc.store(pc, Ordering::Relaxed);
        self.user_sp.store(sp, Ordering::Relaxed);
        self.user_ra.store(ra, Ordering::Relaxed);
        self.user_tp.store(tp, Ordering::Relaxed);
    }

    pub fn user_regs_snapshot(&self) -> UserRegsSnapshot {
        UserRegsSnapshot {
            pc: self.user_pc.load(Ordering::Relaxed),
            sp: self.user_sp.load(Ordering::Relaxed),
            ra: self.user_ra.load(Ordering::Relaxed),
            tp: self.user_tp.load(Ordering::Relaxed),
        }
    }
}

#[extern_trait]
impl TaskExt for Box<Thread> {
    fn on_enter(&self) {
        let scope = self.proc_data.scope.read();
        unsafe { ActiveScope::set(&scope) };
        core::mem::forget(scope);
    }

    fn on_leave(&self) {
        ActiveScope::set_global();
        unsafe { self.proc_data.scope.force_read_decrement() };
    }
}

/// Helper trait to access the thread from a task.
pub trait AsThread {
    /// Try to get the thread from the task.
    fn try_as_thread(&self) -> Option<&Thread>;

    /// Get the thread from the task, panicking if it is a kernel task.
    fn as_thread(&self) -> &Thread {
        self.try_as_thread().expect("kernel task")
    }
}

impl AsThread for TaskInner {
    fn try_as_thread(&self) -> Option<&Thread> {
        self.task_ext()
            .map(|ext| ext.downcast_ref::<Box<Thread>>().as_ref())
    }
}

/// [`Process`]-shared data.
pub struct ProcessData {
    /// The process.
    pub proc: Arc<Process>,
    /// The executable path
    pub exe_path: RwLock<String>,
    /// The command line arguments
    pub cmdline: RwLock<Arc<Vec<String>>>,
    /// The virtual memory address space.
    // TODO: scopify
    pub aspace: Arc<Mutex<AddrSpace>>,
    /// The resource scope
    pub scope: RwLock<Scope>,
    /// The user heap top
    heap_top: AtomicUsize,

    /// The resource limits
    pub rlim: RwLock<Rlimits>,

    /// The child exit wait event
    pub child_exit_event: Arc<PollSet>,
    /// Woken when any thread in this process leaves the thread-group set (for `execve` de-thread).
    pub thread_group_wait: Arc<PollSet>,
    /// Self exit event
    pub exit_event: Arc<PollSet>,
    /// The exit signal of the thread
    pub exit_signal: Option<Signo>,

    /// The process signal manager
    pub signal: Arc<ProcessSignalManager>,

    /// The futex table.
    futex_table: Arc<FutexTable>,

    /// The default mask for file permissions.
    umask: AtomicU32,

    /// Linux `personality(2)` domain; default `PER_LINUX` (0).
    personality: AtomicU32,
    /// Process nice value (`setpriority` / `getpriority` semantics), default 0.
    proc_nice: AtomicI32,
    ruid: AtomicU32,
    euid: AtomicU32,
    suid: AtomicU32,
    rgid: AtomicU32,
    egid: AtomicU32,
    sgid: AtomicU32,
}

impl ProcessData {
    /// Replace the `Arc<Mutex<AddrSpace>>` slot with a brand-new one. Used by
    /// `execve(2)` after a CLONE_VFORK clone, so the child can detach from the
    /// parent's address space before loading the new ELF.
    ///
    /// # Safety
    /// Caller must guarantee that no other thread of this process is currently
    /// using `self.aspace` (or about to start). For the vfork case this holds
    /// because vfork forbids CLONE_THREAD and the parent is blocked in
    /// `do_clone()` until the child wakes it.
    pub unsafe fn replace_aspace(&self, new: Arc<Mutex<AddrSpace>>) {
        // Cast through a raw pointer obtained from the field's address; we
        // intentionally bypass aliasing rules here, justified by the SAFETY
        // contract above. Use `addr_of` to avoid creating an intermediate
        // `&T` reference that would trip Rust's aliasing model lints.
        let slot = core::ptr::addr_of!(self.aspace) as *mut Arc<Mutex<AddrSpace>>;
        unsafe {
            core::ptr::drop_in_place(slot);
            core::ptr::write(slot, new);
        }
    }

    /// Create a new [`ProcessData`].
    pub fn new(
        proc: Arc<Process>,
        exe_path: String,
        cmdline: Arc<Vec<String>>,
        aspace: Arc<Mutex<AddrSpace>>,
        signal_actions: Arc<SpinNoIrq<SignalActions>>,
        exit_signal: Option<Signo>,
    ) -> Arc<Self> {
        Arc::new(Self {
            proc,
            exe_path: RwLock::new(exe_path),
            cmdline: RwLock::new(cmdline),
            aspace,
            scope: RwLock::new(Scope::new()),
            heap_top: AtomicUsize::new(crate::config::USER_HEAP_BASE),

            rlim: RwLock::default(),

            child_exit_event: Arc::default(),
            thread_group_wait: Arc::default(),
            exit_event: Arc::default(),
            exit_signal,

            signal: Arc::new(ProcessSignalManager::new(
                signal_actions,
                crate::config::SIGNAL_TRAMPOLINE,
            )),

            futex_table: Arc::new(FutexTable::new()),

            umask: AtomicU32::new(0o022),

            personality: AtomicU32::new(0),
            proc_nice: AtomicI32::new(0),
            ruid: AtomicU32::new(0),
            euid: AtomicU32::new(0),
            suid: AtomicU32::new(0),
            rgid: AtomicU32::new(0),
            egid: AtomicU32::new(0),
            sgid: AtomicU32::new(0),
        })
    }

    /// Get the top address of the user heap.
    pub fn get_heap_top(&self) -> usize {
        self.heap_top.load(Ordering::Acquire)
    }

    /// Set the top address of the user heap.
    pub fn set_heap_top(&self, top: usize) {
        self.heap_top.store(top, Ordering::Release)
    }

    /// Linux manual: A "clone" child is one which delivers no signal, or a
    /// signal other than SIGCHLD to its parent upon termination.
    pub fn is_clone_child(&self) -> bool {
        self.exit_signal != Some(Signo::SIGCHLD)
    }

    /// Get the umask.
    pub fn umask(&self) -> u32 {
        self.umask.load(Ordering::SeqCst)
    }

    /// Set the umask.
    pub fn set_umask(&self, umask: u32) {
        self.umask.store(umask, Ordering::SeqCst);
    }

    /// Set the umask and return the old value.
    pub fn replace_umask(&self, umask: u32) -> u32 {
        self.umask.swap(umask, Ordering::SeqCst)
    }

    pub fn personality(&self) -> u32 {
        self.personality.load(Ordering::Relaxed)
    }

    pub fn set_personality(&self, value: u32) -> u32 {
        self.personality.swap(value, Ordering::Relaxed)
    }

    pub fn store_personality(&self, value: u32) {
        self.personality.store(value, Ordering::Relaxed);
    }

    pub fn proc_nice(&self) -> i32 {
        self.proc_nice.load(Ordering::Relaxed)
    }

    pub fn set_proc_nice(&self, nice: i32) -> i32 {
        self.proc_nice.swap(nice, Ordering::Relaxed)
    }

    pub fn store_proc_nice(&self, nice: i32) {
        self.proc_nice.store(nice, Ordering::Relaxed);
    }

    pub fn res_uids(&self) -> (u32, u32, u32) {
        (
            self.ruid.load(Ordering::Relaxed),
            self.euid.load(Ordering::Relaxed),
            self.suid.load(Ordering::Relaxed),
        )
    }

    pub fn set_res_uids(&self, ruid: u32, euid: u32, suid: u32) {
        self.ruid.store(ruid, Ordering::Relaxed);
        self.euid.store(euid, Ordering::Relaxed);
        self.suid.store(suid, Ordering::Relaxed);
    }

    pub fn res_gids(&self) -> (u32, u32, u32) {
        (
            self.rgid.load(Ordering::Relaxed),
            self.egid.load(Ordering::Relaxed),
            self.sgid.load(Ordering::Relaxed),
        )
    }

    pub fn set_res_gids(&self, rgid: u32, egid: u32, sgid: u32) {
        self.rgid.store(rgid, Ordering::Relaxed);
        self.egid.store(egid, Ordering::Relaxed);
        self.sgid.store(sgid, Ordering::Relaxed);
    }
}
