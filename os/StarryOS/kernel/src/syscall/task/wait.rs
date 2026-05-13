use alloc::vec::Vec;
use core::{future::poll_fn, task::Poll};

use ax_errno::{AxError, AxResult, LinuxError};
use ax_task::{
    current,
    future::{block_on, interruptible},
};
use bitflags::bitflags;
use linux_raw_sys::general::{
    __WALL, __WCLONE, __WNOTHREAD, CLD_DUMPED, CLD_EXITED, CLD_KILLED, CLD_STOPPED, P_ALL, P_PGID,
    P_PID, P_PIDFD, SIGCHLD, WCONTINUED, WEXITED, WNOHANG, WNOWAIT, WUNTRACED, rusage, siginfo,
    siginfo__bindgen_ty_1__bindgen_ty_1,
};
use starry_process::{Pid, Process};
use starry_vm::{VmMutPtr, VmPtr};

use crate::task::AsThread;

bitflags! {
    #[derive(Debug, Clone, Copy)]
    struct WaitOptions: u32 {
        /// Do not block when there are no processes wishing to report status.
        const WNOHANG = WNOHANG;
        /// Report the status of selected processes which are stopped due to a
        /// `SIGTTIN`, `SIGTTOU`, `SIGTSTP`, or `SIGSTOP` signal.
        const WUNTRACED = WUNTRACED;
        /// Report the status of selected processes which have terminated.
        const WEXITED = WEXITED;
        /// Report the status of selected processes that have continued from a
        /// job control stop by receiving a `SIGCONT` signal.
        const WCONTINUED = WCONTINUED;
        /// Don't reap, just poll status.
        const WNOWAIT = WNOWAIT;

        /// Don't wait on children of other threads in this group
        const WNOTHREAD = __WNOTHREAD;
        /// Wait on all children, regardless of type
        const WALL = __WALL;
        /// Wait for "clone" children only.
        const WCLONE = __WCLONE;
    }
}

#[derive(Debug, Clone, Copy)]
enum WaitPid {
    /// Wait for any child process
    Any,
    /// Wait for the child whose process ID is equal to the value.
    Pid(Pid),
    /// Wait for any child process whose process group ID is equal to the value.
    Pgid(Pid),
}

impl WaitPid {
    fn apply(&self, child: &Process) -> bool {
        match self {
            WaitPid::Any => true,
            WaitPid::Pid(pid) => child.pid() == *pid,
            WaitPid::Pgid(pgid) => child.group().pgid() == *pgid,
        }
    }
}

fn decode_child_siginfo(status: i32) -> (i32, i32) {
    if (status & 0x7f) == 0 {
        (CLD_EXITED as i32, (status >> 8) & 0xff)
    } else if (status & 0xff) == 0x7f {
        (CLD_STOPPED as i32, (status >> 8) & 0xff)
    } else {
        let sig = status & 0x7f;
        if status & 0x80 != 0 {
            (CLD_DUMPED as i32, sig)
        } else {
            (CLD_KILLED as i32, sig)
        }
    }
}

fn fill_sigchld_siginfo(raw_status: i32, child_pid: Pid) -> siginfo {
    let (si_code, si_status) = decode_child_siginfo(raw_status);
    let mut s = core::mem::MaybeUninit::<siginfo>::zeroed();
    unsafe {
        let inner = s.as_mut_ptr().cast::<siginfo__bindgen_ty_1__bindgen_ty_1>();
        (*inner).si_signo = SIGCHLD as i32;
        (*inner).si_errno = 0;
        (*inner).si_code = si_code;
        (*inner)._sifields._sigchld._pid = child_pid as i32;
        (*inner)._sifields._sigchld._uid = 0;
        (*inner)._sifields._sigchld._status = si_status;
        (*inner)._sifields._sigchld._utime = 0;
        (*inner)._sifields._sigchld._stime = 0;
        s.assume_init()
    }
}

fn wait_options_from_waitid(options: i32) -> AxResult<WaitOptions> {
    let raw = options as u32;
    const STATUS: u32 = WEXITED | WUNTRACED | WCONTINUED;
    let mut eff = raw;
    if eff & STATUS == 0 {
        eff |= WEXITED;
    }
    if eff & (WUNTRACED | WCONTINUED) != 0 && eff & WEXITED == 0 {
        return Err(AxError::InvalidInput);
    }
    WaitOptions::from_bits(eff).ok_or(AxError::InvalidInput)
}

fn wait_pid_from_idtype(idtype: u32, id: i32, proc: &Process) -> AxResult<WaitPid> {
    match idtype {
        P_PID => {
            if id <= 0 {
                return Err(AxError::InvalidInput);
            }
            Ok(WaitPid::Pid(id as _))
        }
        P_PGID => {
            if id < 0 {
                return Err(AxError::InvalidInput);
            }
            if id == 0 {
                Ok(WaitPid::Pgid(proc.group().pgid()))
            } else {
                Ok(WaitPid::Pgid(id as _))
            }
        }
        P_ALL => Ok(WaitPid::Any),
        P_PIDFD => Err(AxError::InvalidInput),
        _ => Err(AxError::InvalidInput),
    }
}

enum WaitPoll {
    /// Reaped (or `WNOWAIT` inspected) a zombie child.
    Found { pid: Pid },
    /// `WNOHANG` and no matching zombie yet.
    NoHang,
    /// Must block until `child_exit_event`.
    Pending,
}

fn wait_children(
    proc: &Process,
    which: WaitPid,
    options: WaitOptions,
    exit_code: *mut i32,
    infop: *mut siginfo,
) -> AxResult<WaitPoll> {
    let children = proc
        .children()
        .into_iter()
        .filter(|child| which.apply(child))
        .collect::<Vec<_>>();
    if children.is_empty() {
        return Err(AxError::from(LinuxError::ECHILD));
    }

    if let Some(child) = children
        .iter()
        .find(|child| child.is_zombie() || child.threads().is_empty())
    {
        if !child.is_zombie() {
            child.exit();
        }
        let raw_status = child.exit_code();
        if !options.contains(WaitOptions::WNOWAIT) {
            child.free();
        }
        if let Some(exit_code) = exit_code.nullable() {
            exit_code.vm_write(raw_status)?;
        }
        if let Some(infop) = infop.nullable() {
            let si = fill_sigchld_siginfo(raw_status, child.pid());
            infop.vm_write(si)?;
        }
        Ok(WaitPoll::Found { pid: child.pid() })
    } else if options.contains(WaitOptions::WNOHANG) {
        if let Some(infop) = infop.nullable() {
            let z = core::mem::MaybeUninit::<siginfo>::zeroed();
            let z = unsafe { z.assume_init() };
            infop.vm_write(z)?;
        }
        Ok(WaitPoll::NoHang)
    } else {
        Ok(WaitPoll::Pending)
    }
}

pub fn sys_waitpid(pid: i32, exit_code: *mut i32, options: u32) -> AxResult<isize> {
    let options = WaitOptions::from_bits_truncate(options);
    info!("sys_waitpid <= pid: {pid:?}, options: {options:?}");

    let curr = current();
    let proc_data = &curr.as_thread().proc_data;
    let proc = &proc_data.proc;

    let pid = if pid == -1 {
        WaitPid::Any
    } else if pid == 0 {
        WaitPid::Pgid(proc.group().pgid())
    } else if pid > 0 {
        WaitPid::Pid(pid as _)
    } else {
        WaitPid::Pgid(-pid as _)
    };

    // FIXME: add back support for WALL & WCLONE, since ProcessData may drop before
    // Process now.
    block_on(interruptible(poll_fn(|cx| {
        match wait_children(proc, pid, options, exit_code, core::ptr::null_mut()) {
            Ok(WaitPoll::Found { pid, .. }) => Poll::Ready(Ok(pid as isize)),
            Ok(WaitPoll::NoHang) => Poll::Ready(Ok(0)),
            Ok(WaitPoll::Pending) => {
                proc_data.child_exit_event.register(cx.waker());
                // Close the same lost-wakeup window as waitid: the child can
                // exit between the first check and registering this waker.
                match wait_children(proc, pid, options, exit_code, core::ptr::null_mut()) {
                    Ok(WaitPoll::Found { pid, .. }) => Poll::Ready(Ok(pid as isize)),
                    Ok(WaitPoll::NoHang) => Poll::Ready(Ok(0)),
                    Ok(WaitPoll::Pending) => Poll::Pending,
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    })))?
}

/// `waitid(2)` — report child state via `siginfo_t`, sharing the same wait pool as `waitpid`.
pub fn sys_waitid(
    idtype: u32,
    id: i32,
    infop: *mut siginfo,
    options: i32,
    _ru: *mut rusage,
) -> AxResult<isize> {
    let options = wait_options_from_waitid(options)?;
    info!("sys_waitid <= idtype: {idtype}, id: {id}, options: {options:?}");

    let curr = current();
    let proc_data = &curr.as_thread().proc_data;
    let proc = &proc_data.proc;
    let which = wait_pid_from_idtype(idtype, id, proc)?;

    block_on(interruptible(poll_fn(|cx| {
        match wait_children(proc, which, options, core::ptr::null_mut(), infop) {
            Ok(WaitPoll::Found { .. }) | Ok(WaitPoll::NoHang) => Poll::Ready(Ok(0)),
            Ok(WaitPoll::Pending) => {
                proc_data.child_exit_event.register(cx.waker());
                // 关闭「检查 → 注册 waker」之间的丢唤醒窗口：子进程可能恰好在
                // 这两步之间退出并 child_exit_event.wake()（当时尚无 waiter）。
                match wait_children(proc, which, options, core::ptr::null_mut(), infop) {
                    Ok(WaitPoll::Found { .. }) | Ok(WaitPoll::NoHang) => Poll::Ready(Ok(0)),
                    Ok(WaitPoll::Pending) => Poll::Pending,
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    })))?
}
