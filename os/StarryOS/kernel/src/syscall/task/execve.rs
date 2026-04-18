use alloc::{string::{String, ToString}, sync::Arc, vec::Vec};
use core::ffi::{c_char, c_int};
use core::task::Poll;

use ax_errno::{AxError, AxResult};
use ax_fs::FS_CONTEXT;
use ax_hal::uspace::UserContext;
use ax_task::current;
use ax_task::future::{block_on, interruptible};
use core::future::poll_fn;
use axfs_ng_vfs::Location;
use linux_raw_sys::general::{AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_SYMLINK_NOFOLLOW};
use starry_process::Pid;
use starry_vm::vm_load_until_nul;

use crate::{
    config::USER_HEAP_BASE,
    file::{FD_TABLE, close_file_like, resolve_at},
    mm::{load_user_app, vm_load_string},
    task::{AsThread, ProcessData, kill_thread_for_execve_de_thread},
};

fn load_execve_strings(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> AxResult<(String, Vec<String>, Vec<String>)> {
    let path = vm_load_string(path)?;

    let args = if argv.is_null() {
        Vec::new()
    } else {
        vm_load_until_nul(argv)?
            .into_iter()
            .map(vm_load_string)
            .collect::<Result<Vec<_>, _>>()?
    };

    let envs = if envp.is_null() {
        Vec::new()
    } else {
        vm_load_until_nul(envp)?
            .into_iter()
            .map(vm_load_string)
            .collect::<Result<Vec<_>, _>>()?
    };

    Ok((path, args, envs))
}

/// Wait until this process is single-threaded, killing sibling threads (exec `de_thread`).
fn wait_execve_single_threaded(proc_data: &Arc<ProcessData>) -> AxResult<()> {
    let proc = proc_data.proc.clone();
    let me = current().id().as_u64() as Pid;

    if proc.threads().len() <= 1 {
        return Ok(());
    }

    let mut siblings = proc.threads();
    siblings.retain(|&tid| tid != me);
    for tid in siblings {
        let _ = kill_thread_for_execve_de_thread(&proc, tid);
    }

    block_on(interruptible(poll_fn(|cx| {
        if proc.threads().len() <= 1 {
            Poll::Ready(Ok::<(), AxError>(()))
        } else {
            proc_data.thread_group_wait.register(cx.waker());
            Poll::Pending
        }
    })))?;

    Ok(())
}

fn apply_execve_image(
    uctx: &mut UserContext,
    load_path: &str,
    loc_for_name: impl FnOnce() -> AxResult<Location>,
    args: Vec<String>,
    envs: Vec<String>,
) -> AxResult<isize> {
    let curr = current();
    let proc_data = &curr.as_thread().proc_data;

    let mut aspace = proc_data.aspace.lock();
    let (entry_point, user_stack_base) =
        load_user_app(&mut aspace, Some(load_path), &args, &envs)?;
    drop(aspace);

    let loc = loc_for_name()?;
    curr.set_name(loc.name());

    *proc_data.exe_path.write() = loc.absolute_path()?.to_string();
    *proc_data.cmdline.write() = Arc::new(args);

    proc_data.set_heap_top(USER_HEAP_BASE);

    proc_data.signal.reset_actions();

    curr.as_thread().set_clear_child_tid(0);

    let mut fd_table = FD_TABLE.write();
    let cloexec_fds = fd_table
        .ids()
        .filter(|it| fd_table.get(*it).unwrap().cloexec)
        .collect::<Vec<_>>();
    for fd in cloexec_fds {
        let _ = close_file_like(fd as c_int);
    }
    drop(fd_table);

    uctx.set_ip(entry_point.as_usize());
    uctx.set_sp(user_stack_base.as_usize());
    Ok(0)
}

pub fn sys_execve(
    uctx: &mut UserContext,
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> AxResult<isize> {
    let (path, args, envs) = load_execve_strings(path, argv, envp)?;

    debug!("sys_execve <= path: {path:?}, args: {args:?}, envs: {envs:?}");

    {
        let mut fs = FS_CONTEXT.lock();
        fs.resolve(path.as_str())?;
    }

    let proc_data = current().as_thread().proc_data.clone();
    wait_execve_single_threaded(&proc_data)?;

    let path_for_load = path.clone();
    apply_execve_image(uctx, path_for_load.as_str(), || {
        let mut fs = FS_CONTEXT.lock();
        fs.resolve(path.as_str())
    }, args, envs)
}

/// `execveat` — resolve `pathname` relative to `dirfd`, then same loading path as `execve`.
pub fn sys_execveat(
    uctx: &mut UserContext,
    dirfd: i32,
    pathname: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    flags: i32,
) -> AxResult<isize> {
    if flags < 0 {
        return Err(AxError::InvalidInput);
    }
    let flags_u = flags as u32;
    const ALLOWED: u32 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT;
    if flags_u & !ALLOWED != 0 {
        return Err(AxError::InvalidInput);
    }

    if pathname.is_null() {
        return Err(AxError::InvalidInput);
    }

    let path_owned = vm_load_string(pathname)?;
    let resolve_path = if path_owned.is_empty() {
        if flags_u & AT_EMPTY_PATH == 0 {
            return Err(AxError::InvalidInput);
        }
        None
    } else {
        Some(path_owned.as_str())
    };

    let args = if argv.is_null() {
        Vec::new()
    } else {
        vm_load_until_nul(argv)?
            .into_iter()
            .map(vm_load_string)
            .collect::<Result<Vec<_>, _>>()?
    };

    let envs = if envp.is_null() {
        Vec::new()
    } else {
        vm_load_until_nul(envp)?
            .into_iter()
            .map(vm_load_string)
            .collect::<Result<Vec<_>, _>>()?
    };

    debug!(
        "sys_execveat <= dirfd: {dirfd}, path: {path_owned:?}, args: {args:?}, envs: {envs:?}"
    );

    let loc = resolve_at(dirfd, resolve_path, flags_u)?
        .into_file()
        .ok_or(AxError::InvalidInput)?;
    let abs_path = loc.absolute_path().map_err(|_| AxError::InvalidInput)?;
    let abs_string = abs_path.to_string();
    let loc_for_apply = loc.clone();

    let proc_data = current().as_thread().proc_data.clone();
    wait_execve_single_threaded(&proc_data)?;

    let abs_for_load = abs_string.clone();
    apply_execve_image(uctx, abs_for_load.as_str(), move || Ok(loc_for_apply), args, envs)
}
