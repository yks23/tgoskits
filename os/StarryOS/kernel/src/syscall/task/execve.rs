use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    ffi::{c_char, c_int},
    future::poll_fn,
    task::Poll,
};

use ax_errno::{AxError, AxResult};
use ax_fs::FS_CONTEXT;
use ax_hal::uspace::UserContext;
use ax_sync::Mutex;
use ax_task::{
    current,
    future::{block_on, interruptible},
};
use axfs_ng_vfs::Location;
use linux_raw_sys::general::{AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_SYMLINK_NOFOLLOW, RLIMIT_STACK};
use starry_process::Pid;
use starry_vm::vm_load_until_nul;

use crate::{
    config::{USER_HEAP_BASE, USER_STACK_SIZE},
    file::{FD_TABLE, close_file_like, resolve_at},
    mm::{copy_from_kernel, load_user_app, new_user_aspace_empty, vm_load_string},
    task::{AsThread, ProcessData, kill_thread_for_execve_de_thread, rlim_is_infinite},
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
    })))??;

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

    let stack_bytes = {
        let r = proc_data.rlim.read();
        let sz = r[RLIMIT_STACK].current;
        if rlim_is_infinite(sz) {
            USER_STACK_SIZE
        } else {
            (sz as usize).max(ax_memory_addr::PAGE_SIZE_4K)
        }
    };

    // CLONE_VFORK semantics: if our address space is currently shared with
    // the (vfork) parent, we MUST detach into a fresh, empty address space
    // before we touch any mappings — otherwise load_user_app's `uspace.clear()`
    // would wipe the parent's mappings out from under it (parent SEGVs the
    // moment it returns from the clone() syscall).
    // CLONE_VFORK / CLONE_VM child detach: if our address space is currently
    // shared with the parent, we MUST migrate to a fresh, empty address space
    // before load_user_app() invalidates it (load_user_app calls
    // `uspace.clear()` which would wipe the parent's mappings out from under
    // it). Detection: Arc strong_count > 1 means the parent still holds it.
    if Arc::strong_count(&proc_data.aspace) > 1 {
        let mut new_aspace = crate::mm::new_user_aspace_empty()?;
        // RISC-V & x86_64 share one SATP for kernel + user, so we must copy
        // the kernel half into the new page table before activating it.
        crate::mm::copy_from_kernel(&mut new_aspace)?;
        let new_pt_root = new_aspace.page_table_root();
        let new_arc = Arc::new(ax_sync::Mutex::new(new_aspace));
        // SAFETY: vfork forbids CLONE_THREAD, so this ProcessData has no
        // sibling thread that could race us on the aspace slot. The parent
        // is in a separate ProcessData entirely (CLONE_VFORK does not share
        // ProcessData with the parent).
        unsafe {
            proc_data.replace_aspace(new_arc);
        }
        // Update both the live SATP (so we can keep running this syscall in
        // the new aspace) AND the saved task context's satp (so the next
        // context-switch back to us doesn't think the satp is unchanged and
        // skip the actual write).
        unsafe {
            ax_hal::asm::write_user_page_table(new_pt_root);
        }
        ax_hal::asm::flush_tlb(None);
        unsafe {
            // SAFETY: ctx_mut_ptr is a stable pointer; we are the only thread
            // of this process (vfork/exec single-thread invariant) and we are
            // running on this very task, so no concurrent context switch is
            // touching `ctx`.
            (*ax_task::current().ctx_mut_raw()).set_page_table_root(new_pt_root);
        }
    }

    let mut aspace = proc_data.aspace.lock();
    let (entry_point, user_stack_base) =
        load_user_app(&mut aspace, Some(load_path), &args, &envs, stack_bytes)?;
    drop(aspace);


    let loc = loc_for_name()?;
    let new_name = loc.name();
    let new_exe_path = loc.absolute_path()?.to_string();

    // Build the new address space entirely before committing.
    // Loading into a fresh aspace (rather than clearing the existing one)
    // ensures a CLONE_VM parent's mappings are never disturbed —
    // posix_spawn uses CLONE_VM|CLONE_VFORK and runs the child on a stack
    // slice inside the parent's address space.
    let mut new_aspace = new_user_aspace_empty()?;
    copy_from_kernel(&mut new_aspace)?;
    let (entry_point, user_stack_base) =
        load_user_app(&mut new_aspace, Some(load_path), &args, &envs, stack_bytes)?;

    // Collect CLOEXEC fds to close (read-only scan, no mutation yet).
    let cloexec_fds: Vec<_> = {
        let fd_table = FD_TABLE.read();
        fd_table
            .ids()
            .filter(|it| fd_table.get(*it).unwrap().cloexec)
            .collect()
    };

    // ----------------------------------------------------------------
    // Phase 2: point of no return — commit all changes.
    // Nothing below may fail; errors here would leave the process broken.
    // ----------------------------------------------------------------

    // Replace the aspace Arc so the parent's shared Arc<Mutex<AddrSpace>>
    // (from CLONE_VM) is never touched. The parent's page table register
    // keeps pointing at the original still-live AddrSpace.
    let new_pt_root = new_aspace.page_table_root();
    let newaspace_arc = Arc::new(Mutex::new(new_aspace));
    // SAFETY: vfork forbids CLONE_THREAD, so this ProcessData has no sibling
    // threads racing on the aspace slot.
    unsafe { proc_data.replace_aspace(newaspace_arc) };

    // Switch the hardware page table now that the new aspace is installed.
    curr.switch_page_table(new_pt_root);

    curr.set_name(new_name);
    *proc_data.exe_path.write() = new_exe_path;
    *proc_data.cmdline.write() = Arc::new(args);

    proc_data.set_heap_top(USER_HEAP_BASE);

    proc_data.signal.reset_actions();

    curr.as_thread().set_clear_child_tid(0);

    // Close CLOEXEC file descriptors.
    let mut fd_table = FD_TABLE.write();
    for fd in &cloexec_fds {
        fd_table.remove(*fd);
    }
    drop(fd_table);
    for fd in cloexec_fds {
        let _ = close_file_like(fd as c_int);
    }

    uctx.set_ip(entry_point.as_usize());
    uctx.set_sp(user_stack_base.as_usize());

    // CLONE_VFORK semantics: the child has now installed a brand-new image,
    // so release the vfork parent (no-op when not a vfork child).
    curr.as_thread().release_vfork_parent();

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
    apply_execve_image(
        uctx,
        path_for_load.as_str(),
        || {
            let mut fs = FS_CONTEXT.lock();
            fs.resolve(path.as_str())
        },
        args,
        envs,
    )
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

    debug!("sys_execveat <= dirfd: {dirfd}, path: {path_owned:?}, args: {args:?}, envs: {envs:?}");

    let loc = resolve_at(dirfd, resolve_path, flags_u)?
        .into_file()
        .ok_or(AxError::InvalidInput)?;
    let abs_path = loc.absolute_path().map_err(|_| AxError::InvalidInput)?;
    let abs_string = abs_path.to_string();
    let loc_for_apply = loc.clone();

    let proc_data = current().as_thread().proc_data.clone();
    wait_execve_single_threaded(&proc_data)?;

    let abs_for_load = abs_string.clone();
    apply_execve_image(
        uctx,
        abs_for_load.as_str(),
        move || Ok(loc_for_apply),
        args,
        envs,
    )
}
