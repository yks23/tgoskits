use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
};
use core::{
    ffi::{c_char, c_int},
    mem::{self, size_of},
    ops::{Deref, DerefMut},
    sync::atomic::Ordering,
};

use ax_errno::{AxError, AxResult, LinuxError};
use ax_fs::{FS_CONTEXT, FileBackend, OpenOptions, OpenResult};
use ax_io::{Seek, SeekFrom};
use ax_task::current;
use axfs_ng_vfs::{DirEntry, FileNode, Location, NodeType, Reference, path::Path};
use bitflags::bitflags;
use linux_raw_sys::general::{RESOLVE_BENEATH, open_how, *};
use starry_vm::VmPtr;

use crate::{
    file::{
        Directory, FD_TABLE, File, FileLike, Pipe, add_file_descriptor, add_file_descriptor_from,
        add_file_like_with_status_flags, close_file_like, flock, get_file_like, record_lock,
        with_fs,
    },
    mm::{UserPtr, vm_load_string},
    pseudofs::{Device, dev::tty},
    syscall::{
        stats,
        sys::{sys_getegid, sys_geteuid},
    },
    task::AsThread,
};

/// Convert open flags to [`OpenOptions`].
fn flags_to_options(flags: c_int, mode: __kernel_mode_t, (uid, gid): (u32, u32)) -> OpenOptions {
    let flags = flags as u32;
    let mut options = OpenOptions::new();
    options.mode(mode).user(uid, gid);
    if flags & O_PATH != 0 {
        options.path(true);
        // Linux ignores most status/creation flags with O_PATH. Keep a read
        // bit only because axfs-ng currently requires one before adding PATH.
        options.read(true);
    } else {
        match flags & ACCESS_MODE_MASK {
            O_RDONLY => {
                options.read(true);
            }
            O_WRONLY => {
                options.write(true);
            }
            O_RDWR => {
                options.read(true).write(true);
            }
            _ => {}
        };
        if flags & O_APPEND != 0 {
            options.append(true);
        }
        if flags & O_TRUNC != 0 {
            options.truncate(true);
        }
        if flags & O_CREAT != 0 {
            options.create(true);
        }
        if flags & O_EXCL != 0 {
            options.create_new(true);
        }
    }
    if flags & O_DIRECTORY != 0 {
        options.directory(true);
    }
    if flags & O_NOFOLLOW != 0 {
        options.no_follow(true);
    }
    if flags & O_DIRECT != 0 && flags & O_PATH == 0 {
        options.direct(true);
    }
    options
}

const ACCESS_MODE_MASK: u32 = 0b11;
const SETFL_MUTABLE_FLAGS: u32 = O_NONBLOCK | O_APPEND;

fn open_status_flags(flags: u32) -> u32 {
    if flags & O_PATH != 0 {
        flags & (O_PATH | O_DIRECTORY | O_NOFOLLOW)
    } else {
        flags & (ACCESS_MODE_MASK | O_APPEND | O_NONBLOCK | O_DIRECTORY | O_NOFOLLOW | O_DIRECT)
    }
}

fn linux_ret_from_error(err: AxError) -> isize {
    -LinuxError::from(err).code() as isize
}

fn location_path(loc: &Location) -> String {
    loc.absolute_path()
        .map_or_else(|_| "<path-error>".to_string(), |path| path.to_string())
}

fn openat_context_paths() -> (String, String) {
    FS_CONTEXT.try_lock().map_or_else(
        || ("<fs-busy>".to_string(), "<fs-busy>".to_string()),
        |fs| {
            (
                location_path(fs.current_dir()),
                location_path(fs.root_dir()),
            )
        },
    )
}

fn openat_base_path(dirfd: c_int, path: &str) -> String {
    if Path::new(path).is_absolute() {
        return "<absolute-uses-root>".to_string();
    }
    if dirfd == AT_FDCWD {
        return FS_CONTEXT.try_lock().map_or_else(
            || "<cwd-busy>".to_string(),
            |fs| location_path(fs.current_dir()),
        );
    }
    Directory::from_fd(dirfd).map_or_else(
        |err| format!("<dirfd-error:{err:?}>"),
        |dir| location_path(dir.inner()),
    )
}

fn openat_path_branch(dirfd: c_int, path: &str) -> &'static str {
    if path.is_empty() {
        "empty"
    } else if Path::new(path).is_absolute() {
        "absolute"
    } else if dirfd == AT_FDCWD {
        "relative_cwd"
    } else {
        "relative_dirfd"
    }
}

fn trace_openat(
    stage: &str,
    dirfd: c_int,
    path: &str,
    flags: i32,
    mode: __kernel_mode_t,
    detail: core::fmt::Arguments<'_>,
) {
    if !stats::deep_trace_enabled() {
        return;
    }
    let curr = current();
    let thread = curr.as_thread();
    let regs = thread.user_regs_snapshot();
    let (cwd, root) = openat_context_paths();
    let base = openat_base_path(dirfd, path);
    let detail = format!("{detail}");
    let task_name = curr.name().to_string();
    let raw_flags = flags as u32;
    stats::record_deep_event(
        "openat",
        format_args!(
            "stage={} pid={} tid={} task={} user_pc={:#x} user_sp={:#x} dirfd={} path={:?} \
             flags={:#x} mode={:#o} branch={} cwd={:?} root={:?} base={:?} o_directory={} \
             o_nofollow={} o_creat={} o_excl={} o_trunc={} o_cloexec={} trailing_slash={} {}",
            stage,
            thread.proc_data.proc.pid(),
            curr.id().as_u64(),
            task_name,
            regs.pc,
            regs.sp,
            dirfd,
            path,
            flags,
            mode,
            openat_path_branch(dirfd, path),
            cwd,
            root,
            base,
            raw_flags & O_DIRECTORY != 0,
            raw_flags & O_NOFOLLOW != 0,
            raw_flags & O_CREAT != 0,
            raw_flags & O_EXCL != 0,
            raw_flags & O_TRUNC != 0,
            raw_flags & O_CLOEXEC != 0,
            path.len() > 1 && path.ends_with('/'),
            detail,
        ),
    );
    warn!(
        "deep_openat stage={} pid={} tid={} task={} user_pc={:#x} user_sp={:#x} dirfd={} \
         path={:?} flags={:#x} mode={:#o} branch={} cwd={:?} root={:?} base={:?} o_directory={} \
         o_nofollow={} o_creat={} o_excl={} o_trunc={} o_cloexec={} trailing_slash={} {}",
        stage,
        thread.proc_data.proc.pid(),
        curr.id().as_u64(),
        task_name,
        regs.pc,
        regs.sp,
        dirfd,
        path,
        flags,
        mode,
        openat_path_branch(dirfd, path),
        cwd,
        root,
        base,
        raw_flags & O_DIRECTORY != 0,
        raw_flags & O_NOFOLLOW != 0,
        raw_flags & O_CREAT != 0,
        raw_flags & O_EXCL != 0,
        raw_flags & O_TRUNC != 0,
        raw_flags & O_CLOEXEC != 0,
        path.len() > 1 && path.ends_with('/'),
        detail,
    );
}

fn add_to_fd(result: OpenResult, flags: u32) -> AxResult<i32> {
    let f: Arc<dyn FileLike> = match result {
        OpenResult::File(mut file) => {
            // /dev/xx handling
            if let Ok(device) = file.location().entry().downcast::<Device>() {
                let inner = device.inner().as_any();
                if let Some(ptmx) = inner.downcast_ref::<tty::Ptmx>() {
                    // Opening /dev/ptmx creates a new pseudo-terminal
                    let (master, pty_number) = ptmx.create_pty()?;
                    // TODO: this is cursed
                    let pts = FS_CONTEXT.lock().resolve("/dev/pts")?;
                    let entry = DirEntry::new_file(
                        FileNode::new(master),
                        NodeType::CharacterDevice,
                        Reference::new(Some(pts.entry().clone()), pty_number.to_string()),
                    );
                    let loc = Location::new(file.location().mountpoint().clone(), entry);
                    file = ax_fs::File::new(FileBackend::Direct(loc), file.flags());
                } else if inner.is::<tty::CurrentTty>() {
                    let term = current()
                        .as_thread()
                        .proc_data
                        .proc
                        .group()
                        .session()
                        .terminal()
                        .ok_or(AxError::NotFound)?;
                    let path = if term.is::<tty::NTtyDriver>() {
                        "/dev/console".to_string()
                    } else if let Some(pts) = term.downcast_ref::<tty::PtyDriver>() {
                        format!("/dev/pts/{}", pts.pty_number())
                    } else {
                        panic!("unknown terminal type")
                    };
                    let loc = FS_CONTEXT.lock().resolve(&path)?;
                    file = ax_fs::File::new(FileBackend::Direct(loc), file.flags());
                }
            }
            Arc::new(File::new(file, flags))
        }
        OpenResult::Dir(dir) => Arc::new(Directory::new(dir)),
    };
    if flags & O_NONBLOCK != 0 {
        f.set_nonblocking(true)?;
    }
    add_file_like_with_status_flags(f, flags & O_CLOEXEC != 0, open_status_flags(flags))
}

/// Open or create a file.
/// fd: file descriptor
/// filename: file path to be opened or created
/// flags: open flags
/// mode: see man 7 inode
/// return new file descriptor if succeed, or return -1.
pub fn sys_openat(
    dirfd: c_int,
    path: *const c_char,
    flags: i32,
    mode: __kernel_mode_t,
) -> AxResult<isize> {
    let path = vm_load_string(path)?;
    debug!("sys_openat <= {dirfd} {path:?} {flags:#o} {mode:#o}");
    stats::record_deep_event(
        "openat",
        format_args!(
            "openat_enter dirfd={} path={:?} flags={:#x} mode={:#o}",
            dirfd, path, flags, mode
        ),
    );
    trace_openat("enter", dirfd, &path, flags, mode, format_args!(""));

    let mode = mode & !current().as_thread().proc_data.umask();

    let mut options = flags_to_options(flags, mode, (sys_geteuid()? as _, sys_getegid()? as _));
    if flags as u32 & O_PATH == 0
        && (path.ends_with("/.package-cache") || path.ends_with("/.global-cache"))
    {
        stats::record_deep_event(
            "openat",
            format_args!(
                "openat_cargo_cache_marker_direct path={:?} flags={:#x}",
                path, flags
            ),
        );
        options.direct(true);
    }
    let effective_dirfd = if Path::new(path.as_str()).is_absolute() {
        AT_FDCWD
    } else {
        dirfd
    };
    trace_openat(
        "path_walk_step",
        dirfd,
        &path,
        flags,
        mode,
        format_args!("effective_dirfd={}", effective_dirfd),
    );
    let opened = with_fs(effective_dirfd, |fs| options.open(fs, path.clone()));
    let opened = match opened {
        Ok(opened) => {
            stats::record_deep_event(
                "openat",
                format_args!(
                    "openat_open_ok dirfd={} path={:?} flags={:#x}",
                    dirfd, path, flags
                ),
            );
            let opened_kind = match &opened {
                OpenResult::File(file) => {
                    format!("opened=file target={:?}", location_path(file.location()))
                }
                OpenResult::Dir(dir) => format!("opened=dir target={:?}", location_path(dir)),
            };
            trace_openat(
                "open_ok",
                dirfd,
                &path,
                flags,
                mode,
                format_args!("{}", opened_kind),
            );
            opened
        }
        Err(err) => {
            let ret = linux_ret_from_error(err);
            let errno = LinuxError::from(err);
            stats::record_deep_event(
                "openat",
                format_args!(
                    "openat_err dirfd={} path={:?} flags={:#x} mode={:#o} ret={} errno={:?} \
                     err={:?}",
                    dirfd, path, flags, mode, ret, errno, err
                ),
            );
            trace_openat(
                "exit",
                dirfd,
                &path,
                flags,
                mode,
                format_args!("ret={} errno={:?} err={:?}", ret, errno, err),
            );
            return Err(err);
        }
    };
    stats::record_deep_event(
        "openat",
        format_args!("openat_add_fd_enter path={:?} flags={:#x}", path, flags),
    );
    if stats::deep_trace_enabled() {
        warn!(
            "deep_openat stage=add_fd_enter path={:?} flags={:#x}",
            path, flags
        );
    }
    let fd = match add_to_fd(opened, flags as _) {
        Ok(fd) => fd,
        Err(err) => {
            let ret = linux_ret_from_error(err);
            let errno = LinuxError::from(err);
            trace_openat(
                "exit",
                dirfd,
                &path,
                flags,
                mode,
                format_args!("ret={} errno={:?} err={:?}", ret, errno, err),
            );
            return Err(err);
        }
    };
    stats::record_deep_event(
        "openat",
        format_args!("openat_add_fd_ok path={:?} fd={}", path, fd),
    );
    trace_openat(
        "exit",
        dirfd,
        &path,
        flags,
        mode,
        format_args!("ret={} fd={}", fd, fd),
    );
    Ok(fd as isize)
}

fn path_lexically_stays_beneath(rel: &str) -> bool {
    let mut depth = 0i32;
    for comp in rel.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => depth += 1,
        }
    }
    true
}

/// `openat2(2)` — subset: `resolve == 0` behaves like `openat`; `RESOLVE_BENEATH` rejects
/// absolute paths and lexical `..` escapes beyond `dirfd`.
pub fn sys_openat2(
    dirfd: c_int,
    pathname: *const c_char,
    how: *const open_how,
    hsize: usize,
) -> AxResult<isize> {
    if how.is_null() || hsize < size_of::<open_how>() {
        return Err(AxError::InvalidInput);
    }
    let how = unsafe { how.vm_read_uninit()?.assume_init() };
    let resolve = how.resolve;
    if resolve != 0 && resolve != RESOLVE_BENEATH as u64 {
        return Err(AxError::InvalidInput);
    }
    if resolve == 0 {
        return sys_openat(
            dirfd,
            pathname,
            how.flags as i32,
            how.mode as __kernel_mode_t,
        );
    }

    let path = vm_load_string(pathname)?;
    debug!(
        "sys_openat2 <= {dirfd} {path:?} flags={:#x} resolve={resolve}",
        how.flags
    );
    if Path::new(path.as_str()).is_absolute() || !path_lexically_stays_beneath(path.as_str()) {
        return Err(AxError::from(LinuxError::EACCES));
    }

    let mode = (how.mode as __kernel_mode_t) & !current().as_thread().proc_data.umask();
    let options = flags_to_options(
        how.flags as i32,
        mode,
        (sys_geteuid()? as _, sys_getegid()? as _),
    );
    with_fs(dirfd, |fs| options.open(fs, path))
        .and_then(|it| add_to_fd(it, how.flags as _))
        .map(|fd| fd as isize)
}

/// Open a file by `filename` and insert it into the file descriptor table.
///
/// Return its index in the file table (`fd`). Return `EMFILE` if it already
/// has the maximum number of files open.
#[cfg(target_arch = "x86_64")]
pub fn sys_open(path: *const c_char, flags: i32, mode: __kernel_mode_t) -> AxResult<isize> {
    sys_openat(AT_FDCWD as _, path, flags, mode)
}

pub fn sys_close(fd: c_int) -> AxResult<isize> {
    debug!("sys_close <= {fd}");
    close_file_like(fd)?;
    Ok(0)
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    struct CloseRangeFlags: u32 {
        const UNSHARE = 1 << 1;
        const CLOEXEC = 1 << 2;
    }
}

pub fn sys_close_range(first: i32, last: i32, flags: u32) -> AxResult<isize> {
    if first < 0 || last < first {
        return Err(AxError::InvalidInput);
    }
    let flags = CloseRangeFlags::from_bits(flags).ok_or(AxError::InvalidInput)?;
    debug!("sys_close_range <= fds: [{first}, {last}], flags: {flags:?}");
    if flags.contains(CloseRangeFlags::UNSHARE) {
        // TODO: optimize
        let curr = current();
        let mut scope = curr.as_thread().proc_data.scope.write();
        let mut guard = FD_TABLE.scope_mut(&mut scope);
        let old_files = mem::take(guard.deref_mut());
        old_files.write().clone_from(old_files.read().deref());
    }

    let cloexec = flags.contains(CloseRangeFlags::CLOEXEC);
    let mut fd_table = FD_TABLE.write();
    if let Some(max_index) = fd_table.ids().next_back() {
        for fd in first..=last.min(max_index as i32) {
            if cloexec {
                if let Some(f) = fd_table.get_mut(fd as _) {
                    f.cloexec = true;
                }
            } else {
                let _ = close_file_like(fd);
            }
        }
    }

    Ok(0)
}

fn dup_fd(old_fd: c_int, cloexec: bool) -> AxResult<isize> {
    if old_fd < 0 {
        return Err(AxError::BadFileDescriptor);
    }
    let mut desc = FD_TABLE
        .read()
        .get(old_fd as _)
        .cloned()
        .ok_or(AxError::BadFileDescriptor)?;
    desc.cloexec = cloexec;
    let new_fd = add_file_descriptor(desc)?;
    Ok(new_fd as _)
}

fn dup_fd_from(old_fd: c_int, min_fd: c_int, cloexec: bool) -> AxResult<isize> {
    if old_fd < 0 {
        return Err(AxError::BadFileDescriptor);
    }
    let mut desc = FD_TABLE
        .read()
        .get(old_fd as _)
        .cloned()
        .ok_or(AxError::BadFileDescriptor)?;
    desc.cloexec = cloexec;
    let new_fd = add_file_descriptor_from(desc, min_fd)?;
    Ok(new_fd as _)
}

pub fn sys_dup(old_fd: c_int) -> AxResult<isize> {
    debug!("sys_dup <= {old_fd}");
    dup_fd(old_fd, false)
}

#[cfg(target_arch = "x86_64")]
pub fn sys_dup2(old_fd: c_int, new_fd: c_int) -> AxResult<isize> {
    if old_fd == new_fd {
        get_file_like(new_fd)?;
        return Ok(new_fd as _);
    }
    sys_dup3(old_fd, new_fd, 0)
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Dup3Flags: c_int {
        const O_CLOEXEC = O_CLOEXEC as _; // Close on exec
    }
}

pub fn sys_dup3(old_fd: c_int, new_fd: c_int, flags: c_int) -> AxResult<isize> {
    let flags = Dup3Flags::from_bits(flags).ok_or(AxError::InvalidInput)?;
    debug!("sys_dup3 <= old_fd: {old_fd}, new_fd: {new_fd}, flags: {flags:?}");

    if old_fd == new_fd {
        return Err(AxError::InvalidInput);
    }
    if old_fd < 0 || new_fd < 0 {
        return Err(AxError::BadFileDescriptor);
    }

    let mut fd_table = FD_TABLE.write();
    let mut f = fd_table
        .get(old_fd as _)
        .cloned()
        .ok_or(AxError::BadFileDescriptor)?;
    f.cloexec = flags.contains(Dup3Flags::O_CLOEXEC);

    // 直接 remove（不能调 close_file_like，它会再 lock FD_TABLE 死锁）
    let removed = fd_table.remove(new_fd as _);
    fd_table
        .add_at(new_fd as _, f)
        .map_err(|_| AxError::BadFileDescriptor)?;
    drop(fd_table);
    // 锁释放后做 lock-cleanup（避免持锁时调 record_lock/flock 又拿别的锁）
    if let Some(old) = removed {
        let sc = Arc::strong_count(&old.inner);
        if sc == 1 {
            if let Ok(arc_file) = old.inner.clone().downcast_arc::<File>() {
                if let Ok(st) = arc_file.stat() {
                    let key = (st.dev, st.ino);
                    flock::on_last_file_ref_drop(key, &old.inner);
                    record_lock::release_ofd(Arc::as_ptr(&old.inner) as *const () as usize);
                }
            }
        }
    }

    Ok(new_fd as _)
}

fn lock_inode_key(file: &File) -> AxResult<record_lock::InodeKey> {
    let st = file.stat()?;
    Ok((st.dev, st.ino))
}

fn resolve_record_range(file: &File, fl: &flock64) -> AxResult<(u64, u64)> {
    let cur_off = file.inner().seek(SeekFrom::Current(0))? as u64;
    let size = file.stat()?.size;
    let base = match fl.l_whence as c_int {
        0 => 0u64,
        1 => cur_off,
        2 => size,
        _ => return Err(AxError::InvalidInput),
    };
    let start = (base as i128).saturating_add(fl.l_start as i128).max(0) as u64;
    let end = if fl.l_len == 0 {
        u64::MAX
    } else {
        (start as i128).saturating_add(fl.l_len as i128).max(0) as u64
    };
    if end < start {
        return Err(AxError::InvalidInput);
    }
    Ok((start, end))
}

pub fn sys_fcntl(fd: c_int, cmd: c_int, arg: usize) -> AxResult<isize> {
    debug!("sys_fcntl <= fd: {fd} cmd: {cmd} arg: {arg}");

    match cmd as u32 {
        F_DUPFD => dup_fd_from(
            fd,
            arg.try_into().map_err(|_| AxError::InvalidInput)?,
            false,
        ),
        F_DUPFD_CLOEXEC => {
            dup_fd_from(fd, arg.try_into().map_err(|_| AxError::InvalidInput)?, true)
        }
        F_SETLK | F_SETLKW => {
            let file = File::from_fd(fd)?;
            let key = lock_inode_key(&file)?;
            let fl = UserPtr::<flock64>::from(arg).get_as_mut()?;
            let range = resolve_record_range(&file, fl)?;
            let owner = record_lock::RLOwner::Posix(current().as_thread().proc_data.proc.pid());
            let blocking = cmd as u32 == F_SETLKW;
            record_lock::setlk(key, owner, range, fl.l_type, blocking)?;
            Ok(0)
        }
        F_OFD_SETLK | F_OFD_SETLKW => {
            let file = File::from_fd(fd)?;
            let key = lock_inode_key(&file)?;
            let arc = get_file_like(fd)?;
            let fl = UserPtr::<flock64>::from(arg).get_as_mut()?;
            let range = resolve_record_range(&file, fl)?;
            let owner = record_lock::RLOwner::Ofd(Arc::as_ptr(&arc) as *const () as usize);
            let blocking = cmd as u32 == F_OFD_SETLKW;
            record_lock::setlk(key, owner, range, fl.l_type, blocking)?;
            Ok(0)
        }
        F_GETLK | F_OFD_GETLK => {
            let file = File::from_fd(fd)?;
            let key = lock_inode_key(&file)?;
            let arc = get_file_like(fd)?;
            let ofd = cmd as u32 == F_OFD_GETLK;
            let owner = if ofd {
                record_lock::RLOwner::Ofd(Arc::as_ptr(&arc) as *const () as usize)
            } else {
                record_lock::RLOwner::Posix(current().as_thread().proc_data.proc.pid())
            };
            let fl = UserPtr::<flock64>::from(arg).get_as_mut()?;
            let range = resolve_record_range(&file, fl)?;
            record_lock::getlk(key, owner, range, fl)?;
            Ok(0)
        }
        F_SETLEASE | F_GETLEASE => Err(AxError::InvalidInput),
        F_SETOWN => {
            let file = File::from_fd(fd)?;
            file.fasync_set_owner(arg as i32);
            Ok(0)
        }
        F_GETOWN => {
            let file = File::from_fd(fd)?;
            Ok(file.fasync_get().0 as isize)
        }
        F_SETSIG => {
            let file = File::from_fd(fd)?;
            file.fasync_set_sig(arg as i32);
            Ok(0)
        }
        F_GETSIG => {
            let file = File::from_fd(fd)?;
            Ok(file.fasync_get().1 as isize)
        }
        F_SETFL => {
            let arg = u32::try_from(arg).map_err(|_| AxError::InvalidInput)?;
            let desc = FD_TABLE
                .read()
                .get(fd as _)
                .cloned()
                .ok_or(AxError::BadFileDescriptor)?;
            desc.inner.set_nonblocking(arg & O_NONBLOCK != 0)?;
            let current = desc.status_flags.load(Ordering::Acquire);
            let next = (current & !SETFL_MUTABLE_FLAGS) | (arg & SETFL_MUTABLE_FLAGS);
            desc.status_flags.store(next, Ordering::Release);
            Ok(0)
        }
        F_GETFL => {
            let desc = FD_TABLE
                .read()
                .get(fd as _)
                .cloned()
                .ok_or(AxError::BadFileDescriptor)?;
            let mut ret = desc.status_flags.load(Ordering::Acquire);
            if desc.inner.nonblocking() {
                ret |= O_NONBLOCK;
            } else {
                ret &= !O_NONBLOCK;
            }

            Ok(ret as _)
        }
        F_GETFD => {
            let cloexec = FD_TABLE
                .read()
                .get(fd as _)
                .ok_or(AxError::BadFileDescriptor)?
                .cloexec;
            Ok(if cloexec { FD_CLOEXEC as _ } else { 0 })
        }
        F_SETFD => {
            let cloexec = arg & FD_CLOEXEC as usize != 0;
            FD_TABLE
                .write()
                .get_mut(fd as _)
                .ok_or(AxError::BadFileDescriptor)?
                .cloexec = cloexec;
            Ok(0)
        }
        F_GETPIPE_SZ => {
            let pipe = Pipe::from_fd(fd)?;
            Ok(pipe.capacity() as _)
        }
        F_SETPIPE_SZ => {
            let pipe = Pipe::from_fd(fd)?;
            pipe.resize(arg)?;
            Ok(0)
        }
        _ => {
            warn!("unsupported fcntl parameters: cmd: {cmd}");
            Err(AxError::InvalidInput)
        }
    }
}

pub fn sys_flock(fd: c_int, operation: c_int) -> AxResult<isize> {
    debug!("flock <= fd: {fd}, operation: {operation}");
    let file = File::from_fd(fd)?;
    let key = lock_inode_key(&file)?;
    let arc = get_file_like(fd)?;
    flock::flock_inode(key, &arc, operation)?;
    Ok(0)
}
