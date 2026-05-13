use alloc::{format, string::ToString, sync::Arc};
use core::{
    ffi::{c_char, c_int},
    mem::{self, size_of},
    ops::{Deref, DerefMut},
};

use ax_errno::{AxError, AxResult, LinuxError};
use ax_fs::{FS_CONTEXT, FileBackend, OpenOptions, OpenResult};
use ax_io::{Seek, SeekFrom};
use ax_task::current;
use axfs_ng_vfs::{DirEntry, FileNode, Location, NodePermission, NodeType, Reference, path::Path};
use bitflags::bitflags;
use linux_raw_sys::general::{RESOLVE_BENEATH, open_how, *};
use starry_vm::VmPtr;

use crate::{
    file::{
        Directory, FD_TABLE, File, FileLike, Pipe, add_file_like, close_file_like, flock,
        get_file_like, record_lock, with_fs,
    },
    mm::{UserPtr, vm_load_string},
    pseudofs::{Device, dev::tty},
    task::AsThread,
};

/// Convert open flags to [`OpenOptions`].
fn flags_to_options(flags: c_int, mode: __kernel_mode_t, (uid, gid): (u32, u32)) -> OpenOptions {
    let flags = flags as u32;
    let mut options = OpenOptions::new();
    options.mode(mode).user(uid, gid);
    match flags & 0b11 {
        O_RDONLY => options.read(true),
        O_WRONLY => options.write(true),
        _ => options.read(true).write(true),
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
    if flags & O_PATH != 0 {
        options.path(true);
    }
    if flags & O_EXCL != 0 {
        options.create_new(true);
    }
    if flags & O_DIRECTORY != 0 {
        options.directory(true);
    }
    if flags & O_NOFOLLOW != 0 {
        options.no_follow(true);
    }
    if flags & O_DIRECT != 0 {
        options.direct(true);
    }
    options
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
    add_file_like(f, flags & O_CLOEXEC != 0)
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

    let mode = mode & !current().as_thread().proc_data.umask();

    let cred = current().as_thread().cred();
    let options = flags_to_options(flags, mode, (cred.fsuid, cred.fsgid));
    with_fs(dirfd, |fs| options.open(fs, path))
        .and_then(|it| add_to_fd(it, flags as _))
        .map(|fd| fd as isize)
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
    let f = get_file_like(old_fd)?;
    let new_fd = add_file_like(f, cloexec)?;
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
        F_DUPFD => dup_fd(fd, false),
        F_DUPFD_CLOEXEC => dup_fd(fd, true),
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
            get_file_like(fd)?.set_nonblocking(arg & (O_NONBLOCK as usize) > 0)?;
            Ok(0)
        }
        F_GETFL => {
            let f = get_file_like(fd)?;

            let mut ret = f.open_flags();
            if f.nonblocking() {
                ret |= O_NONBLOCK;
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
