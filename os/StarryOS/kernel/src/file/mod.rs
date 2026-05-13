pub mod epoll;
pub mod event;
pub(crate) mod flock;
mod fs;
mod net;
mod pidfd;
mod pipe;
pub(crate) mod record_lock;
pub mod signalfd;

use alloc::{borrow::Cow, sync::Arc, vec::Vec};
use core::{ffi::c_int, sync::atomic::AtomicU32, time::Duration};

use ax_errno::{AxError, AxResult};
use ax_fs::{FS_CONTEXT, FileBackend, FileFlags, OpenOptions};
use ax_io::prelude::*;
use ax_task::current;
use axfs_ng_vfs::DeviceId;
use axpoll::Pollable;
use downcast_rs::{DowncastSync, impl_downcast};
use flatten_objects::FlattenObjects;
use linux_raw_sys::general::{
    O_RDONLY, O_WRONLY, RLIMIT_NOFILE, STATX_BASIC_STATS, STATX_MNT_ID, stat, statx,
    statx_timestamp,
};
use spin::RwLock;

pub use self::{
    fs::{Directory, File, resolve_at, with_fs},
    net::Socket,
    pidfd::PidFd,
    pipe::Pipe,
};
use crate::{
    pseudofs::DeviceMmap,
    task::{AX_FILE_LIMIT, AsThread},
};

#[derive(Debug, Clone, Copy)]
pub struct Kstat {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub blksize: u32,
    pub blocks: u64,
    pub rdev: DeviceId,
    pub atime: Duration,
    pub mtime: Duration,
    pub ctime: Duration,
}

impl Default for Kstat {
    fn default() -> Self {
        Self {
            dev: 0,
            ino: 1,
            nlink: 1,
            mode: 0,
            uid: 1,
            gid: 1,
            size: 0,
            blksize: 4096,
            blocks: 0,
            rdev: DeviceId::default(),
            atime: Duration::default(),
            mtime: Duration::default(),
            ctime: Duration::default(),
        }
    }
}

impl From<Kstat> for stat {
    fn from(value: Kstat) -> Self {
        // SAFETY: valid for stat
        let mut stat: stat = unsafe { core::mem::zeroed() };
        stat.st_dev = value.dev as _;
        stat.st_ino = value.ino as _;
        stat.st_nlink = value.nlink as _;
        stat.st_mode = value.mode as _;
        stat.st_uid = value.uid as _;
        stat.st_gid = value.gid as _;
        stat.st_size = value.size as _;
        stat.st_blksize = value.blksize as _;
        stat.st_blocks = value.blocks as _;
        stat.st_rdev = value.rdev.0 as _;

        stat.st_atime = value.atime.as_secs() as _;
        stat.st_atime_nsec = value.atime.subsec_nanos() as _;
        stat.st_mtime = value.mtime.as_secs() as _;
        stat.st_mtime_nsec = value.mtime.subsec_nanos() as _;
        stat.st_ctime = value.ctime.as_secs() as _;
        stat.st_ctime_nsec = value.ctime.subsec_nanos() as _;

        stat
    }
}

impl From<Kstat> for statx {
    fn from(value: Kstat) -> Self {
        // SAFETY: valid for statx
        let mut statx: statx = unsafe { core::mem::zeroed() };
        statx.stx_mask = STATX_BASIC_STATS | STATX_MNT_ID;
        statx.stx_blksize = value.blksize as _;
        statx.stx_attributes = 0;
        statx.stx_nlink = value.nlink as _;
        statx.stx_uid = value.uid as _;
        statx.stx_gid = value.gid as _;
        statx.stx_mode = value.mode as _;
        statx.stx_ino = value.ino as _;
        statx.stx_size = value.size as _;
        statx.stx_blocks = value.blocks as _;
        statx.stx_attributes_mask = 0;
        statx.stx_rdev_major = value.rdev.major();
        statx.stx_rdev_minor = value.rdev.minor();

        fn time_to_statx(time: &Duration) -> statx_timestamp {
            statx_timestamp {
                tv_sec: time.as_secs() as _,
                tv_nsec: time.subsec_nanos() as _,
                __reserved: 0,
            }
        }
        statx.stx_atime = time_to_statx(&value.atime);
        statx.stx_ctime = time_to_statx(&value.ctime);
        statx.stx_mtime = time_to_statx(&value.mtime);

        statx.stx_dev_major = (value.dev >> 32) as _;
        statx.stx_dev_minor = value.dev as _;

        statx
    }
}

pub trait WriteBuf: Write + IoBufMut {}
impl<T: Write + IoBufMut> WriteBuf for T {}
pub type IoDst<'a> = dyn WriteBuf + 'a;

pub trait ReadBuf: Read + IoBuf {}
impl<T: Read + IoBuf> ReadBuf for T {}
pub type IoSrc<'a> = dyn ReadBuf + 'a;

#[allow(dead_code)]
pub trait FileLike: Pollable + DowncastSync {
    fn read(&self, _dst: &mut IoDst) -> AxResult<usize> {
        Err(AxError::InvalidInput)
    }

    fn write(&self, _src: &mut IoSrc) -> AxResult<usize> {
        Err(AxError::InvalidInput)
    }

    fn stat(&self) -> AxResult<Kstat> {
        Ok(Kstat::default())
    }

    fn path(&self) -> Cow<'_, str>;

    fn file_mmap(&self) -> AxResult<(FileBackend, FileFlags)> {
        Err(AxError::BadFileDescriptor)
    }

    fn device_mmap(&self, _offset: u64) -> AxResult<DeviceMmap> {
        Err(AxError::BadFileDescriptor)
    }

    fn ioctl(&self, _cmd: u32, _arg: usize) -> AxResult<usize> {
        Err(AxError::NotATty)
    }

    fn nonblocking(&self) -> bool {
        false
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> AxResult {
        Ok(())
    }

    fn from_fd(fd: c_int) -> AxResult<Arc<Self>>
    where
        Self: Sized + 'static,
    {
        get_file_like(fd)?
            .downcast_arc()
            .map_err(|_| AxError::InvalidInput)
    }

    fn add_to_fd_table(self, cloexec: bool) -> AxResult<c_int>
    where
        Self: Sized + 'static,
    {
        add_file_like(Arc::new(self), cloexec)
    }
}
impl_downcast!(sync FileLike);

#[derive(Clone)]
pub struct FileDescriptor {
    pub inner: Arc<dyn FileLike>,
    pub cloexec: bool,
    /// File status flags shared by duplicated descriptors for this open file description.
    pub status_flags: Arc<AtomicU32>,
}

scope_local::scope_local! {
    /// The current file descriptor table.
    pub static FD_TABLE: Arc<RwLock<FlattenObjects<FileDescriptor, AX_FILE_LIMIT>>> = Arc::default();
}

/// Get a file-like object by `fd`.
pub fn get_file_like(fd: c_int) -> AxResult<Arc<dyn FileLike>> {
    FD_TABLE
        .read()
        .get(fd as usize)
        .map(|fd| fd.inner.clone())
        .ok_or(AxError::BadFileDescriptor)
}

/// Add a file to the file descriptor table.
pub fn add_file_like(f: Arc<dyn FileLike>, cloexec: bool) -> AxResult<c_int> {
    add_file_like_with_status_flags(f, cloexec, 0)
}

/// Add a file to the file descriptor table with initial file status flags.
pub fn add_file_like_with_status_flags(
    f: Arc<dyn FileLike>,
    cloexec: bool,
    status_flags: u32,
) -> AxResult<c_int> {
    let max_nofile = current().as_thread().proc_data.rlim.read()[RLIMIT_NOFILE].current;
    let mut table = FD_TABLE.write();
    if table.count() as u64 >= max_nofile {
        return Err(AxError::TooManyOpenFiles);
    }
    let fd = FileDescriptor {
        inner: f,
        cloexec,
        status_flags: Arc::new(AtomicU32::new(status_flags)),
    };
    Ok(table.add(fd).map_err(|_| AxError::TooManyOpenFiles)? as c_int)
}

/// Add a descriptor to the descriptor table using the lowest available fd.
pub fn add_file_descriptor(fd: FileDescriptor) -> AxResult<c_int> {
    let max_nofile = current().as_thread().proc_data.rlim.read()[RLIMIT_NOFILE].current;
    let mut table = FD_TABLE.write();
    if table.count() as u64 >= max_nofile {
        return Err(AxError::TooManyOpenFiles);
    }
    Ok(table.add(fd).map_err(|_| AxError::TooManyOpenFiles)? as c_int)
}

/// Add a descriptor to the descriptor table using the lowest available fd >= `min_fd`.
pub fn add_file_descriptor_from(desc: FileDescriptor, min_fd: c_int) -> AxResult<c_int> {
    if min_fd < 0 {
        return Err(AxError::InvalidInput);
    }

    let max_nofile = current().as_thread().proc_data.rlim.read()[RLIMIT_NOFILE].current;
    let min_fd = min_fd as usize;
    if min_fd as u64 >= max_nofile {
        return Err(AxError::InvalidInput);
    }

    let mut table = FD_TABLE.write();
    if table.count() as u64 >= max_nofile {
        return Err(AxError::TooManyOpenFiles);
    }

    let end = (max_nofile as usize).min(AX_FILE_LIMIT);
    let Some(fd) = (min_fd..end).find(|fd| !table.is_assigned(*fd)) else {
        return Err(AxError::TooManyOpenFiles);
    };
    Ok(table
        .add_at(fd, desc)
        .map_err(|_| AxError::TooManyOpenFiles)? as c_int)
}

/// Close a file by `fd`.
pub fn close_file_like(fd: c_int) -> AxResult {
    let f = FD_TABLE
        .write()
        .remove(fd as usize)
        .ok_or(AxError::BadFileDescriptor)?;
    let sc = Arc::strong_count(&f.inner);
    debug!("close_file_like <= count: {sc}");
    if sc == 1 {
        if let Ok(arc_file) = f.inner.clone().downcast_arc::<File>() {
            if let Ok(st) = arc_file.stat() {
                let key = (st.dev, st.ino);
                flock::on_last_file_ref_drop(key, &f.inner);
                record_lock::release_ofd(Arc::as_ptr(&f.inner) as *const () as usize);
            }
        }
    }
    Ok(())
}

/// Close every descriptor owned by the current process fd table on process exit.
///
/// A table shared via `CLONE_FILES` must stay alive for the remaining sharers; in
/// that case the final drop of the shared `Arc` will release the descriptors.
pub fn close_file_table_for_exit() {
    if Arc::strong_count(&*FD_TABLE) != 1 {
        return;
    }

    let fds = FD_TABLE.read().ids().collect::<Vec<_>>();
    for fd in fds {
        let _ = close_file_like(fd as c_int);
    }
}

pub fn add_stdio(fd_table: &mut FlattenObjects<FileDescriptor, AX_FILE_LIMIT>) -> AxResult<()> {
    assert_eq!(fd_table.count(), 0);
    let cx = FS_CONTEXT.lock();
    let open = |options: &mut OpenOptions| {
        AxResult::Ok(Arc::new(File::new(
            options.open(&cx, "/dev/console")?.into_file()?,
        )))
    };

    let tty_in = open(OpenOptions::new().read(true).write(false))?;
    let tty_out = open(OpenOptions::new().read(false).write(true))?;
    fd_table
        .add(FileDescriptor {
            inner: tty_in,
            cloexec: false,
            status_flags: Arc::new(AtomicU32::new(O_RDONLY)),
        })
        .map_err(|_| AxError::TooManyOpenFiles)?;
    fd_table
        .add(FileDescriptor {
            inner: tty_out.clone(),
            cloexec: false,
            status_flags: Arc::new(AtomicU32::new(O_WRONLY)),
        })
        .map_err(|_| AxError::TooManyOpenFiles)?;
    fd_table
        .add(FileDescriptor {
            inner: tty_out,
            cloexec: false,
            status_flags: Arc::new(AtomicU32::new(O_WRONLY)),
        })
        .map_err(|_| AxError::TooManyOpenFiles)?;

    Ok(())
}
