use alloc::sync::Arc;
use core::ffi::c_int;

use ax_errno::{AxError, AxResult};
use bitflags::bitflags;
use linux_raw_sys::general::{O_CLOEXEC, O_NONBLOCK};
use starry_vm::VmMutPtr;

use crate::{
    file::{FileLike, Pipe, add_file_like_with_status_flags, close_file_like},
    syscall::stats,
};

bitflags! {
    /// Flags for the `pipe2` syscall.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct PipeFlags: u32 {
        /// Create a pipe with close-on-exec flag.
        const CLOEXEC = O_CLOEXEC;
        /// Create a non-blocking pipe.
        const NONBLOCK = O_NONBLOCK;
    }
}

pub fn sys_pipe2(fds: *mut [c_int; 2], flags: u32) -> AxResult<isize> {
    let flags = PipeFlags::from_bits(flags).ok_or(AxError::InvalidInput)?;

    let cloexec = flags.contains(PipeFlags::CLOEXEC);
    let (read_end, write_end) = Pipe::new();
    if flags.contains(PipeFlags::NONBLOCK) {
        read_end.set_nonblocking(true)?;
        write_end.set_nonblocking(true)?;
    }
    let status_flags = if flags.contains(PipeFlags::NONBLOCK) {
        O_NONBLOCK
    } else {
        0
    };
    let read_fd = add_file_like_with_status_flags(Arc::new(read_end), cloexec, status_flags)?;
    let write_fd = add_file_like_with_status_flags(
        Arc::new(write_end),
        cloexec,
        status_flags | linux_raw_sys::general::O_WRONLY,
    )
    .inspect_err(|_| close_file_like(read_fd).unwrap())?;

    fds.vm_write([read_fd, write_fd])?;

    debug!(
        "sys_pipe2 <= fds: {:?}, flags: {:?}",
        [read_fd, write_fd],
        flags
    );
    stats::record_deep_event(
        "pipe",
        format_args!(
            "pipe2 read_fd={} write_fd={} flags={:?} nonblock={}",
            read_fd,
            write_fd,
            flags,
            flags.contains(PipeFlags::NONBLOCK)
        ),
    );
    Ok(0)
}
