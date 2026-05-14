use alloc::{string::String, vec::Vec};
use core::fmt::Write as _;

use ax_errno::{AxError, AxResult};
use ax_hal::time::TimeValue;
use ax_task::future::{self, block_on, poll_io};
use axpoll::IoEvents;
use linux_raw_sys::general::{POLLNVAL, pollfd, timespec};
use starry_signal::SignalSet;

use super::FdPollSet;
use crate::{
    file::get_file_like,
    mm::{UserConstPtr, UserPtr, nullable},
    syscall::{signal::check_sigset_size, stats},
    task::with_blocked_signals,
    time::TimeValueLike,
};

fn poll_fds_summary(poll_fds: &[pollfd]) -> String {
    let mut out = String::new();
    for (idx, fd) in poll_fds.iter().take(8).enumerate() {
        let _ = write!(
            out,
            "{}:fd={} events={:#x} revents={:#x};",
            idx, fd.fd, fd.events, fd.revents
        );
    }
    if poll_fds.len() > 8 {
        let _ = write!(out, "...(+{})", poll_fds.len() - 8);
    }
    out
}

fn do_poll(
    poll_fds: &mut [pollfd],
    timeout: Option<TimeValue>,
    sigmask: Option<SignalSet>,
) -> AxResult<isize> {
    debug!("do_poll fds={poll_fds:?} timeout={timeout:?}");
    if stats::deep_trace_enabled() {
        stats::record_deep_event(
            "poll",
            format_args!(
                "enter nfds={} timeout={:?} fds={}",
                poll_fds.len(),
                timeout,
                poll_fds_summary(poll_fds)
            ),
        );
    }

    let mut res = 0isize;
    let mut fds = Vec::with_capacity(poll_fds.len());
    let mut revents = Vec::with_capacity(poll_fds.len());
    for fd in poll_fds.iter_mut() {
        if fd.fd == -1 {
            // Skip -1
            continue;
        }
        match get_file_like(fd.fd) {
            Ok(f) => {
                fds.push((
                    f,
                    IoEvents::from_bits(fd.events as _).ok_or(AxError::InvalidInput)?
                        | IoEvents::ALWAYS_POLL,
                ));
                revents.push(&mut fd.revents);
            }
            Err(_) => {
                // If the fd is invalid, set revents to POLLNVAL
                fd.revents = POLLNVAL as _;
                res += 1;
            }
        }
    }
    if res > 0 {
        if stats::deep_trace_enabled() {
            stats::record_deep_event(
                "poll",
                format_args!(
                    "exit_invalid ready={} fds={}",
                    res,
                    poll_fds_summary(poll_fds)
                ),
            );
        }
        return Ok(res);
    }
    let fds = FdPollSet(fds);

    let result = with_blocked_signals(sigmask, || {
        match block_on(future::timeout(
            timeout,
            poll_io(&fds, IoEvents::empty(), false, || {
                let mut res = 0usize;
                for ((fd, events), revents) in fds.0.iter().zip(revents.iter_mut()) {
                    let mut result = fd.poll();
                    if result.contains(IoEvents::IN) {
                        result |= IoEvents::RDNORM;
                    }
                    if result.contains(IoEvents::OUT) {
                        result |= IoEvents::WRNORM;
                    }
                    // POSIX: POLLHUP and POLLERR are always reported in revents,
                    // even if not requested in events. They must NOT be masked out.
                    let always_report =
                        result & (IoEvents::HUP | IoEvents::ERR | IoEvents::RDHUP | IoEvents::NVAL);
                    result &= *events;
                    result |= always_report;

                    **revents = result.bits() as _;
                    if **revents != 0 {
                        res += 1;
                    }
                }
                if res > 0 {
                    Ok(res as _)
                } else {
                    Err(AxError::WouldBlock)
                }
            }),
        )) {
            Ok(r) => r,
            Err(_) => Ok(0),
        }
    });
    if stats::deep_trace_enabled() {
        stats::record_deep_event(
            "poll",
            format_args!(
                "exit result={:?} fds={}",
                result,
                poll_fds_summary(poll_fds)
            ),
        );
    }
    result
}

#[cfg(target_arch = "x86_64")]
pub fn sys_poll(fds: UserPtr<pollfd>, nfds: u32, timeout: i32) -> AxResult<isize> {
    let fds = fds.get_as_mut_slice(nfds as usize)?;
    let timeout = if timeout < 0 {
        None
    } else {
        Some(TimeValue::from_millis(timeout as u64))
    };
    do_poll(fds, timeout, None)
}

pub fn sys_ppoll(
    fds: UserPtr<pollfd>,
    nfds: i32,
    timeout: UserConstPtr<timespec>,
    sigmask: UserConstPtr<SignalSet>,
    sigsetsize: usize,
) -> AxResult<isize> {
    check_sigset_size(sigsetsize)?;
    let fds = fds.get_as_mut_slice(nfds.try_into().map_err(|_| AxError::InvalidInput)?)?;
    let timeout = nullable!(timeout.get_as_ref())?
        .map(|ts| ts.try_into_time_value())
        .transpose()?;
    // Signal mask is passed through to do_poll -> with_blocked_signals, and
    // poll_io uses the interruptible wrapper so EINTR is correctly returned
    // when a signal arrives during blocking.
    do_poll(fds, timeout, nullable!(sigmask.get_as_ref())?.copied())
}
