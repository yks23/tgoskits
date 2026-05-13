use alloc::{borrow::Cow, format, sync::Arc};
use core::{
    mem,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::Context,
};

use ax_errno::{AxError, AxResult};
use ax_memory_addr::PAGE_SIZE_4K;
use ax_sync::Mutex;
use ax_task::{
    current,
    future::{block_on, poll_io},
};
use axpoll::{IoEvents, PollSet, Pollable};
use linux_raw_sys::{general::S_IFIFO, ioctl::FIONREAD};
use ringbuf::{
    HeapRb,
    traits::{Consumer, Observer, Producer},
};
use starry_signal::{SignalInfo, Signo};
use starry_vm::VmMutPtr;

use super::{FileLike, Kstat};
use crate::{
    file::{IoDst, IoSrc},
    syscall::stats,
    task::{AsThread, send_signal_to_process},
};

const RING_BUFFER_INIT_SIZE: usize = 65536; // 64 KiB

struct Shared {
    buffer: Mutex<HeapRb<u8>>,
    poll_rx: PollSet,
    poll_tx: PollSet,
    poll_close: PollSet,
    readers: AtomicUsize,
    writers: AtomicUsize,
}

pub struct Pipe {
    read_side: bool,
    shared: Arc<Shared>,
    non_blocking: AtomicBool,
}
impl Drop for Pipe {
    fn drop(&mut self) {
        if self.is_read() {
            let readers = self.shared.readers.fetch_sub(1, Ordering::AcqRel);
            let woken = self.shared.poll_tx.wake();
            stats::record_deep_event(
                "pipe",
                format_args!(
                    "close_read pipe={:#x} readers_before={} writers={} tx_woken={}",
                    Arc::as_ptr(&self.shared) as usize,
                    readers,
                    self.shared.writers.load(Ordering::Acquire),
                    woken
                ),
            );
        } else {
            let writers = self.shared.writers.fetch_sub(1, Ordering::AcqRel);
            let woken = self.shared.poll_rx.wake();
            stats::record_deep_event(
                "pipe",
                format_args!(
                    "close_write pipe={:#x} readers={} writers_before={} rx_woken={}",
                    Arc::as_ptr(&self.shared) as usize,
                    self.shared.readers.load(Ordering::Acquire),
                    writers,
                    woken
                ),
            );
        }
        let close_woken = self.shared.poll_close.wake();
        stats::record_deep_event(
            "pipe",
            format_args!(
                "close_notify pipe={:#x} readers={} writers={} close_woken={}",
                Arc::as_ptr(&self.shared) as usize,
                self.shared.readers.load(Ordering::Acquire),
                self.shared.writers.load(Ordering::Acquire),
                close_woken
            ),
        );
    }
}

impl Pipe {
    pub fn new() -> (Pipe, Pipe) {
        let shared = Arc::new(Shared {
            buffer: Mutex::new(HeapRb::new(RING_BUFFER_INIT_SIZE)),
            poll_rx: PollSet::new(),
            poll_tx: PollSet::new(),
            poll_close: PollSet::new(),
            readers: AtomicUsize::new(1),
            writers: AtomicUsize::new(1),
        });
        let read_end = Pipe {
            read_side: true,
            shared: shared.clone(),
            non_blocking: AtomicBool::new(false),
        };
        let write_end = Pipe {
            read_side: false,
            shared,
            non_blocking: AtomicBool::new(false),
        };
        (read_end, write_end)
    }

    pub const fn is_read(&self) -> bool {
        self.read_side
    }

    pub const fn is_write(&self) -> bool {
        !self.read_side
    }

    pub fn closed(&self) -> bool {
        if self.is_read() {
            self.shared.writers.load(Ordering::Acquire) == 0
        } else {
            self.shared.readers.load(Ordering::Acquire) == 0
        }
    }

    pub fn capacity(&self) -> usize {
        self.shared.buffer.lock().capacity().get()
    }

    pub fn resize(&self, new_size: usize) -> AxResult<()> {
        let new_size = new_size.div_ceil(PAGE_SIZE_4K).max(1) * PAGE_SIZE_4K;

        let mut buffer = self.shared.buffer.lock();
        if new_size == buffer.capacity().get() {
            return Ok(());
        }
        if new_size < buffer.occupied_len() {
            return Err(AxError::ResourceBusy);
        }
        let old_buffer = mem::replace(&mut *buffer, HeapRb::new(new_size));
        let (left, right) = old_buffer.as_slices();
        buffer.push_slice(left);
        buffer.push_slice(right);
        Ok(())
    }
}

fn raise_pipe() {
    let curr = current();
    send_signal_to_process(
        curr.as_thread().proc_data.proc.pid(),
        Some(SignalInfo::new_kernel(Signo::SIGPIPE)),
    )
    .expect("Failed to send SIGPIPE");
}

impl FileLike for Pipe {
    fn read(&self, dst: &mut IoDst) -> AxResult<usize> {
        if !self.is_read() {
            return Err(AxError::BadFileDescriptor);
        }
        if dst.is_full() {
            return Ok(0);
        }

        block_on(poll_io(self, IoEvents::IN, self.nonblocking(), || {
            let read = {
                let cons = self.shared.buffer.lock();
                let (left, right) = cons.as_slices();
                let mut count = dst.write(left)?;
                if count >= left.len() {
                    count += dst.write(right)?;
                }
                unsafe { cons.advance_read_index(count) };
                count
            };
            if read > 0 {
                let woken = self.shared.poll_tx.wake();
                stats::record_deep_event(
                    "pipe",
                    format_args!(
                        "read_data pipe={:#x} bytes={} readers={} writers={} tx_woken={}",
                        Arc::as_ptr(&self.shared) as usize,
                        read,
                        self.shared.readers.load(Ordering::Acquire),
                        self.shared.writers.load(Ordering::Acquire),
                        woken
                    ),
                );
                Ok(read)
            } else if self.closed() {
                stats::record_deep_event(
                    "pipe",
                    format_args!(
                        "read_eof pipe={:#x} readers={} writers=0",
                        Arc::as_ptr(&self.shared) as usize,
                        self.shared.readers.load(Ordering::Acquire)
                    ),
                );
                Ok(0)
            } else {
                stats::record_deep_event(
                    "pipe",
                    format_args!(
                        "read_wouldblock pipe={:#x} readers={} writers={} len=0",
                        Arc::as_ptr(&self.shared) as usize,
                        self.shared.readers.load(Ordering::Acquire),
                        self.shared.writers.load(Ordering::Acquire)
                    ),
                );
                Err(AxError::WouldBlock)
            }
        }))
    }

    fn write(&self, src: &mut IoSrc) -> AxResult<usize> {
        if !self.is_write() {
            return Err(AxError::BadFileDescriptor);
        }
        let size = src.remaining();
        if size == 0 {
            return Ok(0);
        }

        let mut total_written = 0;

        block_on(poll_io(self, IoEvents::OUT, self.nonblocking(), || {
            if self.closed() {
                stats::record_deep_event(
                    "pipe",
                    format_args!(
                        "write_broken pipe={:#x} readers=0 writers={} remaining={}",
                        Arc::as_ptr(&self.shared) as usize,
                        self.shared.writers.load(Ordering::Acquire),
                        src.remaining()
                    ),
                );
                raise_pipe();
                return Err(AxError::BrokenPipe);
            }

            let written = {
                let mut prod = self.shared.buffer.lock();
                let (left, right) = prod.vacant_slices_mut();
                let mut count = src.read(unsafe { left.assume_init_mut() })?;
                if count >= left.len() {
                    count += src.read(unsafe { right.assume_init_mut() })?;
                }
                unsafe { prod.advance_write_index(count) };
                count
            };
            if written > 0 {
                let woken = self.shared.poll_rx.wake();
                total_written += written;
                stats::record_deep_event(
                    "pipe",
                    format_args!(
                        "write_data pipe={:#x} bytes={} total={} readers={} writers={} rx_woken={}",
                        Arc::as_ptr(&self.shared) as usize,
                        written,
                        total_written,
                        self.shared.readers.load(Ordering::Acquire),
                        self.shared.writers.load(Ordering::Acquire),
                        woken
                    ),
                );
                if total_written == size || self.nonblocking() {
                    return Ok(total_written);
                }
            }
            stats::record_deep_event(
                "pipe",
                format_args!(
                    "write_wouldblock pipe={:#x} total={} requested={} readers={} writers={}",
                    Arc::as_ptr(&self.shared) as usize,
                    total_written,
                    size,
                    self.shared.readers.load(Ordering::Acquire),
                    self.shared.writers.load(Ordering::Acquire)
                ),
            );
            Err(AxError::WouldBlock)
        }))
    }

    fn stat(&self) -> AxResult<Kstat> {
        Ok(Kstat {
            mode: S_IFIFO | if self.is_read() { 0o444 } else { 0o222 },
            ..Default::default()
        })
    }

    fn path(&self) -> Cow<'_, str> {
        format!("pipe:[{}]", self as *const _ as usize).into()
    }

    fn set_nonblocking(&self, nonblocking: bool) -> AxResult {
        self.non_blocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn nonblocking(&self) -> bool {
        self.non_blocking.load(Ordering::Acquire)
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> AxResult<usize> {
        match cmd {
            FIONREAD => {
                (arg as *mut u32).vm_write(self.shared.buffer.lock().occupied_len() as u32)?;
                Ok(0)
            }
            _ => Err(AxError::NotATty),
        }
    }
}

impl Pollable for Pipe {
    fn poll(&self) -> IoEvents {
        let mut events = IoEvents::empty();
        let buf = self.shared.buffer.lock();
        if self.read_side {
            events.set(IoEvents::IN, buf.occupied_len() > 0 || self.closed());
            events.set(IoEvents::HUP, self.closed());
        } else {
            events.set(IoEvents::OUT, buf.vacant_len() > 0 || self.closed());
            events.set(IoEvents::ERR, self.closed());
        }
        stats::record_deep_event(
            "pipe",
            format_args!(
                "poll pipe={:#x} side={} events={:#x} readers={} writers={} len={} cap={} \
                 nonblock={}",
                Arc::as_ptr(&self.shared) as usize,
                if self.read_side { "read" } else { "write" },
                events.bits(),
                self.shared.readers.load(Ordering::Acquire),
                self.shared.writers.load(Ordering::Acquire),
                buf.occupied_len(),
                buf.capacity().get(),
                self.nonblocking()
            ),
        );
        events
    }

    fn register(&self, context: &mut Context<'_>, events: IoEvents) {
        if events.contains(IoEvents::IN) {
            self.shared.poll_rx.register(context.waker());
        }
        if events.contains(IoEvents::OUT) {
            self.shared.poll_tx.register(context.waker());
        }
        self.shared.poll_close.register(context.waker());
    }
}
