use alloc::vec;
use core::{ffi::c_char, mem::MaybeUninit};

use ax_config::ARCH;
use ax_errno::{AxError, AxResult, LinuxError};
use ax_fs::FS_CONTEXT;
use ax_task::current;
use linux_raw_sys::{
    general::{GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM},
    system::{new_utsname, sysinfo},
};
use starry_vm::{VmMutPtr, VmPtr, vm_read_slice, vm_write_slice};

use crate::task::{AsThread, processes};

pub fn sys_getuid() -> AxResult<isize> {
    Ok(current().as_thread().proc_data.res_uids().0 as isize)
}

pub fn sys_geteuid() -> AxResult<isize> {
    Ok(current().as_thread().proc_data.res_uids().1 as isize)
}

pub fn sys_getgid() -> AxResult<isize> {
    Ok(current().as_thread().proc_data.res_gids().0 as isize)
}

pub fn sys_getegid() -> AxResult<isize> {
    Ok(current().as_thread().proc_data.res_gids().1 as isize)
}

pub fn sys_setuid(_uid: u32) -> AxResult<isize> {
    debug!("sys_setuid <= uid: {_uid}");
    Ok(0)
}

pub fn sys_setgid(_gid: u32) -> AxResult<isize> {
    debug!("sys_setgid <= gid: {_gid}");
    Ok(0)
}

pub fn sys_getresuid(ruid: *mut u32, euid: *mut u32, suid: *mut u32) -> AxResult<isize> {
    let (r, e, s) = current().as_thread().proc_data.res_uids();
    if let Some(p) = ruid.nullable() {
        p.vm_write(r)?;
    }
    if let Some(p) = euid.nullable() {
        p.vm_write(e)?;
    }
    if let Some(p) = suid.nullable() {
        p.vm_write(s)?;
    }
    Ok(0)
}

pub fn sys_getresgid(rgid: *mut u32, egid: *mut u32, sgid: *mut u32) -> AxResult<isize> {
    let (r, e, s) = current().as_thread().proc_data.res_gids();
    if let Some(p) = rgid.nullable() {
        p.vm_write(r)?;
    }
    if let Some(p) = egid.nullable() {
        p.vm_write(e)?;
    }
    if let Some(p) = sgid.nullable() {
        p.vm_write(s)?;
    }
    Ok(0)
}

pub fn sys_getgroups(size: usize, list: *mut u32) -> AxResult<isize> {
    debug!("sys_getgroups <= size: {size}");
    if size < 1 {
        return Err(AxError::InvalidInput);
    }
    vm_write_slice(list, &[0])?;
    Ok(1)
}

pub fn sys_setgroups(_size: usize, _list: *const u32) -> AxResult<isize> {
    Ok(0)
}

const fn pad_str(info: &str) -> [c_char; 65] {
    let mut data: [c_char; 65] = [0; 65];
    // this needs #![feature(const_copy_from_slice)]
    // data[..info.len()].copy_from_slice(info.as_bytes());
    unsafe {
        core::ptr::copy_nonoverlapping(info.as_ptr().cast(), data.as_mut_ptr(), info.len());
    }
    data
}

const UTSNAME: new_utsname = new_utsname {
    sysname: pad_str("Linux"),
    nodename: pad_str("starry"),
    release: pad_str("10.0.0"),
    version: pad_str("10.0.0"),
    machine: pad_str(ARCH),
    domainname: pad_str("https://github.com/Starry-OS/StarryOS"),
};

pub fn sys_uname(name: *mut new_utsname) -> AxResult<isize> {
    name.vm_write(UTSNAME)?;
    Ok(0)
}

pub fn sys_sysinfo(info: *mut sysinfo) -> AxResult<isize> {
    // FIXME: Zeroable
    let mut kinfo: sysinfo = unsafe { core::mem::zeroed() };
    kinfo.procs = processes().len() as _;
    kinfo.mem_unit = 1;
    info.vm_write(kinfo)?;
    Ok(0)
}

pub fn sys_syslog(_type: i32, _buf: *mut c_char, _len: usize) -> AxResult<isize> {
    Ok(0)
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct GetRandomFlags: u32 {
        const NONBLOCK = GRND_NONBLOCK;
        const RANDOM = GRND_RANDOM;
        const INSECURE = GRND_INSECURE;
    }
}

pub fn sys_getrandom(buf: *mut u8, len: usize, flags: u32) -> AxResult<isize> {
    if len == 0 {
        return Ok(0);
    }
    let flags = GetRandomFlags::from_bits_retain(flags);

    debug!("sys_getrandom <= buf: {buf:p}, len: {len}, flags: {flags:?}");

    let path = if flags.contains(GetRandomFlags::RANDOM) {
        "/dev/random"
    } else {
        "/dev/urandom"
    };

    let f = FS_CONTEXT.lock().resolve(path)?;
    let mut kbuf = vec![0; len];
    let len = f.entry().as_file()?.read_at(&mut kbuf, 0)?;

    vm_write_slice(buf, &kbuf)?;

    Ok(len as _)
}

pub fn sys_seccomp(_op: u32, _flags: u32, _args: *const ()) -> AxResult<isize> {
    warn!("dummy sys_seccomp");
    Ok(0)
}

#[cfg(target_arch = "riscv64")]
pub fn sys_riscv_flush_icache() -> AxResult<isize> {
    riscv::asm::fence_i();
    Ok(0)
}

/// Linux `struct riscv_hwprobe` from `arch/riscv/include/uapi/asm/hwprobe.h`.
#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct RiscvHwprobe {
    key: i64,
    value: u64,
}

/// `riscv_hwprobe(2)` — glibc / rustc rely on this existing (not `ENOSYS`) on recent
/// Debian riscv64 userland. We answer a small fixed set of keys for QEMU virt-class
/// guests; unknown keys follow Linux semantics (`key = -1`, `value = 0`).
#[cfg(target_arch = "riscv64")]
pub fn sys_riscv_hwprobe(
    pairs: *mut (),
    pair_count: usize,
    cpusetsize: usize,
    cpus: *mut u8,
    flags: u32,
) -> AxResult<isize> {
    let pairs = pairs.cast::<RiscvHwprobe>();
    const RISCV_HWPROBE_WHICH_CPUS: u32 = 1 << 0;
    const KEY_MVENDORID: i64 = 0;
    const KEY_MARCHID: i64 = 1;
    const KEY_MIMPID: i64 = 2;
    const KEY_BASE_BEHAVIOR: i64 = 3;
    const KEY_IMA_EXT_0: i64 = 4;

    const BASE_BEHAVIOR_IMA: u64 = 1 << 0;
    const IMA_FD: u64 = 1 << 0;
    const IMA_C: u64 = 1 << 1;
    const EXT_ZAAMO: u64 = 1 << 56;
    const EXT_ZALRSC: u64 = 1 << 57;

    if flags != 0 && flags != RISCV_HWPROBE_WHICH_CPUS {
        return Err(AxError::from(LinuxError::EINVAL));
    }
    if flags == RISCV_HWPROBE_WHICH_CPUS {
        // Full CPU-mask reduction is not implemented yet.
        return Err(AxError::from(LinuxError::EINVAL));
    }
    if pair_count > 4096 {
        return Err(AxError::from(LinuxError::EINVAL));
    }
    if pairs.is_null() {
        return if pair_count == 0 {
            Ok(0)
        } else {
            Err(AxError::from(LinuxError::EFAULT))
        };
    }

    // Optional CPU set: NULL + 0 ⇒ all online CPUs (we expose a single hart).
    if cpusetsize != 0 || !cpus.is_null() {
        if cpus.is_null() || cpusetsize == 0 {
            return Err(AxError::from(LinuxError::EINVAL));
        }
        if cpusetsize > 128 {
            return Err(AxError::from(LinuxError::EINVAL));
        }
        let mut buffer = [0u8; 128];
        vm_read_slice(cpus.cast_const(), unsafe {
            core::slice::from_raw_parts_mut(
                buffer.as_mut_ptr().cast::<MaybeUninit<u8>>(),
                cpusetsize,
            )
        })?;
        let mask_init = &buffer[..cpusetsize];
        if !mask_init.iter().any(|&b| b != 0) {
            return Err(AxError::from(LinuxError::EINVAL));
        }
        if mask_init[0] & 1 == 0 {
            return Err(AxError::from(LinuxError::EINVAL));
        }
    }

    fn answer_pair(key: i64) -> (i64, u64) {
        match key {
            KEY_MVENDORID => (KEY_MVENDORID, 0),
            KEY_MARCHID => (KEY_MARCHID, 0),
            KEY_MIMPID => (KEY_MIMPID, 0),
            KEY_BASE_BEHAVIOR => (KEY_BASE_BEHAVIOR, BASE_BEHAVIOR_IMA),
            KEY_IMA_EXT_0 => (KEY_IMA_EXT_0, IMA_FD | IMA_C | EXT_ZAAMO | EXT_ZALRSC),
            _ => (-1, 0),
        }
    }

    for i in 0..pair_count {
        let elem = unsafe { pairs.add(i) };
        let cur = unsafe { elem.vm_read_uninit()?.assume_init() };
        let (k, v) = answer_pair(cur.key);
        elem.vm_write(RiscvHwprobe { key: k, value: v })?;
    }

    Ok(0)
}
