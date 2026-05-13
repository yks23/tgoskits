//! `/dev/syscall_stats_mm`：mmap 到内核 4KiB 统计页，syscall 入口由内核更新（见 `syscall::stats`）。

use core::any::Any;

use axfs_ng_vfs::{DeviceId, NodeFlags, VfsResult};

use crate::{
    pseudofs::{DeviceMmap, DeviceOps},
    syscall::stats,
};

/// 字符设备号（自定义，避免与常见 id 冲突）。
pub const SYSCALL_STATS_MM_DEVICE_ID: DeviceId = DeviceId::new(10, 201);

pub struct SyscallStatsMm;

impl DeviceOps for SyscallStatsMm {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let total = stats::total_invocations();
        let nr = stats::last_raw_sysno();
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&total.to_le_bytes());
        out[8..12].copy_from_slice(&nr.to_le_bytes());
        let skip = offset.min(16) as usize;
        let src = &out[skip..];
        let n = buf.len().min(src.len());
        buf[..n].copy_from_slice(&src[..n]);
        Ok(n)
    }

    fn write_at(&self, _buf: &[u8], _offset: u64) -> VfsResult<usize> {
        Ok(0)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn mmap(&self, _offset: u64) -> DeviceMmap {
        DeviceMmap::Physical(stats::syscall_stats_shm_phys_range())
    }

    fn flags(&self) -> NodeFlags {
        NodeFlags::NON_CACHEABLE
    }
}
