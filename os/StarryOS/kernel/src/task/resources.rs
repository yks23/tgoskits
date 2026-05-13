//! Resource limits.

use core::ops::{Index, IndexMut};

use linux_raw_sys::general::{
    RLIM_NLIMITS, RLIM64_INFINITY, RLIMIT_AS, RLIMIT_DATA, RLIMIT_NOFILE, RLIMIT_NPROC,
    RLIMIT_STACK,
};

/// Maximum FD slots in the per-process table (RLIMIT_NOFILE hard cap).
// 注意：bitmaps crate 默认只支持 BitsImpl<N> N<=1024，超过会编译失败。
// flatten_objects 用 bitmaps，故 AX_FILE_LIMIT 上限是 1024。
// 自我编译实际用 cargo / rustc 经验上 1024 fd 已足，只是没法跑大并行 -j16+ 编译。
// 如果后续真要更高，需要改 bitmaps 或换 flatten_objects 实现。
pub const AX_FILE_LIMIT: usize = 1024;

/// Default soft limit for open file descriptors.
pub const AX_FILE_LIMIT_SOFT: u64 = 4096;

/// The limit for a specific resource
#[derive(Debug, Clone, Copy)]
pub struct Rlimit {
    /// The current limit for the resource (soft)
    pub current: u64,
    /// The maximum limit for the resource (hard)
    pub max: u64,
}

impl Default for Rlimit {
    fn default() -> Self {
        Self { current: 0, max: 0 }
    }
}

impl Rlimit {
    /// Creates a new `Rlimit` with the specified soft and hard limits.
    pub fn new(soft: u64, hard: u64) -> Self {
        Self {
            current: soft,
            max: hard,
        }
    }
}

impl From<u64> for Rlimit {
    fn from(value: u64) -> Self {
        Self {
            current: value,
            max: value,
        }
    }
}

/// Process resource limits
#[derive(Clone)]
pub struct Rlimits([Rlimit; RLIM_NLIMITS as usize]);

impl Default for Rlimits {
    fn default() -> Self {
        let mut result = Self(core::array::from_fn(|_| Rlimit::default()));
        // Match the Linux default (8 MiB) so applications like PostgreSQL
        // that compute safe recursion/stack-depth limits from getrlimit
        // get a consistent answer. USER_STACK_SIZE is kept in sync so the
        // advertised limit matches the mapped stack VMA.
        let stack = crate::config::USER_STACK_SIZE as u64;
        result[RLIMIT_STACK] = Rlimit::new(stack, stack);
        result[RLIMIT_NOFILE] = Rlimit::new(AX_FILE_LIMIT_SOFT, AX_FILE_LIMIT as u64);
        let as_bytes = crate::config::USER_SPACE_SIZE as u64;
        result[RLIMIT_AS] = Rlimit::new(as_bytes, as_bytes);
        let data_bytes = crate::config::USER_HEAP_SIZE_MAX as u64;
        result[RLIMIT_DATA] = Rlimit::new(data_bytes, data_bytes);
        result[RLIMIT_NPROC] = Rlimit::new(4096, 4096);
        result
    }
}

impl Index<u32> for Rlimits {
    type Output = Rlimit;

    fn index(&self, index: u32) -> &Self::Output {
        &self.0[index as usize]
    }
}

impl IndexMut<u32> for Rlimits {
    fn index_mut(&mut self, index: u32) -> &mut Self::Output {
        &mut self.0[index as usize]
    }
}

/// `true` if `v` means unlimited for rlimit64 values.
#[inline]
pub fn rlim_is_infinite(v: u64) -> bool {
    v == RLIM64_INFINITY as u64 || v == u64::MAX
}
