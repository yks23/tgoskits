//! RISC-V specific page table structures.

use ax_memory_addr::VirtAddr;
use ax_page_table_entry::riscv::Rv64PTE;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{PageTable64, PageTable64Cursor, PagingMetaData};

/// Number of SMP harts for TLB shootdown. Initialized to 1 (UP).
static SMP_HART_COUNT: AtomicUsize = AtomicUsize::new(1);

/// A virtual address that can be used in RISC-V Sv39 and Sv48 page tables.
pub trait SvVirtAddr: ax_memory_addr::MemoryAddr + Send + Sync {
    /// Flush the TLB.
    fn flush_tlb(vaddr: Option<Self>);
}

/// Perform a remote TLB shootdown via SBI for SMP systems.
#[cfg(not(docsrs))]
#[inline]
pub fn remote_flush_tlb(vaddr: Option<VirtAddr>) {
    let n = SMP_HART_COUNT.load(Ordering::Relaxed);
    if n <= 1 {
        return;
    }
    let mut mask: usize = 0;
    for i in 0..n {
        mask |= 1 << (i % 64);
    }
    let hart_mask = sbi_rt::HartMask::from_mask_base(mask, 0);
    if let Some(vaddr) = vaddr {
        let _ = sbi_rt::remote_sfence_vma(hart_mask, vaddr.as_usize(), 4096);
    } else {
        let _ = sbi_rt::remote_sfence_vma(hart_mask, 0, 0);
    }
}

/// Set the number of SMP harts for TLB shootdown. Call during boot.
pub fn set_smp_hart_count(count: usize) {
    SMP_HART_COUNT.store(count, Ordering::Relaxed);
}

impl SvVirtAddr for VirtAddr {
    #[inline]
    fn flush_tlb(vaddr: Option<Self>) {
        if let Some(vaddr) = vaddr {
            riscv::asm::sfence_vma(0, vaddr.as_usize())
        } else {
            riscv::asm::sfence_vma_all();
        }
        #[cfg(not(docsrs))]
        remote_flush_tlb(vaddr);
    }
}

/// Metadata of RISC-V Sv39 page tables.
pub struct Sv39MetaData<VA: SvVirtAddr> {
    _virt_addr: core::marker::PhantomData<VA>,
}

/// Metadata of RISC-V Sv48 page tables.
pub struct Sv48MetaData<VA: SvVirtAddr> {
    _virt_addr: core::marker::PhantomData<VA>,
}

impl<VA: SvVirtAddr> PagingMetaData for Sv39MetaData<VA> {
    const LEVELS: usize = 3;
    const PA_MAX_BITS: usize = 56;
    const VA_MAX_BITS: usize = 39;

    type VirtAddr = VA;

    #[inline]
    fn flush_tlb(vaddr: Option<VA>) {
        <VA as SvVirtAddr>::flush_tlb(vaddr);
    }
}

impl<VA: SvVirtAddr> PagingMetaData for Sv48MetaData<VA> {
    const LEVELS: usize = 4;
    const PA_MAX_BITS: usize = 56;
    const VA_MAX_BITS: usize = 48;

    type VirtAddr = VA;

    #[inline]
    fn flush_tlb(vaddr: Option<VA>) {
        <VA as SvVirtAddr>::flush_tlb(vaddr);
    }
}

/// Sv39: Page-Based 39-bit (3 levels) Virtual-Memory System.
pub type Sv39PageTable<H> = PageTable64<Sv39MetaData<VirtAddr>, Rv64PTE, H>;
/// Sv39 page table cursor.
pub type Sv39PageTableCursor<'a, H> = PageTable64Cursor<'a, Sv39MetaData<VirtAddr>, Rv64PTE, H>;

/// Sv48: Page-Based 48-bit (4 levels) Virtual-Memory System.
pub type Sv48PageTable<H> = PageTable64<Sv48MetaData<VirtAddr>, Rv64PTE, H>;
/// Sv48 page table cursor.
pub type Sv48PageTableCursor<'a, H> = PageTable64Cursor<'a, Sv48MetaData<VirtAddr>, Rv64PTE, H>;
