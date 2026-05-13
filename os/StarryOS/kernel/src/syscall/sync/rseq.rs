use core::mem::size_of;

use ax_errno::AxError;
use ax_task::current;
use starry_vm::{VmMutPtr, VmPtr};

use crate::task::AsThread;

const RSEQ_CPU_ID_UNINITIALIZED: u32 = u32::MAX;
const RSEQ_FLAG_UNREGISTER: u32 = 1;
const RSEQ_LEN: usize = 0x20;
const RSEQ_SIG: u32 = 0xd428bc00;

fn validate_rseq_addr(addr: *mut u8, len: usize) -> Result<Option<usize>, AxError> {
    if addr.is_null() {
        if len != 0 {
            return Err(AxError::InvalidInput);
        }
        return Ok(None);
    }

    if len != RSEQ_LEN {
        return Err(AxError::InvalidInput);
    }

    Ok(Some(addr.addr()))
}

fn validate_rseq_flags(flags: u32) -> Result<bool, AxError> {
    match flags {
        0 => Ok(false),
        RSEQ_FLAG_UNREGISTER => Ok(true),
        _ => Err(AxError::InvalidInput),
    }
}

/// Minimal implementation of the rseq syscall registration.
///
/// This implementation only supports registration/unregistration via the
/// first argument (addr) and the flags argument. It stores the user pointer
/// in the current thread structure so kernel-side users can inspect it.
///
/// C prototype (simplified):
/// long rseq(void *addr, uint32_t len, int flags, uint32_t sig);
pub fn sys_rseq(addr: *mut u8, len: usize, flags: u32, sig: u32) -> Result<isize, AxError> {
    debug!(
        "sys_rseq <= addr: {:?}, len: {}, flags: {}, sig: {}",
        addr, len, flags, sig
    );

    let unregister = validate_rseq_flags(flags)?;
    let addr = validate_rseq_addr(addr, len)?;
    if sig != RSEQ_SIG {
        return Err(AxError::InvalidInput);
    }

    let thread = current();
    let thread = thread.as_thread();

    if unregister {
        if addr != Some(thread.rseq_area()) {
            return Err(AxError::InvalidInput);
        }
        thread.set_rseq_area(0);
        return Ok(0);
    }

    let Some(addr) = addr else {
        return Err(AxError::InvalidInput);
    };
    if thread.rseq_area() != 0 {
        return Err(AxError::ResourceBusy);
    }

    // Check that the user pointer is readable/writable (we only need the address).
    // Try to read one byte to ensure the area is valid.
    if (addr as *mut u8).vm_read().is_err() {
        return Err(AxError::InvalidInput);
    }

    // Mark cpu_id as uninitialized so libc can fall back if it inspects the area.
    ((addr + size_of::<u32>()) as *mut u32).vm_write(RSEQ_CPU_ID_UNINITIALIZED)?;
    thread.set_rseq_area(addr);

    Ok(0)
}

#[cfg(test)]
mod tests {
    use ax_errno::AxError;

    use super::validate_rseq_addr;

    #[test]
    fn validate_rseq_addr_allows_unregister() {
        assert_eq!(validate_rseq_addr(core::ptr::null_mut(), 0).unwrap(), None);
    }

    #[test]
    fn validate_rseq_addr_rejects_null_addr_with_nonzero_len() {
        assert_eq!(
            validate_rseq_addr(core::ptr::null_mut(), 8).unwrap_err(),
            AxError::InvalidInput
        );
    }

    #[test]
    fn validate_rseq_addr_rejects_nonnull_addr_with_zero_len() {
        assert_eq!(
            validate_rseq_addr(core::ptr::dangling_mut::<u8>(), 0).unwrap_err(),
            AxError::InvalidInput
        );
    }

    #[test]
    fn validate_rseq_addr_rejects_wrong_len() {
        assert_eq!(
            validate_rseq_addr(1usize as *mut u8, super::RSEQ_LEN - 1).unwrap_err(),
            AxError::InvalidInput
        );
    }

    #[test]
    fn validate_rseq_flags_accepts_register_and_unregister_only() {
        assert!(!super::validate_rseq_flags(0).unwrap());
        assert!(super::validate_rseq_flags(super::RSEQ_FLAG_UNREGISTER).unwrap());
        assert_eq!(
            super::validate_rseq_flags(2).unwrap_err(),
            AxError::InvalidInput
        );
    }

    #[test]
    fn validate_rseq_addr_rejects_wrong_len() {
        assert_eq!(
            validate_rseq_addr(1usize as *mut u8, super::RSEQ_LEN - 1).unwrap_err(),
            AxError::InvalidInput
        );
    }

    #[test]
    fn validate_rseq_flags_accepts_register_and_unregister_only() {
        assert!(!super::validate_rseq_flags(0).unwrap());
        assert!(super::validate_rseq_flags(super::RSEQ_FLAG_UNREGISTER).unwrap());
        assert_eq!(
            super::validate_rseq_flags(2).unwrap_err(),
            AxError::InvalidInput
        );
    }
}
