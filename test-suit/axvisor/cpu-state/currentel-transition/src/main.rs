#![cfg_attr(feature = "ax-std", no_std)]
#![cfg_attr(feature = "ax-std", no_main)]

#[cfg(feature = "ax-std")]
#[macro_use]
extern crate ax_std as std;

use std::{os::arceos::modules::ax_hal, println, string::String};

use ax_hal::trap::page_fault_handler;
use ax_memory_addr::{MemoryAddr, PAGE_SIZE_4K, VirtAddr};
use ax_mm::new_user_aspace;
use axvisor_guestlib::{emit_json_result, power_off_or_hang};

const CASE_ID: &str = "cpu.currentel.transition";
const USER_CODE_START: usize = 0x4_000;
const USER_SHARED_START: usize = 0x8_000;
const USER_STACK_START: usize = 0x10_000;

#[page_fault_handler]
fn handle_page_fault(_vaddr: VirtAddr, _access_flags: ax_hal::paging::MappingFlags) -> bool {
    false
}

core::arch::global_asm!(
    r#"
    .section .text.axdiff_currentel_user, "ax"
    .p2align 2
    .global axdiff_currentel_user_entry
    .global axdiff_currentel_user_after_fault
    .global axdiff_currentel_user_entry_end
axdiff_currentel_user_entry:
    mov x1, #1
    str x1, [x0, #8]
    mrs x1, CurrentEL
    mov x1, #0xff
    str x1, [x0]
axdiff_currentel_user_after_fault:
    mov x1, #2
    str x1, [x0, #8]
    mov x8, #0
    svc #0
1:
    b 1b
axdiff_currentel_user_entry_end:
"#
);

unsafe extern "C" {
    fn axdiff_currentel_user_entry();
    fn axdiff_currentel_user_after_fault();
    fn axdiff_currentel_user_entry_end();
}

#[cfg(target_arch = "aarch64")]
fn read_current_el() -> u64 {
    use core::arch::asm;

    let raw: u64;
    unsafe {
        asm!("mrs {value}, CurrentEL", value = out(reg) raw);
    }
    raw
}

#[cfg(not(target_arch = "aarch64"))]
fn read_current_el() -> u64 {
    0
}

fn decoded_el(raw: u64) -> u64 {
    (raw >> 2) & 0b11
}

#[cfg(target_arch = "aarch64")]
fn sync_executable_range(start: VirtAddr, size: usize) {
    use core::arch::asm;

    let mut addr = start.as_usize().align_down(64usize);
    let end = (start.as_usize() + size + 63) & !63usize;

    while addr < end {
        unsafe {
            asm!("dc cvau, {addr}", addr = in(reg) addr);
        }
        addr += 64;
    }
    unsafe {
        asm!("dsb ish");
    }

    let mut addr = start.as_usize().align_down(64usize);
    while addr < end {
        unsafe {
            asm!("ic ivau, {addr}", addr = in(reg) addr);
        }
        addr += 64;
    }
    unsafe {
        asm!("dsb ish");
        asm!("isb");
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn sync_executable_range(_start: VirtAddr, _size: usize) {}

fn prepare_user_aspace() -> Result<(ax_mm::AddrSpace, VirtAddr, VirtAddr), &'static str> {
    let code_start = axdiff_currentel_user_entry as *const ();
    let code_end = axdiff_currentel_user_entry_end as *const ();
    let code_bytes = unsafe {
        core::slice::from_raw_parts(
            code_start.cast::<u8>(),
            (code_end as usize).saturating_sub(code_start as usize),
        )
    };

    let user_code_start = VirtAddr::from(USER_CODE_START);
    let user_shared_start = VirtAddr::from(USER_SHARED_START);
    let user_stack_start = VirtAddr::from(USER_STACK_START);
    let user_stack_top = user_stack_start + PAGE_SIZE_4K;

    let base = user_code_start;
    let end = user_stack_top;
    let size = end.as_usize() - base.as_usize();

    let mut aspace = new_user_aspace(base, size).map_err(|_| "create_user_aspace")?;

    let code_rw_flags = ax_hal::paging::MappingFlags::READ
        | ax_hal::paging::MappingFlags::WRITE
        | ax_hal::paging::MappingFlags::EXECUTE
        | ax_hal::paging::MappingFlags::USER;
    let code_rx_flags = ax_hal::paging::MappingFlags::READ
        | ax_hal::paging::MappingFlags::EXECUTE
        | ax_hal::paging::MappingFlags::USER;
    let data_flags = ax_hal::paging::MappingFlags::READ
        | ax_hal::paging::MappingFlags::WRITE
        | ax_hal::paging::MappingFlags::USER;

    aspace
        .map_alloc(user_code_start, PAGE_SIZE_4K, code_rw_flags, true)
        .map_err(|_| "map_user_code")?;
    aspace
        .map_alloc(user_shared_start, PAGE_SIZE_4K, data_flags, true)
        .map_err(|_| "map_shared_page")?;
    aspace
        .map_alloc(user_stack_start, PAGE_SIZE_4K, data_flags, true)
        .map_err(|_| "map_user_stack")?;

    aspace
        .write(user_code_start, code_bytes)
        .map_err(|_| "copy_user_code")?;
    aspace
        .write(user_shared_start, &[0; 16])
        .map_err(|_| "clear_shared_page")?;
    aspace
        .protect(user_code_start, PAGE_SIZE_4K, code_rx_flags)
        .map_err(|_| "protect_user_code")?;
    sync_executable_range(user_code_start, code_bytes.len());

    Ok((aspace, user_stack_top, user_shared_start))
}

fn read_shared_words(
    aspace: &ax_mm::AddrSpace,
    shared_start: VirtAddr,
) -> Result<[u64; 2], &'static str> {
    let mut shared = [0u8; 16];
    aspace
        .read(shared_start, &mut shared)
        .map_err(|_| "read_shared_page")?;
    Ok([
        u64::from_le_bytes(shared[0..8].try_into().unwrap()),
        u64::from_le_bytes(shared[8..16].try_into().unwrap()),
    ])
}

fn format_return_reason(reason: ax_hal::uspace::ReturnReason) -> String {
    match reason {
        ax_hal::uspace::ReturnReason::Syscall => String::from("\"syscall\""),
        ax_hal::uspace::ReturnReason::Interrupt => String::from("\"interrupt\""),
        ax_hal::uspace::ReturnReason::Unknown => String::from("\"unknown\""),
        ax_hal::uspace::ReturnReason::PageFault(addr, flags) => format!(
            "{{\"kind\":\"page_fault\",\"addr\":{},\"flags\":\"{:?}\"}}",
            addr.as_usize(),
            flags
        ),
        ax_hal::uspace::ReturnReason::Exception(exc) => {
            #[cfg(target_arch = "aarch64")]
            {
                format!(
                    "{{\"kind\":\"exception\",\"exception_kind\":\"{:?}\",\"esr\":{},\"far\":{}}}",
                    exc.kind(),
                    exc.esr.get(),
                    exc.far
                )
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                format!(
                    "{{\"kind\":\"exception\",\"exception_kind\":\"{:?}\"}}",
                    exc.kind()
                )
            }
        }
    }
}

fn emit_error(stage: &str, detail: &str) -> ! {
    emit_json_result(
        CASE_ID,
        "error",
        &format!("{{\"stage\":\"{}\",\"detail\":\"{}\"}}", stage, detail),
    );
    power_off_or_hang();
}

#[cfg_attr(feature = "ax-std", unsafe(no_mangle))]
fn main() -> ! {
    println!("Running {}", CASE_ID);

    let el1_before = read_current_el();
    let (user_aspace, user_stack_top, user_shared_start) = match prepare_user_aspace() {
        Ok(v) => v,
        Err(stage) => emit_error(stage, "failed"),
    };
    let user_entry = axdiff_currentel_user_entry as *const () as usize;
    let user_after_fault_label = axdiff_currentel_user_after_fault as *const () as usize;
    let user_after_fault = USER_CODE_START + user_after_fault_label.saturating_sub(user_entry);

    let old_ttbr0 = ax_hal::asm::read_user_page_table();
    unsafe {
        ax_hal::asm::write_user_page_table(user_aspace.page_table_root());
    }
    ax_hal::asm::flush_tlb(None);

    let mut uctx = ax_hal::uspace::UserContext::new(
        USER_CODE_START,
        user_stack_top,
        user_shared_start.as_usize(),
    );

    let first_reason = uctx.run();
    let [el0_raw_after_exception, phase_after_exception] =
        match read_shared_words(&user_aspace, user_shared_start) {
            Ok(words) => words,
            Err(stage) => emit_error(stage, "failed"),
        };
    if phase_after_exception != 1 {
        emit_error("enter_el0", "user code did not reach the EL0 probe marker");
    }
    if !matches!(first_reason, ax_hal::uspace::ReturnReason::Exception(_)) {
        emit_error(
            "currentel_el0_access",
            "expected EL0 CurrentEL access to trap as an exception",
        );
    }

    uctx.set_ip(user_after_fault);
    let second_reason = uctx.run();
    let [el0_raw_after_syscall, phase_after_syscall] =
        match read_shared_words(&user_aspace, user_shared_start) {
            Ok(words) => words,
            Err(stage) => emit_error(stage, "failed"),
        };
    if phase_after_syscall != 2 {
        emit_error(
            "resume_after_fault",
            "user code did not resume to the post-fault path",
        );
    }
    if !matches!(second_reason, ax_hal::uspace::ReturnReason::Syscall) {
        emit_error(
            "resume_after_fault",
            "expected resumed EL0 path to exit via SVC",
        );
    }

    unsafe {
        ax_hal::asm::write_user_page_table(old_ttbr0);
    }
    ax_hal::asm::flush_tlb(None);

    let el1_after = read_current_el();

    emit_json_result(
        CASE_ID,
        "ok",
        &format!(
            "{{\"el1_before\":{{\"raw\":{},\"decoded_el\":{}}},\"el0_probe\":{{\"\
             raw_after_exception\":{},\"phase_after_exception\":{},\"raw_after_resume\":{},\"\
             phase_after_resume\":{}}},\"first_return_reason\":{},\"second_return_reason\":{},\"\
             el1_after\":{{\"raw\":{},\"decoded_el\":{}}}}}",
            el1_before,
            decoded_el(el1_before),
            el0_raw_after_exception,
            phase_after_exception,
            el0_raw_after_syscall,
            phase_after_syscall,
            format_return_reason(first_reason),
            format_return_reason(second_reason),
            el1_after,
            decoded_el(el1_after),
        ),
    );

    power_off_or_hang();
}
