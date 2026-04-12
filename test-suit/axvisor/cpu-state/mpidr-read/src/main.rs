#![cfg_attr(feature = "ax-std", no_std)]
#![cfg_attr(feature = "ax-std", no_main)]

#[cfg(feature = "ax-std")]
#[macro_use]
extern crate ax_std as std;

use std::println;

use axvisor_guestlib::{emit_json_result, power_off_or_hang};

const CASE_ID: &str = "cpu.mpidr.read";

#[cfg(target_arch = "aarch64")]
fn read_mpidr_el1() -> u64 {
    use core::arch::asm;

    let raw: u64;
    unsafe {
        asm!("mrs {value}, MPIDR_EL1", value = out(reg) raw);
    }
    raw
}

#[cfg(not(target_arch = "aarch64"))]
fn read_mpidr_el1() -> u64 {
    0
}

#[cfg_attr(feature = "ax-std", unsafe(no_mangle))]
fn main() -> ! {
    println!("Running {}", CASE_ID);

    let raw = read_mpidr_el1();
    let aff0 = raw & 0xff;
    let aff1 = (raw >> 8) & 0xff;
    let aff2 = (raw >> 16) & 0xff;
    let aff3 = (raw >> 32) & 0xff;
    let mt = ((raw >> 24) & 0x1) != 0;
    let u = ((raw >> 30) & 0x1) != 0;

    emit_json_result(
        CASE_ID,
        "ok",
        &format!(
            "{{\"raw\":{},\"aff0\":{},\"aff1\":{},\"aff2\":{},\"aff3\":{},\"mt\":{},\"u\":{}}}",
            raw, aff0, aff1, aff2, aff3, mt, u
        ),
    );

    power_off_or_hang();
}
