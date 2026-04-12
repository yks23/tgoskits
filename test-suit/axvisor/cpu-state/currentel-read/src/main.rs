#![cfg_attr(feature = "ax-std", no_std)]
#![cfg_attr(feature = "ax-std", no_main)]

#[cfg(feature = "ax-std")]
#[macro_use]
extern crate ax_std as std;

use std::println;

use axvisor_guestlib::{emit_json_result, power_off_or_hang};

const CASE_ID: &str = "cpu.currentel.read";

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

#[cfg_attr(feature = "ax-std", unsafe(no_mangle))]
fn main() -> ! {
    println!("Running {}", CASE_ID);

    let raw = read_current_el();
    let decoded_el = (raw >> 2) & 0b11;

    emit_json_result(
        CASE_ID,
        "ok",
        &format!("{{\"raw\":{},\"decoded_el\":{}}}", raw, decoded_el),
    );

    power_off_or_hang();
}
