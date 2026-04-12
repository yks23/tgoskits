#![cfg_attr(feature = "ax-std", no_std)]

#[cfg(feature = "ax-std")]
extern crate ax_std as std;

use std::println;

pub const RESULT_BEGIN_MARKER: &str = "AXTEST_RESULT_BEGIN";
pub const RESULT_END_MARKER: &str = "AXTEST_RESULT_END";

pub fn emit_json_result(case_id: &str, status: &str, diff_json: &str) {
    println!("{RESULT_BEGIN_MARKER}");
    println!(
        "{{\"case_id\":\"{}\",\"status\":\"{}\",\"diff\":{}}}",
        case_id, status, diff_json
    );
    println!("{RESULT_END_MARKER}");
}

pub fn power_off_or_hang() -> ! {
    // Diff guests leave lifecycle control to the runner. After emitting the
    // result payload, stay parked until the runner stops or deletes the VM.
    loop {
        core::hint::spin_loop();
    }
}
