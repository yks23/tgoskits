#![cfg_attr(feature = "ax-std", no_std)]
#![cfg_attr(feature = "ax-std", no_main)]

use core::fmt::Write;

#[cfg(feature = "ax-std")]
#[macro_use]
extern crate ax_std as std;

#[cfg(feature = "ax-std")]
use std::os::arceos::{
    api::task::{AxCpuMask, ax_set_current_affinity},
    modules::ax_hal::percpu::this_cpu_id,
};
use std::{println, string::String, thread, vec::Vec};

use axvisor_guestlib::{emit_json_result, power_off_or_hang};

const CASE_ID: &str = "cpu.mpidr.multicore-read";
const SAMPLES_PER_CPU: usize = 3;

#[derive(Clone, Copy)]
struct CpuRecord {
    logical_cpu_id: usize,
    observed_cpu_id: usize,
    samples: [u64; SAMPLES_PER_CPU],
}

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

#[cfg(feature = "ax-std")]
fn pin_current_to_cpu(cpu_id: usize) {
    assert!(
        ax_set_current_affinity(AxCpuMask::one_shot(cpu_id)).is_ok(),
        "failed to pin current task to CPU {cpu_id}"
    );
    for _ in 0..256 {
        if this_cpu_id() == cpu_id {
            return;
        }
        thread::yield_now();
    }
    assert_eq!(
        this_cpu_id(),
        cpu_id,
        "task did not migrate to CPU {cpu_id}"
    );
}

fn read_samples() -> [u64; SAMPLES_PER_CPU] {
    let mut samples = [0u64; SAMPLES_PER_CPU];
    for sample in &mut samples {
        *sample = read_mpidr_el1();
        thread::yield_now();
    }
    samples
}

#[cfg(feature = "ax-std")]
fn probe_cpu(cpu_id: usize) -> CpuRecord {
    pin_current_to_cpu(cpu_id);
    CpuRecord {
        logical_cpu_id: cpu_id,
        observed_cpu_id: this_cpu_id(),
        samples: read_samples(),
    }
}

fn decode_record(record: &CpuRecord) -> String {
    let raw = record.samples[0];
    let aff0 = raw & 0xff;
    let aff1 = (raw >> 8) & 0xff;
    let aff2 = (raw >> 16) & 0xff;
    let aff3 = (raw >> 32) & 0xff;
    let mt = ((raw >> 24) & 0x1) != 0;
    let u = ((raw >> 30) & 0x1) != 0;
    let all_equal = record.samples.iter().all(|sample| *sample == raw);

    format!(
        "{{\"logical_cpu_id\":{},\"observed_cpu_id\":{},\"samples\":[{},{},{}],\"all_equal\":{},\"\
         raw\":{},\"aff0\":{},\"aff1\":{},\"aff2\":{},\"aff3\":{},\"mt\":{},\"u\":{}}}",
        record.logical_cpu_id,
        record.observed_cpu_id,
        record.samples[0],
        record.samples[1],
        record.samples[2],
        all_equal,
        raw,
        aff0,
        aff1,
        aff2,
        aff3,
        mt,
        u
    )
}

#[cfg_attr(feature = "ax-std", unsafe(no_mangle))]
fn main() -> ! {
    println!("Running {}", CASE_ID);

    let cpu_count = thread::available_parallelism().unwrap().get();
    let mut handles = Vec::with_capacity(cpu_count);
    for cpu_id in 0..cpu_count {
        handles.push(thread::spawn(move || probe_cpu(cpu_id)));
    }

    let mut records = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    records.sort_by_key(|record| record.logical_cpu_id);

    let mut records_json = String::from("[");
    for (index, record) in records.iter().enumerate() {
        if index != 0 {
            records_json.push(',');
        }
        records_json.push_str(&decode_record(record));
    }
    records_json.push(']');

    let unique_raw_count = {
        let mut unique = Vec::new();
        for record in &records {
            let raw = record.samples[0];
            if !unique.contains(&raw) {
                unique.push(raw);
            }
        }
        unique.len()
    };

    let mut diff = String::new();
    write!(
        &mut diff,
        "{{\"cpu_count\":{},\"unique_raw_count\":{},\"records\":{}}}",
        cpu_count, unique_raw_count, records_json
    )
    .unwrap();

    emit_json_result(CASE_ID, "ok", &diff);

    power_off_or_hang();
}
