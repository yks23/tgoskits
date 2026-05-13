use alloc::{
    borrow::Cow,
    boxed::Box,
    format,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::{
    ffi::CStr,
    fmt::Write as _,
    iter,
    sync::atomic::{AtomicUsize, Ordering},
};

use ax_alloc::global_allocator;
use ax_config::ARCH;
use ax_hal::{
    paging::MappingFlags,
    time::{monotonic_time, monotonic_time_nanos},
};
use ax_sync::Mutex;
use ax_task::{AxCpuMask, AxTaskRef, WeakAxTaskRef, current};
use axfs_ng_vfs::{DeviceId, Filesystem, NodeType, VfsError, VfsResult};
use indoc::indoc;
use lazy_static::lazy_static;
use rand::{Rng, SeedableRng, rngs::SmallRng};
use starry_process::Process;

use crate::{
    file::FD_TABLE,
    mm::BackendFileInfo,
    pseudofs::{
        DirMaker, DirMapping, NodeOpsMux, RwFile, SeqFile, SimpleDir, SimpleDirOps, SimpleFile,
        SimpleFileOperation, SimpleFs,
    },
    task::{AsThread, TaskStat, get_task, tasks},
};

const KERNEL_PAGE_SIZE: usize = 4096;

fn proc_mounts_text() -> &'static str {
    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\ndevtmpfs /dev devtmpfs \
     rw,nosuid,relatime,size=65536k,mode=755 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev,relatime 0 \
     0\nsysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n/dev/root / ext4 rw,relatime 0 0\n"
}

fn proc_filesystems_text() -> &'static str {
    "nodev\tsysfs\nnodev\ttmpfs\nnodev\tproc\n\text4\n"
}

fn format_meminfo() -> String {
    let ga = global_allocator();
    let total_pages = ga.used_pages() + ga.available_pages();
    let free_pages = ga.available_pages();
    let total_kb = total_pages.saturating_mul(KERNEL_PAGE_SIZE) / 1024;
    let memfree_kb = free_pages.saturating_mul(KERNEL_PAGE_SIZE) / 1024;
    let heap_avail_kb = ga.available_bytes() / 1024;
    let memavail_kb = memfree_kb.saturating_add(heap_avail_kb).min(total_kb);
    format!(
        "MemTotal:       {total_kb} kB\nMemFree:        {memfree_kb} kB\nMemAvailable:   \
         {memavail_kb} kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n",
    )
}

fn format_cpuinfo() -> String {
    let mut s = String::new();
    let n = ax_hal::cpu_num().max(1);
    for i in 0..n {
        let _ = writeln!(s, "processor\t: {i}");
        #[cfg(target_arch = "x86_64")]
        {
            let _ = writeln!(s, "model name\t: QEMU Virtual CPU @ 2.0GHz");
            let _ = writeln!(
                s,
                "flags\t\t: fpu de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 \
                 mmx fxsr sse sse2 ss ht"
            );
        }
        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        {
            #[cfg(target_arch = "riscv64")]
            let _ = writeln!(s, "isa\t\t: rv64gc");
            #[cfg(target_arch = "riscv32")]
            let _ = writeln!(s, "isa\t\t: rv32gc");
            #[cfg(target_arch = "riscv64")]
            let _ = writeln!(s, "mmu\t\t: sv48");
            #[cfg(target_arch = "riscv32")]
            let _ = writeln!(s, "mmu\t\t: sv32");
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "riscv32",
            target_arch = "riscv64"
        )))]
        {
            let _ = writeln!(s, "model name\t: StarryOS virtual CPU");
            let _ = writeln!(s, "flags\t\t:");
        }
    }
    s
}

fn format_proc_version() -> String {
    format!("Linux version 10.0.0 (starry@starry) ({ARCH}) #1 SMP\n")
}

fn format_uptime() -> String {
    let t = monotonic_time();
    format!("{}.{:06} 0.00\n", t.as_secs(), t.subsec_micros())
}

fn format_loadavg() -> String {
    let n = tasks().len().max(1);
    format!("0.00 0.00 0.00 {n}/{n} {n}\n")
}

fn format_uuid_dashed(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:\
         02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

fn proc_random_uuid_line() -> String {
    let mut b = [0u8; 16];
    PROC_RNG.lock().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!("{}\n", format_uuid_dashed(&b))
}

fn proc_boot_id_line() -> String {
    let mut g = PROC_BOOT_ID.lock();
    if g.is_none() {
        let mut b = [0u8; 16];
        PROC_RNG.lock().fill_bytes(&mut b);
        *g = Some(format!("{}\n", format_uuid_dashed(&b)));
    }
    g.clone().unwrap()
}

lazy_static! {
    static ref PROC_RNG: Mutex<SmallRng> = Mutex::new(SmallRng::seed_from_u64(
        monotonic_time_nanos() as u64 ^ 0x6eed_0e9d_eadb_eef1u64,
    ));
}

static PROC_BOOT_ID: Mutex<Option<String>> = Mutex::new(None);

pub fn new_procfs() -> Filesystem {
    SimpleFs::new_with("proc".into(), 0x9fa0, builder)
}

struct ProcessTaskDir {
    fs: Arc<SimpleFs>,
    process: Weak<Process>,
}

impl SimpleDirOps for ProcessTaskDir {
    fn child_names<'a>(&'a self) -> Box<dyn Iterator<Item = Cow<'a, str>> + 'a> {
        let Some(process) = self.process.upgrade() else {
            return Box::new(iter::empty());
        };
        Box::new(
            process
                .threads()
                .into_iter()
                .map(|tid| tid.to_string().into()),
        )
    }

    fn lookup_child(&self, name: &str) -> VfsResult<NodeOpsMux> {
        let process = self.process.upgrade().ok_or(VfsError::NotFound)?;
        let tid = name.parse::<u32>().map_err(|_| VfsError::NotFound)?;
        let task = get_task(tid).map_err(|_| VfsError::NotFound)?;
        if task.as_thread().proc_data.proc.pid() != process.pid() {
            return Err(VfsError::NotFound);
        }

        Ok(NodeOpsMux::Dir(SimpleDir::new_maker(
            self.fs.clone(),
            Arc::new(ThreadDir {
                fs: self.fs.clone(),
                task: Arc::downgrade(&task),
            }),
        )))
    }

    fn is_cacheable(&self) -> bool {
        false
    }
}

fn task_status(task: &AxTaskRef) -> String {
    let thread = task.as_thread();
    let cred = thread.cred();
    render_task_status(
        thread.proc_data.proc.pid(),
        task.id().as_u64(),
        &cred,
        task.cpumask(),
        ax_hal::cpu_num(),
    )
}

fn render_task_status(
    tgid: u32,
    pid: u64,
    cred: &crate::task::Cred,
    cpumask: AxCpuMask,
    cpu_num: usize,
) -> String {
    let cpus_allowed = format_cpumask_hex(cpumask, cpu_num);
    let cpus_allowed_list = format_cpumask_list(cpumask, cpu_num);

    render_task_status_fields(tgid, pid, cred, &cpus_allowed, &cpus_allowed_list)
}

#[rustfmt::skip]
fn render_task_status_fields(
    tgid: u32,
    pid: u64,
    cred: &crate::task::Cred,
    cpus_allowed: &str,
    cpus_allowed_list: &str,
) -> String {
    format!(
        "Tgid:\t{tgid}\n\
        Pid:\t{pid}\n\
        Uid:\t{}\t{}\t{}\t{}\n\
        Gid:\t{}\t{}\t{}\t{}\n\
        Cpus_allowed:\t{cpus_allowed}\n\
        Cpus_allowed_list:\t{cpus_allowed_list}\n\
        Mems_allowed:\t1\n\
        Mems_allowed_list:\t0",
        cred.uid, cred.euid, cred.suid, cred.fsuid,
        cred.gid, cred.egid, cred.sgid, cred.fsgid,
    )
}

fn format_cpumask_hex(cpumask: AxCpuMask, cpu_num: usize) -> String {
    format_cpu_presence_hex(&collect_cpu_presence(&cpumask, cpu_num))
}

fn format_cpu_presence_hex(cpu_presence: &[bool]) -> String {
    let word_count = cpu_presence.len().div_ceil(32).max(1);
    let mut words = vec![0u32; word_count];

    for (cpu, allowed) in cpu_presence.iter().copied().enumerate() {
        if allowed {
            words[cpu / 32] |= 1u32 << (cpu % 32);
        }
    }

    words
        .iter()
        .rev()
        .map(|word| format!("{word:08x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_cpumask_list(cpumask: AxCpuMask, cpu_num: usize) -> String {
    format_cpu_presence_list(&collect_cpu_presence(&cpumask, cpu_num))
}

fn format_cpu_presence_list(cpu_presence: &[bool]) -> String {
    let mut ranges = Vec::new();
    let mut cpu = 0;

    while cpu < cpu_presence.len() {
        if !cpu_presence[cpu] {
            cpu += 1;
            continue;
        }

        let start = cpu;
        let mut end = cpu;
        while end + 1 < cpu_presence.len() && cpu_presence[end + 1] {
            end += 1;
        }

        ranges.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        cpu = end + 1;
    }

    ranges.join(",")
}

fn collect_cpu_presence<I>(cpus: I, cpu_num: usize) -> Vec<bool>
where
    I: IntoIterator<Item = usize>,
{
    let mut cpu_presence = vec![false; cpu_num];

    for cpu in cpus {
        if cpu < cpu_num {
            cpu_presence[cpu] = true;
        }
    }

    cpu_presence
}

/// The /proc/[pid]/fd directory
struct ThreadFdDir {
    fs: Arc<SimpleFs>,
    task: WeakAxTaskRef,
}

impl SimpleDirOps for ThreadFdDir {
    fn child_names<'a>(&'a self) -> Box<dyn Iterator<Item = Cow<'a, str>> + 'a> {
        let Some(task) = self.task.upgrade() else {
            return Box::new(iter::empty());
        };
        let ids = FD_TABLE
            .scope(&task.as_thread().proc_data.scope.read())
            .read()
            .ids()
            .map(|id| Cow::Owned(id.to_string()))
            .collect::<Vec<_>>();
        Box::new(ids.into_iter())
    }

    fn lookup_child(&self, name: &str) -> VfsResult<NodeOpsMux> {
        let fs = self.fs.clone();
        let task = self.task.upgrade().ok_or(VfsError::NotFound)?;
        let fd = name.parse::<u32>().map_err(|_| VfsError::NotFound)?;
        let path = FD_TABLE
            .scope(&task.as_thread().proc_data.scope.read())
            .read()
            .get(fd as _)
            .ok_or(VfsError::NotFound)?
            .inner
            .path()
            .into_owned();
        Ok(SimpleFile::new(fs, NodeType::Symlink, move || Ok(path.clone())).into())
    }

    fn is_cacheable(&self) -> bool {
        false
    }
}

/// The /proc/[pid] directory
struct ThreadDir {
    fs: Arc<SimpleFs>,
    task: WeakAxTaskRef,
}

fn render_thread_maps(task: &WeakAxTaskRef) -> VfsResult<String> {
    let mut output = String::new();

    let task = match task.upgrade() {
        Some(t) => t,
        None => return Ok(output),
    };

    let aspace_arc = task.as_thread().proc_data.aspace();
    let mm = aspace_arc.lock();

    for area in mm.areas() {
        let start = area.start();
        let end = area.end();
        let backend = area.backend();
        let BackendFileInfo {
            path,
            offset: file_offset,
            inode,
            dev,
            shared: is_shared,
        } = backend.file_info()?;

        let flag_end = if is_shared { 's' } else { 'p' };
        let flags = area.flags();
        let perms = {
            let r = if flags.contains(MappingFlags::READ) {
                'r'
            } else {
                '-'
            };
            let w = if flags.contains(MappingFlags::WRITE) {
                'w'
            } else {
                '-'
            };
            let x = if flags.contains(MappingFlags::EXECUTE) {
                'x'
            } else {
                '-'
            };
            format!("{}{}{}{}", r, w, x, flag_end)
        };
        const MAPS_COL_WIDTH: usize = 25 + core::mem::size_of::<usize>() * 6 - 1;
        let mut writer = SeqWriter::new(&mut output);

        let dev = dev.map(DeviceId).map(|dev| (dev.major(), dev.minor()));

        write!(
            &mut writer,
            "{:08x}-{:08x} {} {:08x} {:02x}:{:02x} {}",
            start.as_usize(),
            end.as_usize(),
            perms,
            file_offset.unwrap_or(0),
            dev.map(|(major, _)| major).unwrap_or(0),
            dev.map(|(_, minor)| minor).unwrap_or(0),
            inode.unwrap_or(0),
        )
        .map_err(|_| VfsError::InvalidInput)?;
        writer.pad_to(MAPS_COL_WIDTH)?;
        if !path.is_empty() {
            writer.write_str(&path)?;
        }
        writer.newline()?;
    }

    Ok(output)
}

impl SimpleDirOps for ThreadDir {
    fn child_names<'a>(&'a self) -> Box<dyn Iterator<Item = Cow<'a, str>> + 'a> {
        Box::new(
            [
                "stat",
                "status",
                "oom_score_adj",
                "task",
                "maps",
                "mounts",
                "cmdline",
                "comm",
                "exe",
                "fd",
            ]
            .into_iter()
            .map(Cow::Borrowed),
        )
    }

    fn lookup_child(&self, name: &str) -> VfsResult<NodeOpsMux> {
        let fs = self.fs.clone();
        let task = self.task.upgrade().ok_or(VfsError::NotFound)?;
        Ok(match name {
            "stat" => SimpleFile::new_regular(fs, move || {
                Ok(format!("{}", TaskStat::from_thread(&task)?).into_bytes())
            })
            .into(),
            "status" => SimpleFile::new_regular(fs, move || Ok(task_status(&task))).into(),
            "oom_score_adj" => SimpleFile::new_regular(
                fs,
                RwFile::new(move |req| match req {
                    SimpleFileOperation::Read => Ok(Some(
                        task.as_thread().oom_score_adj().to_string().into_bytes(),
                    )),
                    SimpleFileOperation::Write(data) => {
                        if !data.is_empty() {
                            let value = str::from_utf8(data)
                                .ok()
                                .and_then(|it| it.parse::<i32>().ok())
                                .ok_or(VfsError::InvalidInput)?;
                            task.as_thread().set_oom_score_adj(value);
                        }
                        Ok(None)
                    }
                }),
            )
            .into(),
            "task" => SimpleDir::new_maker(
                fs.clone(),
                Arc::new(ProcessTaskDir {
                    fs,
                    process: Arc::downgrade(&task.as_thread().proc_data.proc),
                }),
            )
            .into(),
            "maps" => {
                let task = self.task.clone();
                SeqFile::new_regular(fs, move || render_thread_maps(&task)).into()
            }
            "mounts" => SimpleFile::new_regular(fs, move || Ok(proc_mounts_text())).into(),
            "cmdline" => SimpleFile::new_regular(fs, move || {
                let cmdline = task.as_thread().proc_data.cmdline.read();
                let mut buf = Vec::new();
                for arg in cmdline.iter() {
                    buf.extend_from_slice(arg.as_bytes());
                    buf.push(0);
                }
                Ok(buf)
            })
            .into(),
            "comm" => SimpleFile::new_regular(
                fs,
                RwFile::new(move |req| match req {
                    SimpleFileOperation::Read => {
                        let mut bytes = vec![0; 16];
                        let name = task.name();
                        let copy_len = name.len().min(15);
                        bytes[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
                        bytes[copy_len] = b'\n';
                        Ok(Some(bytes))
                    }
                    SimpleFileOperation::Write(data) => {
                        if !data.is_empty() {
                            let mut input = [0; 16];
                            let copy_len = data.len().min(15);
                            input[..copy_len].copy_from_slice(&data[..copy_len]);
                            task.set_name(
                                CStr::from_bytes_until_nul(&input)
                                    .map_err(|_| VfsError::InvalidInput)?
                                    .to_str()
                                    .map_err(|_| VfsError::InvalidInput)?,
                            );
                        }
                        Ok(None)
                    }
                }),
            )
            .into(),
            "exe" => SimpleFile::new(fs, NodeType::Symlink, move || {
                Ok(task.as_thread().proc_data.exe_path.read().clone())
            })
            .into(),
            "fd" => SimpleDir::new_maker(
                fs.clone(),
                Arc::new(ThreadFdDir {
                    fs,
                    task: Arc::downgrade(&task),
                }),
            )
            .into(),
            _ => return Err(VfsError::NotFound),
        })
    }

    fn is_cacheable(&self) -> bool {
        false
    }
}

/// Handles /proc/[pid] & /proc/self
struct ProcFsHandler(Arc<SimpleFs>);

impl SimpleDirOps for ProcFsHandler {
    fn child_names<'a>(&'a self) -> Box<dyn Iterator<Item = Cow<'a, str>> + 'a> {
        Box::new(
            tasks()
                .into_iter()
                .map(|task| task.id().as_u64().to_string().into())
                .chain([Cow::Borrowed("self")]),
        )
    }

    fn lookup_child(&self, name: &str) -> VfsResult<NodeOpsMux> {
        let task = if name == "self" {
            current().clone()
        } else {
            let tid = name.parse::<u32>().map_err(|_| VfsError::NotFound)?;
            get_task(tid).map_err(|_| VfsError::NotFound)?
        };
        let node = NodeOpsMux::Dir(SimpleDir::new_maker(
            self.0.clone(),
            Arc::new(ThreadDir {
                fs: self.0.clone(),
                task: Arc::downgrade(&task),
            }),
        ));
        Ok(node)
    }

    fn is_cacheable(&self) -> bool {
        false
    }
}

fn builder(fs: Arc<SimpleFs>) -> DirMaker {
    let mut root = DirMapping::new();
    root.add(
        "mounts",
        SimpleFile::new_regular(fs.clone(), || Ok(proc_mounts_text())),
    );
    root.add(
        "meminfo",
        SimpleFile::new_regular(fs.clone(), || Ok(format_meminfo())),
    );
    root.add(
        "cpuinfo",
        SimpleFile::new_regular(fs.clone(), || Ok(format_cpuinfo())),
    );
    root.add(
        "loadavg",
        SimpleFile::new_regular(fs.clone(), || Ok(format_loadavg())),
    );
    root.add(
        "uptime",
        SimpleFile::new_regular(fs.clone(), || Ok(format_uptime())),
    );
    root.add(
        "version",
        SimpleFile::new_regular(fs.clone(), || Ok(format_proc_version())),
    );
    root.add(
        "filesystems",
        SimpleFile::new_regular(fs.clone(), || Ok(proc_filesystems_text())),
    );
    root.add(
        "meminfo2",
        SimpleFile::new_regular(fs.clone(), || {
            let allocator = ax_alloc::global_allocator();
            Ok(format!("{:?}\n", allocator.usages()))
        }),
    );
    root.add(
        "instret",
        SimpleFile::new_regular(fs.clone(), || {
            #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
            {
                Ok(format!("{}\n", riscv::register::instret::read64()))
            }
            #[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
            {
                Ok("0\n".to_string())
            }
        }),
    );
    {
        static IRQ_CNT: AtomicUsize = AtomicUsize::new(0);

        ax_task::register_timer_callback(|_| {
            IRQ_CNT.fetch_add(1, Ordering::Relaxed);
        });

        root.add(
            "interrupts",
            SimpleFile::new_regular(fs.clone(), || {
                Ok(format!("0: {}", IRQ_CNT.load(Ordering::Relaxed)))
            }),
        );
    }

    root.add("sys", {
        let mut sys = DirMapping::new();

        sys.add("kernel", {
            let mut kernel = DirMapping::new();

            kernel.add(
                "pid_max",
                SimpleFile::new_regular(fs.clone(), || Ok("32768\n")),
            );

            let mut random = DirMapping::new();
            random.add(
                "uuid",
                SimpleFile::new_regular(fs.clone(), || Ok(proc_random_uuid_line())),
            );
            random.add(
                "boot_id",
                SimpleFile::new_regular(fs.clone(), || Ok(proc_boot_id_line())),
            );
            kernel.add("random", SimpleDir::new_maker(fs.clone(), Arc::new(random)));

            SimpleDir::new_maker(fs.clone(), Arc::new(kernel))
        });

        SimpleDir::new_maker(fs.clone(), Arc::new(sys))
    });

    let proc_dir = ProcFsHandler(fs.clone());
    SimpleDir::new_maker(fs, Arc::new(proc_dir.chain(root)))
}

pub struct SeqWriter<W: core::fmt::Write> {
    inner: W,
    col: usize,
}

impl<W: core::fmt::Write> SeqWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, col: 0 }
    }
}

impl<W: core::fmt::Write> SeqWriter<W> {
    fn write_str(&mut self, s: &str) -> VfsResult<()> {
        self.col += s.len();
        self.inner.write_str(s)?;
        Ok(())
    }

    #[allow(unused)]
    fn write_char(&mut self, c: char) -> VfsResult<()> {
        self.col += c.len_utf8();
        self.inner.write_char(c)?;
        Ok(())
    }

    fn pad_to(&mut self, target: usize) -> VfsResult<()> {
        if self.col < target {
            let pad = target - self.col;
            for _ in 0..pad {
                self.inner.write_char(' ')?;
            }
            self.col = target;
        }
        Ok(())
    }

    fn newline(&mut self) -> VfsResult<()> {
        self.inner.write_char('\n')?;
        self.col = 0;
        Ok(())
    }
}

impl<W: core::fmt::Write> core::fmt::Write for SeqWriter<W> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.write_str(s).map_err(|_| core::fmt::Error)
    }
}
#[cfg(test)]
mod tests {
    use alloc::{format, string::String};

    use super::{
        collect_cpu_presence, format_cpu_presence_hex, format_cpu_presence_list,
        render_task_status_fields,
    };
    use crate::task::Cred;

    fn legacy_render_task_status(tgid: u32, pid: u64) -> String {
        format!(
            "Tgid:\t{}\nPid:\t{}\nUid:\t0 0 0 0\nGid:\t0 0 0 \
             0\nCpus_allowed:\t1\nCpus_allowed_list:\t0\nMems_allowed:\t1\nMems_allowed_list:\t0",
            tgid, pid
        )
    }

    fn render_task_status_from_cpus(tgid: u32, pid: u64, cpus: &[usize], cpu_num: usize) -> String {
        let cpu_presence = collect_cpu_presence(cpus.iter().copied(), cpu_num);
        let cpus_allowed = format_cpu_presence_hex(&cpu_presence);
        let cpus_allowed_list = format_cpu_presence_list(&cpu_presence);

        render_task_status_fields(tgid, pid, &Cred::root(), &cpus_allowed, &cpus_allowed_list)
    }

    #[test]
    fn old_hardcoded_status_lies_about_non_cpu0_affinity() {
        let legacy = legacy_render_task_status(42, 84);

        assert!(legacy.contains("Cpus_allowed:\t1\n"));
        assert!(legacy.contains("Cpus_allowed_list:\t0\n"));
        assert!(!legacy.contains("Cpus_allowed:\t0000000a\n"));
        assert!(!legacy.contains("Cpus_allowed_list:\t1,3\n"));
    }

    #[test]
    fn cpus_allowed_hex_matches_actual_affinity_bits() {
        let cpu_presence = collect_cpu_presence([1, 3], 4);

        assert_eq!(format_cpu_presence_hex(&cpu_presence), "0000000a");
    }

    #[test]
    fn cpus_allowed_hex_orders_32bit_words_from_high_to_low() {
        let cpu_presence = collect_cpu_presence([0, 1, 32, 63], 64);

        assert_eq!(format_cpu_presence_hex(&cpu_presence), "80000001,00000003");
    }

    #[test]
    fn cpus_allowed_list_compacts_contiguous_ranges() {
        let cpu_presence = collect_cpu_presence([0, 2, 3, 4, 7, 9, 10, 11], 12);

        assert_eq!(format_cpu_presence_list(&cpu_presence), "0,2-4,7,9-11");
    }

    #[test]
    fn task_status_reports_real_affinity_instead_of_cpu0_only() {
        let status = render_task_status_from_cpus(42, 84, &[1, 3], 4);

        assert!(status.contains("Tgid:\t42\n"));
        assert!(status.contains("Pid:\t84\n"));
        assert!(status.contains("Cpus_allowed:\t0000000a\n"));
        assert!(status.contains("Cpus_allowed_list:\t1,3\n"));
    }
}
