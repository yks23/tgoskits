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
use ax_hal::time::{monotonic_time, monotonic_time_nanos};
use ax_sync::Mutex;
use ax_task::{AxTaskRef, WeakAxTaskRef, current};
use axfs_ng_vfs::{Filesystem, NodeType, VfsError, VfsResult};
use indoc::indoc;
use lazy_static::lazy_static;
use rand::{Rng, SeedableRng, rngs::SmallRng};
use starry_process::Process;

use crate::{
    file::FD_TABLE,
    pseudofs::{
        DirMaker, DirMapping, NodeOpsMux, RwFile, SimpleDir, SimpleDirOps, SimpleFile,
        SimpleFileOperation, SimpleFs,
    },
    task::{AsThread, TaskStat, get_task, tasks},
};

const KERNEL_PAGE_SIZE: usize = 4096;

fn proc_mounts_text() -> &'static str {
    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n\
     devtmpfs /dev devtmpfs rw,nosuid,relatime,size=65536k,mode=755 0 0\n\
     tmpfs /tmp tmpfs rw,nosuid,nodev,relatime 0 0\n\
     sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n\
     /dev/root / ext4 rw,relatime 0 0\n"
}

fn proc_filesystems_text() -> &'static str {
    "nodev\tsysfs\n\
     nodev\ttmpfs\n\
     nodev\tproc\n\
     \text4\n"
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
        "MemTotal:       {total_kb} kB\n\
         MemFree:        {memfree_kb} kB\n\
         MemAvailable:   {memavail_kb} kB\n\
         SwapTotal:             0 kB\n\
         SwapFree:              0 kB\n",
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
                "flags\t\t: fpu de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 mmx fxsr sse sse2 ss ht"
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
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
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

#[rustfmt::skip]
fn task_status(task: &AxTaskRef) -> String {
    format!(
        "Tgid:\t{}\n\
        Pid:\t{}\n\
        Uid:\t0 0 0 0\n\
        Gid:\t0 0 0 0\n\
        Cpus_allowed:\t1\n\
        Cpus_allowed_list:\t0\n\
        Mems_allowed:\t1\n\
        Mems_allowed_list:\t0",
        task.as_thread().proc_data.proc.pid(),
        task.id().as_u64()
    )
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
            "maps" => SimpleFile::new_regular(fs, move || {
                Ok(indoc! {"
                    7f000000-7f001000 r--p 00000000 00:00 0          [vdso]
                    7f001000-7f003000 r-xp 00001000 00:00 0          [vdso]
                    7f003000-7f005000 r--p 00003000 00:00 0          [vdso]
                    7f005000-7f007000 rw-p 00005000 00:00 0          [vdso]
                "})
            })
            .into(),
            "mounts" => SimpleFile::new_regular(fs, move || {
                Ok(proc_mounts_text())
            })
            .into(),
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
            kernel.add(
                "random",
                SimpleDir::new_maker(fs.clone(), Arc::new(random)),
            );

            SimpleDir::new_maker(fs.clone(), Arc::new(kernel))
        });

        SimpleDir::new_maker(fs.clone(), Arc::new(sys))
    });

    let proc_dir = ProcFsHandler(fs.clone());
    SimpleDir::new_maker(fs, Arc::new(proc_dir.chain(root)))
}
