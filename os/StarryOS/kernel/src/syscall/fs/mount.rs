use core::ffi::{c_char, c_void};

use alloc::{collections::BTreeMap, collections::BTreeSet, sync::Arc};

use ax_driver::{PartitionRegion, prelude::BlockDriverOps};
use ax_errno::{AxError, AxResult, LinuxError};
use ax_fs::{FS_CONTEXT, new_ext4_shared, spare_block_disk, virtio_disk_index_for_path};
use ax_task::current;
use axfs_ng_vfs::{Mountpoint, NodeType};
use spin::Mutex;

use downcast_rs::Downcast;

use crate::{
    file::{Directory, FD_TABLE, File},
    mm::vm_load_string,
    pseudofs::{MemoryFs, bind_mount::BindDirFilesystem},
};

/// `MS_BIND` from Linux `mount(2)`.
const MS_BIND: i32 = 0x1000;
/// `MNT_FORCE` / `MNT_DETACH` from Linux `mount.h`.
const MNT_FORCE: i32 = 0x0000_0001;
const MNT_DETACH: i32 = 0x0000_0002;

/// Spare virtio disks currently hosting an ext4 mount (at most one ext4 per disk).
static EXT4_IN_USE_DISKS: Mutex<BTreeSet<usize>> = Mutex::new(BTreeSet::new());
/// Maps a mounted ext4 [`Mountpoint`] pointer to its virtio disk index.
static EXT4_DISK_FOR_MOUNT: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());

fn record_ext4_mount(mp: &Arc<Mountpoint>, disk_index: usize) {
    EXT4_DISK_FOR_MOUNT
        .lock()
        .insert(Arc::as_ptr(mp) as usize, disk_index);
}

fn mountpoint_has_open_files(mp: &Arc<Mountpoint>) -> bool {
    let task = current();
    let scope = task.as_thread().proc_data.scope.read();
    let table = FD_TABLE.scope(&scope).read();
    for id in table.ids() {
        let Some(desc) = table.get(id) else {
            continue;
        };
        let f = desc.inner.as_ref();
        if let Some(file) = f.downcast_ref::<File>() {
            if Arc::ptr_eq(file.inner().location().mountpoint(), mp) {
                return true;
            }
        } else if let Some(dir) = f.downcast_ref::<Directory>() {
            if Arc::ptr_eq(dir.inner().mountpoint(), mp) {
                return true;
            }
        }
    }
    false
}

pub fn sys_mount(
    source: *const c_char,
    target: *const c_char,
    fs_type: *const c_char,
    flags: i32,
    _data: *const c_void,
) -> AxResult<isize> {
    let source = vm_load_string(source)?;
    let target = vm_load_string(target)?;
    let fs_type = vm_load_string(fs_type)?;
    debug!("sys_mount <= source: {source:?}, target: {target:?}, fs_type: {fs_type:?}, flags: {flags}");

    if flags & MS_BIND != 0 {
        return do_bind_mount(&source, &target);
    }

    match fs_type.as_str() {
        "tmpfs" => {
            let fs = MemoryFs::new();
            let target = FS_CONTEXT.lock().resolve(&target)?;
            target.mount(&fs)?;
            Ok(0)
        }
        "ext4" => do_ext4_mount(&source, &target),
        "9p" | "9p2000.L" => Err(AxError::NoSuchDevice),
        _ => Err(AxError::NoSuchDevice),
    }
}

fn do_bind_mount(source: &str, target: &str) -> AxResult<isize> {
    let mut fs = FS_CONTEXT.lock();
    let source_loc = fs.resolve(source)?;
    if source_loc.node_type() != NodeType::Directory {
        return Err(AxError::from(LinuxError::ENOTDIR));
    }
    let target_loc = fs.resolve(target)?;
    if target_loc.node_type() != NodeType::Directory {
        return Err(AxError::from(LinuxError::ENOTDIR));
    }
    if source_loc.ptr_eq(&target_loc) {
        return Err(AxError::InvalidInput);
    }
    let bind_fs = BindDirFilesystem::new(source_loc.entry().clone());
    target_loc.mount(&bind_fs)?;
    Ok(0)
}

fn do_ext4_mount(source: &str, target: &str) -> AxResult<isize> {
    let Some(disk_index) = virtio_disk_index_for_path(source) else {
        return Err(AxError::from(LinuxError::ENOTBLK));
    };
    let Some(dev_arc) = spare_block_disk(disk_index) else {
        return Err(AxError::NoSuchDevice);
    };
    {
        let mut in_use = EXT4_IN_USE_DISKS.lock();
        if !in_use.insert(disk_index) {
            return Err(AxError::ResourceBusy);
        }
    }
    let region = {
        let g = dev_arc.lock();
        PartitionRegion::from_num_blocks(g.num_blocks())
    };
    let fs = match new_ext4_shared(dev_arc, region) {
        Ok(fs) => fs,
        Err(e) => {
            EXT4_IN_USE_DISKS.lock().remove(&disk_index);
            return Err(e);
        }
    };
    let new_mp = match FS_CONTEXT.lock().resolve(target)?.mount(&fs) {
        Ok(mp) => mp,
        Err(e) => {
            EXT4_IN_USE_DISKS.lock().remove(&disk_index);
            return Err(e);
        }
    };
    record_ext4_mount(&new_mp, disk_index);
    Ok(0)
}

pub fn sys_umount2(target: *const c_char, flags: i32) -> AxResult<isize> {
    let target = vm_load_string(target)?;
    debug!("sys_umount2 <= target: {target:?}, flags: {flags}");
    let loc = FS_CONTEXT.lock().resolve(&target)?;
    if !loc.is_root_of_mount() {
        return Err(AxError::InvalidInput);
    }
    let mp = loc.mountpoint().clone();
    let busy = mountpoint_has_open_files(&mp);
    if busy && (flags & (MNT_FORCE | MNT_DETACH)) == 0 {
        return Err(AxError::ResourceBusy);
    }
    loc.filesystem().flush()?;
    let key = Arc::as_ptr(&mp) as usize;
    let disk_idx = EXT4_DISK_FOR_MOUNT.lock().get(&key).copied();
    loc.unmount()?;
    EXT4_DISK_FOR_MOUNT.lock().remove(&key);
    if let Some(idx) = disk_idx {
        EXT4_IN_USE_DISKS.lock().remove(&idx);
    }
    Ok(0)
}
