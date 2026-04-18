use alloc::sync::Arc;

use ax_driver::{AxBlockDevice, PartitionRegion};
use ax_sync::Mutex as AxSyncMutex;
use axfs_ng_vfs::{Filesystem, VfsResult};

cfg_if::cfg_if! {
    if #[cfg(feature = "ext4")] {
        mod ext4;
        type DefaultFilesystem = ext4::Ext4Filesystem;

        /// Build an ext4 [`Filesystem`] on a block device that may already be wrapped for sharing.
        pub fn new_ext4_shared(
            dev: Arc<AxSyncMutex<AxBlockDevice>>,
            region: PartitionRegion,
        ) -> VfsResult<Filesystem> {
            ext4::Ext4Filesystem::new_shared(dev, region)
        }
    } else if #[cfg(feature = "fat")] {
        mod fat;
        type DefaultFilesystem = fat::FatFilesystem;
    } else {
        struct DefaultFilesystem;
        impl DefaultFilesystem {
            pub fn new(_dev: AxBlockDevice, _region: PartitionRegion) -> VfsResult<Filesystem> {
                panic!("No filesystem feature enabled");
            }
        }
    }
}

pub fn new_default(dev: AxBlockDevice, region: PartitionRegion) -> VfsResult<Filesystem> {
    DefaultFilesystem::new(dev, region)
}

#[cfg(not(feature = "ext4"))]
pub fn new_ext4_shared(
    _dev: Arc<AxSyncMutex<AxBlockDevice>>,
    _region: PartitionRegion,
) -> VfsResult<Filesystem> {
    Err(axfs_ng_vfs::VfsError::OperationNotSupported)
}
