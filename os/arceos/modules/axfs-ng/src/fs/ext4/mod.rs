mod fs;
mod inode;
mod util;

use alloc::sync::Arc;

use ax_driver::{
    AxBlockDevice, PartitionBlockDevice, PartitionRegion,
    prelude::{BaseDriverOps, BlockDriverOps, DevResult, DeviceType},
};
pub use fs::*;
pub use inode::*;
use ax_sync::Mutex as AxSyncMutex;
use lwext4_rust::{BlockDevice, Ext4Error, Ext4Result, ffi::EIO};

pub(crate) struct LockedAxBlockDevice {
    dev: Arc<AxSyncMutex<AxBlockDevice>>,
}

impl LockedAxBlockDevice {
    pub(crate) fn new(dev: Arc<AxSyncMutex<AxBlockDevice>>) -> Self {
        Self { dev }
    }
}

impl BaseDriverOps for LockedAxBlockDevice {
    fn device_name(&self) -> &str {
        "virtio-blk"
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }
}

impl BlockDriverOps for LockedAxBlockDevice {
    fn num_blocks(&self) -> u64 {
        self.dev.lock().num_blocks()
    }

    fn block_size(&self) -> usize {
        self.dev.lock().block_size()
    }

    fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult {
        self.dev.lock().read_block(block_id, buf)
    }

    fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult {
        self.dev.lock().write_block(block_id, buf)
    }

    fn flush(&mut self) -> DevResult {
        self.dev.lock().flush()
    }
}

pub(crate) enum Ext4DiskInner {
    Owned(PartitionBlockDevice<AxBlockDevice>),
    Shared(PartitionBlockDevice<LockedAxBlockDevice>),
}

pub(crate) struct Ext4Disk(Ext4DiskInner);

impl Ext4Disk {
    pub(crate) const fn new(dev: AxBlockDevice, region: PartitionRegion) -> Self {
        Self(Ext4DiskInner::Owned(PartitionBlockDevice::new(dev, region)))
    }

    pub(crate) fn new_shared(dev: Arc<AxSyncMutex<AxBlockDevice>>, region: PartitionRegion) -> Self {
        Self(Ext4DiskInner::Shared(PartitionBlockDevice::new(
            LockedAxBlockDevice::new(dev),
            region,
        )))
    }

    fn check_buffer_len(&self, buf_len: usize) -> Ext4Result<()> {
        let block_size = match &self.0 {
            Ext4DiskInner::Owned(p) => p.block_size(),
            Ext4DiskInner::Shared(p) => p.block_size(),
        };
        if block_size == 0 || !buf_len.is_multiple_of(block_size) {
            return Err(Ext4Error::new(EIO as _, None));
        }
        Ok(())
    }
}

impl BlockDevice for Ext4Disk {
    fn read_blocks(&mut self, block_id: u64, buf: &mut [u8]) -> Ext4Result<usize> {
        self.check_buffer_len(buf.len())?;
        match &mut self.0 {
            Ext4DiskInner::Owned(p) => {
                p.read_block(block_id, buf).map_err(|_| Ext4Error::new(EIO as _, None))?;
            }
            Ext4DiskInner::Shared(p) => {
                p.read_block(block_id, buf).map_err(|_| Ext4Error::new(EIO as _, None))?;
            }
        }
        Ok(buf.len())
    }

    fn write_blocks(&mut self, block_id: u64, buf: &[u8]) -> Ext4Result<usize> {
        self.check_buffer_len(buf.len())?;
        match &mut self.0 {
            Ext4DiskInner::Owned(p) => {
                p.write_block(block_id, buf).map_err(|_| Ext4Error::new(EIO as _, None))?;
            }
            Ext4DiskInner::Shared(p) => {
                p.write_block(block_id, buf).map_err(|_| Ext4Error::new(EIO as _, None))?;
            }
        }
        Ok(buf.len())
    }

    fn num_blocks(&self) -> Ext4Result<u64> {
        Ok(match &self.0 {
            Ext4DiskInner::Owned(p) => p.num_blocks(),
            Ext4DiskInner::Shared(p) => p.num_blocks(),
        })
    }
}
