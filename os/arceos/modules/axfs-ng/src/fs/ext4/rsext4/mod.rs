mod fs;
mod inode;
mod util;

use alloc::sync::Arc;

use ax_driver::{
    AxBlockDevice, PartitionBlockDevice, PartitionRegion,
    prelude::{BaseDriverOps, BlockDriverOps, DevResult, DeviceType},
};
use ax_sync::Mutex as AxSyncMutex;
pub use fs::*;
pub use inode::*;
use rsext4::{
    BlockDevice,
    bmalloc::AbsoluteBN,
    config::BLOCK_SIZE,
    disknode::Ext4Timestamp,
    error::{Ext4Error, Ext4Result},
};

pub(crate) struct LockedAxBlockDevice {
    dev: Arc<AxSyncMutex<AxBlockDevice>>,
}

impl LockedAxBlockDevice {
    pub(crate) fn new(dev: Arc<AxSyncMutex<AxBlockDevice>>) -> Self {
        Self { dev }
    }
}

impl BaseDriverOps for LockedAxBlockDevice {
    fn device_name(&self) -> &str { "virtio-blk" }
    fn device_type(&self) -> DeviceType { DeviceType::Block }
}

impl BlockDriverOps for LockedAxBlockDevice {
    fn num_blocks(&self) -> u64 { self.dev.lock().num_blocks() }
    fn block_size(&self) -> usize { self.dev.lock().block_size() }
    fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult {
        self.dev.lock().read_block(block_id, buf)
    }
    fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult {
        self.dev.lock().write_block(block_id, buf)
    }
    fn flush(&mut self) -> DevResult { self.dev.lock().flush() }
}

pub(crate) enum Ext4DiskInner {
    Owned(PartitionBlockDevice<AxBlockDevice>),
    Shared(PartitionBlockDevice<LockedAxBlockDevice>),
}

pub(crate) struct Ext4Disk(pub(crate) Ext4DiskInner);

impl Ext4Disk {
    pub(crate) const fn new(dev: AxBlockDevice, region: PartitionRegion) -> Self {
        Self(Ext4DiskInner::Owned(PartitionBlockDevice::new(dev, region)))
    }

    pub(crate) fn new_shared(
        dev: Arc<AxSyncMutex<AxBlockDevice>>,
        region: PartitionRegion,
    ) -> Self {
        Self(Ext4DiskInner::Shared(PartitionBlockDevice::new(
            LockedAxBlockDevice::new(dev),
            region,
        )))
    }
}

impl BlockDevice for Ext4Disk {
    fn write(&mut self, buffer: &[u8], block_id: AbsoluteBN, count: u32) -> Ext4Result<()> {
        let dev_block = match &self.0 {
            Ext4DiskInner::Owned(p) => p.block_size(),
            Ext4DiskInner::Shared(p) => p.block_size(),
        };
        if !BLOCK_SIZE.is_multiple_of(dev_block) {
            return Err(Ext4Error::invalid_input());
        }
        let factor = (BLOCK_SIZE / dev_block) as u64;
        let required_size = BLOCK_SIZE * count as usize;
        if buffer.len() < required_size {
            return Err(Ext4Error::buffer_too_small(buffer.len(), required_size));
        }
        let start_block = block_id.raw() * factor;
        match &mut self.0 {
            Ext4DiskInner::Owned(p) => {
                p.write_block(start_block, &buffer[..required_size])
                    .map_err(|_| Ext4Error::io())
            }
            Ext4DiskInner::Shared(p) => {
                p.write_block(start_block, &buffer[..required_size])
                    .map_err(|_| Ext4Error::io())
            }
        }
    }

    fn read(&mut self, buffer: &mut [u8], block_id: AbsoluteBN, count: u32) -> Ext4Result<()> {
        let dev_block = match &self.0 {
            Ext4DiskInner::Owned(p) => p.block_size(),
            Ext4DiskInner::Shared(p) => p.block_size(),
        };
        if !BLOCK_SIZE.is_multiple_of(dev_block) {
            return Err(Ext4Error::invalid_input());
        }
        let factor = (BLOCK_SIZE / dev_block) as u64;
        let required_size = BLOCK_SIZE * count as usize;
        if buffer.len() < required_size {
            return Err(Ext4Error::buffer_too_small(buffer.len(), required_size));
        }
        let start_block = block_id.raw() * factor;
        match &mut self.0 {
            Ext4DiskInner::Owned(p) => {
                p.read_block(start_block, &mut buffer[..required_size])
                    .map_err(|_| Ext4Error::io())
            }
            Ext4DiskInner::Shared(p) => {
                p.read_block(start_block, &mut buffer[..required_size])
                    .map_err(|_| Ext4Error::io())
            }
        }
    }

    fn open(&mut self) -> Ext4Result<()> {
        Ok(())
    }

    fn close(&mut self) -> Ext4Result<()> {
        self.flush()
    }

    fn total_blocks(&self) -> u64 {
        let dev_block = match &self.0 {
            Ext4DiskInner::Owned(p) => p.block_size(),
            Ext4DiskInner::Shared(p) => p.block_size(),
        } as u64;
        let total_bytes = match &self.0 {
            Ext4DiskInner::Owned(p) => p.num_blocks(),
            Ext4DiskInner::Shared(p) => p.num_blocks(),
        }
        .saturating_mul(dev_block);
        total_bytes / BLOCK_SIZE as u64
    }

    fn block_size(&self) -> u32 {
        BLOCK_SIZE as u32
    }

    fn flush(&mut self) -> Ext4Result<()> {
        match &mut self.0 {
            Ext4DiskInner::Owned(p) => p.flush().map_err(|_| Ext4Error::io()),
            Ext4DiskInner::Shared(p) => p.flush().map_err(|_| Ext4Error::io()),
        }
    }

    fn current_time(&self) -> Ext4Result<Ext4Timestamp> {
        if cfg!(feature = "times") {
            let dur = ax_hal::time::wall_time();
            Ok(Ext4Timestamp::new(dur.as_secs() as i64, dur.subsec_nanos()))
        } else {
            Ok(Ext4Timestamp::new(0, 0))
        }
    }
}
