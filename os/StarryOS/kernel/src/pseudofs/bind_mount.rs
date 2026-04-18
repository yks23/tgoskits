//! Bind mount: expose an existing directory as the root of a nested mount.

use alloc::sync::Arc;

use axfs_ng_vfs::{DirEntry, Filesystem, FilesystemOps, StatFs, VfsResult};

/// Minimal filesystem wrapper so a directory can be mounted as another mount root.
pub struct BindDirFilesystem {
    root: DirEntry,
}

impl BindDirFilesystem {
    pub fn new(root: DirEntry) -> Filesystem {
        Filesystem::new(Arc::new(Self { root }))
    }
}

impl FilesystemOps for BindDirFilesystem {
    fn name(&self) -> &str {
        "bind"
    }

    fn root_dir(&self) -> DirEntry {
        self.root.clone()
    }

    fn stat(&self) -> VfsResult<StatFs> {
        self.root.filesystem().stat()
    }

    fn flush(&self) -> VfsResult<()> {
        self.root.filesystem().flush()
    }
}
