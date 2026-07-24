use file_id::FileId;
use notify::{RecursiveMode, WatchFilter};
use std::path::{Path, PathBuf};

/// A path registered with the debouncer, together with the options it was watched with.
#[derive(Debug, Clone)]
pub struct WatchRoot {
    /// The watched path.
    pub path: PathBuf,
    /// Whether the watch covers the path's descendants.
    pub recursive_mode: RecursiveMode,
    /// The filter the watch was installed with.
    pub watch_filter: WatchFilter,
}

/// The interface of a file ID cache.
///
/// This trait can be implemented for an existing cache, if it already holds `FileId`s.
pub trait FileIdCache {
    /// Get a `FileId` from the cache for a given `path`.
    ///
    /// If the path is not cached, `None` should be returned and there should not be any attempt to read the file ID from disk.
    fn cached_file_id(&self, path: &Path) -> Option<impl AsRef<FileId>>;

    /// Add a new path to the cache or update its value.
    ///
    /// This will be called if a new file or directory is created or if an existing file is overridden.
    ///
    /// `watch_filter` gates directories the same way it does for the watch itself:
    /// implementations should not descend into directories it rejects, since events beneath
    /// them are suppressed and cached entries there could never be invalidated. Use
    /// [`WatchFilter::allows_dir`] for the check. A rejected directory's own ID should still be
    /// cached: its own events are delivered by its watched parent, and rename stitching needs
    /// the ID.
    ///
    /// The filter is documented to receive absolute paths, so implementations should evaluate
    /// it against absolutized paths even when `path` is relative. Absolutizing only
    /// approximates what the backend does: FSEvents canonicalizes, so on macOS a filter that
    /// matches on a canonicalized prefix will gate the watch but not this cache walk. Prefer
    /// matching on [`std::path::Path::file_name`] in filters that also have to gate a cache.
    fn add_path(&mut self, path: &Path, recursive_mode: RecursiveMode, watch_filter: &WatchFilter);

    /// Remove a path from the cache.
    ///
    /// This will be called if a file or directory is deleted.
    fn remove_path(&mut self, path: &Path);

    /// Re-scan all `roots`.
    ///
    /// This will be called if the notification back-end has dropped events.
    /// The roots are passed as argument, so the implementer doesn't have to store them.
    /// Each root carries the `WatchFilter` it was watched with; implementations must honor it
    /// the same way `add_path` does and not walk excluded directories.
    ///
    /// The default implementation calls `add_path` for each root.
    fn rescan(&mut self, roots: &[WatchRoot]) {
        for root in roots {
            self.add_path(&root.path, root.recursive_mode, &root.watch_filter);
        }
    }
}

/// An implementation of the `FileIdCache` trait that doesn't hold any data.
///
/// This pseudo cache can be used to disable the file tracking using file system IDs.
#[derive(Debug, Clone, Default)]
pub struct NoCache;

impl NoCache {
    /// Construct an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Default::default()
    }
}

impl FileIdCache for NoCache {
    fn cached_file_id(&self, _path: &Path) -> Option<impl AsRef<FileId>> {
        Option::<&FileId>::None
    }

    fn add_path(
        &mut self,
        _path: &Path,
        _recursive_mode: RecursiveMode,
        _watch_filter: &WatchFilter,
    ) {
    }

    fn remove_path(&mut self, _path: &Path) {}
}

/// The recommended file ID cache implementation for the current platform
#[cfg(any(target_os = "linux", target_os = "android", target_family = "wasm"))]
pub type RecommendedCache = NoCache;
/// The recommended file ID cache implementation for the current platform
#[cfg(not(any(target_os = "linux", target_os = "android", target_family = "wasm")))]
pub type RecommendedCache = crate::file_id_map::FileIdMap;
