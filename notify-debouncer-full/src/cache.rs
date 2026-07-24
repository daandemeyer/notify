use file_id::FileId;
use notify::{RecursiveMode, WatchPathConfig};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// A path registered with the debouncer, together with the options it was watched with.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WatchRoot {
    /// The watched path.
    pub path: PathBuf,
    /// The options the path was watched with.
    pub config: WatchPathConfig,
}

impl WatchRoot {
    /// Creates the root of a watch on `path` with the options `config`.
    ///
    /// # Examples
    ///
    /// ```
    /// use notify::{RecursiveMode, WatchPathConfig};
    /// use notify_debouncer_full::WatchRoot;
    ///
    /// let root = WatchRoot::new("src", WatchPathConfig::new(RecursiveMode::Recursive));
    /// ```
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, config: WatchPathConfig) -> Self {
        Self {
            path: path.into(),
            config,
        }
    }
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
    /// `roots` are the watches that cover `path`: a watch on `path` itself and the recursive
    /// watches above it that reach `path`. The default implementation walks `path` and calls
    /// `add_single_path` for each entry that one of the roots reaches. A non-recursive root
    /// reaches the direct children of `path`.
    ///
    /// A root does not enter a directory that its [`WatchFilter`](notify::WatchFilter) rejects,
    /// and that includes `path` when it is not the path of the root. The watch does not report
    /// changes below such a directory, so IDs cached there would never be removed. The ID of the
    /// rejected directory itself is cached, because its watched parent reports its events.
    fn add_path(&mut self, path: &Path, roots: &[&WatchRoot]) {
        let max_depth = |root: &WatchRoot| match root.config.recursive_mode() {
            RecursiveMode::Recursive => usize::MAX,
            RecursiveMode::NonRecursive => 1,
        };
        // The filter receives absolute paths, in the form that the backends build. The cache
        // keys keep the form of `path`, because the delivered event paths have that form.
        let absolute = roots
            .iter()
            .any(|root| !root.config.watch_filter().is_accept_all())
            .then(|| crate::absolute_path(path));
        let mut walk = WalkDir::new(path)
            .follow_links(true)
            .max_depth(roots.iter().map(|root| max_depth(root)).max().unwrap_or(0))
            .into_iter();
        // The indices in `roots` of the roots that enter the last directory at each depth.
        let mut entering: Vec<Vec<usize>> = Vec::new();
        while let Some(entry) = walk.next() {
            let Ok(entry) = entry else { continue };
            let depth = entry.depth();
            entering.truncate(depth);
            self.add_single_path(entry.path());
            if !entry.file_type().is_dir() {
                continue;
            }
            let reaching = entering
                .last()
                .cloned()
                .unwrap_or_else(|| (0..roots.len()).collect());
            let entered: Vec<_> = reaching
                .into_iter()
                .filter(|&index| {
                    let root = roots[index];
                    let watch_filter = root.config.watch_filter();
                    // The watcher checks the root of a watch when it is added.
                    depth < max_depth(root)
                        && ((depth == 0 && path == root.path)
                            || watch_filter.is_accept_all()
                            || absolute.as_ref().is_some_and(|absolute| {
                                match entry.path().strip_prefix(path) {
                                    Ok(relative) if depth > 0 => {
                                        watch_filter.allows_dir(&absolute.join(relative))
                                    }
                                    _ => watch_filter.allows_dir(absolute),
                                }
                            }))
                })
                .collect();
            if entered.is_empty() {
                walk.skip_current_dir();
            }
            entering.push(entered);
        }
    }

    /// Add `path` to the cache without the entries below it.
    ///
    /// This will be called for an entry inside a non-recursive watch, and by `add_path` for each
    /// entry it walks. The watch does not report changes below an entry of a non-recursive watch,
    /// so the cache does not need their IDs.
    fn add_single_path(&mut self, path: &Path);

    /// Remove a path from the cache.
    ///
    /// This will be called if a file or directory is deleted.
    fn remove_path(&mut self, path: &Path);

    /// Re-scan all `roots`.
    ///
    /// This will be called if the notification back-end has dropped events.
    /// The roots are passed as argument, so the implementer doesn't have to store them.
    ///
    /// The default implementation calls `add_path` for each root.
    fn rescan(&mut self, roots: &[WatchRoot]) {
        for root in roots {
            self.add_path(&root.path, &[root]);
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

    fn add_path(&mut self, _path: &Path, _roots: &[&WatchRoot]) {}

    fn add_single_path(&mut self, _path: &Path) {}

    fn remove_path(&mut self, _path: &Path) {}
}

/// The recommended file ID cache implementation for the current platform
#[cfg(any(target_os = "linux", target_os = "android", target_family = "wasm"))]
pub type RecommendedCache = NoCache;
/// The recommended file ID cache implementation for the current platform
#[cfg(not(any(target_os = "linux", target_os = "android", target_family = "wasm")))]
pub type RecommendedCache = crate::file_id_map::FileIdMap;
