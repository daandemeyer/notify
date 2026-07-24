use crate::FileIdCache;
use file_id::{get_file_id, FileId};
use notify::{RecursiveMode, WatchFilter};
use rustc_hash::FxHashMap as HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// A cache to hold the file system IDs of all watched files.
///
/// The file ID cache uses unique file IDs provided by the file system and is used to stitch together
/// rename events in case the notification back-end doesn't emit rename cookies.
#[derive(Debug, Clone, Default)]
pub struct FileIdMap {
    paths: HashMap<PathBuf, FileId>,
}

impl FileIdMap {
    /// Construct an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Default::default()
    }

    fn dir_scan_depth(is_recursive: bool) -> usize {
        if is_recursive {
            usize::MAX
        } else {
            1
        }
    }
}

impl FileIdCache for FileIdMap {
    fn cached_file_id(&self, path: &Path) -> Option<impl AsRef<FileId>> {
        self.paths.get(path)
    }

    fn add_path(&mut self, path: &Path, recursive_mode: RecursiveMode, watch_filter: &WatchFilter) {
        let is_recursive = recursive_mode == RecursiveMode::Recursive;

        // The filter receives backend-resolved absolute paths, so evaluate it on an
        // absolutized mirror of each entry while keeping the cache keyed by the walked form:
        // lookups use delivered event paths in that form. Absolutization only approximates the
        // canonical form the macOS backends resolve to (known limitation).
        let absolute_root = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());

        let mut walk = WalkDir::new(path)
            .follow_links(true)
            .max_depth(Self::dir_scan_depth(is_recursive))
            .into_iter();
        while let Some(entry) = walk.next() {
            let Ok(entry) = entry else { continue };

            if entry.file_type().is_dir() && !watch_filter.is_accept_all() {
                let absolute =
                    absolute_root.join(entry.path().strip_prefix(path).unwrap_or(entry.path()));
                if !watch_filter.allows_dir(&absolute) {
                    // Cache the excluded directory's own ID (its own events are still
                    // delivered by its watched parent, and rename stitching needs it) but never
                    // descend: events beneath it are suppressed, so cached entries there could
                    // never be invalidated.
                    walk.skip_current_dir();
                }
            }

            if let Ok(file_id) = get_file_id(entry.path()) {
                self.paths.insert(entry.into_path(), file_id);
            }
        }
    }

    fn remove_path(&mut self, path: &Path) {
        self.paths.retain(|p, _| !p.starts_with(path));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn reject_name(name: &'static str) -> WatchFilter {
        WatchFilter::with_filter(move |p: &Path| p.file_name() != Some(std::ffi::OsStr::new(name)))
    }

    #[test]
    fn add_path_caches_excluded_directory_own_id() {
        let tempdir = tempfile::tempdir().unwrap();
        let excluded = tempdir.path().join("excluded");
        fs::create_dir(&excluded).unwrap();
        let excluded_file = excluded.join("file.txt");
        fs::write(&excluded_file, b"content").unwrap();

        let mut cache = FileIdMap::new();
        cache.add_path(
            &excluded,
            RecursiveMode::Recursive,
            &reject_name("excluded"),
        );

        // The excluded directory's own events are still delivered by its watched parent and
        // rename stitching needs its ID; nothing beneath it may be fingerprinted.
        assert!(cache.cached_file_id(&excluded).is_some());
        assert!(cache.cached_file_id(&excluded_file).is_none());
    }

    #[test]
    fn add_path_evaluates_filter_on_absolutized_paths() {
        // A genuinely relative walk root needs a directory reachable by a relative path from
        // the process CWD, without mutating that CWD (other tests run in parallel). Nesting the
        // tempdir under the CWD gives exactly that; `tempfile` keeps the name unique, and the
        // guard removes it even if an assertion below fails.
        let cwd = std::env::current_dir().unwrap();
        let tempdir = tempfile::tempdir_in(&cwd).unwrap();
        let relative = PathBuf::from(tempdir.path().file_name().unwrap());

        let excluded = tempdir.path().join("excluded");
        fs::create_dir(&excluded).unwrap();
        fs::write(excluded.join("file.txt"), b"content").unwrap();
        fs::write(tempdir.path().join("visible.txt"), b"content").unwrap();

        // The filter matches on the absolute form only; it must still prune the walk of the
        // relative form.
        let absolute_excluded = cwd.join(&relative).join("excluded");
        let watch_filter =
            WatchFilter::with_filter(move |p: &Path| !p.starts_with(&absolute_excluded));

        let mut cache = FileIdMap::new();
        cache.add_path(&relative, RecursiveMode::Recursive, &watch_filter);

        // Cache keys keep the walked (relative) form, since lookups use delivered event paths
        // in that form.
        assert!(cache
            .cached_file_id(&relative.join("visible.txt"))
            .is_some());
        assert!(cache
            .cached_file_id(&tempdir.path().join("visible.txt"))
            .is_none());
        assert!(cache.cached_file_id(&relative.join("excluded")).is_some());
        assert!(cache
            .cached_file_id(&relative.join("excluded").join("file.txt"))
            .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn add_path_checks_symlink_targets() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path();
        let excluded = root.join("excluded");
        fs::create_dir(&excluded).unwrap();
        fs::write(excluded.join("file.txt"), b"content").unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&excluded, &link).unwrap();

        let mut cache = FileIdMap::new();
        cache.add_path(root, RecursiveMode::Recursive, &reject_name("excluded"));

        // The link's name passes the filter, but its target does not, so the walk must not
        // descend through it either.
        assert!(cache.cached_file_id(&link.join("file.txt")).is_none());
    }
}
