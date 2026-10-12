use crate::FileIdCache;
use file_id::{FileId, get_file_id};
use rustc_hash::FxHashMap as HashMap;
use std::path::{Path, PathBuf};

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
}

impl FileIdCache for FileIdMap {
    fn cached_file_id(&self, path: &Path) -> Option<impl AsRef<FileId>> {
        self.paths.get(path)
    }

    fn add_single_path(&mut self, path: &Path) {
        if let Ok(file_id) = get_file_id(path) {
            self.paths.insert(path.to_path_buf(), file_id);
        }
    }

    fn remove_path(&mut self, path: &Path) {
        self.paths.retain(|p, _| !p.starts_with(path));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WatchRoot;
    use notify::{RecursiveMode, WatchFilter, WatchPathConfig};
    use std::fs;

    fn reject_name(name: &'static str) -> WatchPathConfig {
        WatchPathConfig::new(RecursiveMode::Recursive)
            .with_watch_filter(crate::testing::reject_name(name))
    }

    #[test]
    fn add_path_walks_as_deep_as_the_recursive_mode() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path();
        let child = root.join("child");
        let grandchild = child.join("grandchild");
        fs::create_dir_all(&grandchild).unwrap();

        let mut cache = FileIdMap::new();
        cache.add_path(
            root,
            &[&WatchRoot::new(
                root,
                WatchPathConfig::new(RecursiveMode::NonRecursive),
            )],
        );
        assert!(cache.cached_file_id(root).is_some());
        assert!(cache.cached_file_id(&child).is_some());
        assert!(cache.cached_file_id(&grandchild).is_none());

        let mut cache = FileIdMap::new();
        cache.add_path(
            root,
            &[&WatchRoot::new(
                root,
                WatchPathConfig::new(RecursiveMode::Recursive),
            )],
        );
        assert!(cache.cached_file_id(&grandchild).is_some());
    }

    #[test]
    fn add_path_caches_the_id_of_an_excluded_directory_only() {
        let tempdir = tempfile::tempdir().unwrap();
        let excluded = tempdir.path().join("excluded");
        fs::create_dir(&excluded).unwrap();
        let excluded_file = excluded.join("file.txt");
        fs::write(&excluded_file, b"content").unwrap();
        let root = WatchRoot::new(tempdir.path(), reject_name("excluded"));

        let mut cache = FileIdMap::new();
        cache.add_path(tempdir.path(), &[&root]);

        // The watched parent reports the events of the excluded directory, so rename stitching
        // needs its ID. The watch reports nothing below it.
        assert!(cache.cached_file_id(&excluded).is_some());
        assert!(cache.cached_file_id(&excluded_file).is_none());

        // The same holds when the excluded directory is the path that is added.
        let mut cache = FileIdMap::new();
        cache.add_path(&excluded, &[&root]);
        assert!(cache.cached_file_id(&excluded).is_some());
        assert!(cache.cached_file_id(&excluded_file).is_none());
    }

    #[test]
    fn add_path_does_not_filter_the_root() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join("excluded");
        fs::create_dir(&root).unwrap();
        let file = root.join("file.txt");
        fs::write(&file, b"content").unwrap();

        // The watcher refuses a root that the filter rejects, so a registered root is accepted.
        let mut cache = FileIdMap::new();
        cache.add_path(&root, &[&WatchRoot::new(&root, reject_name("excluded"))]);
        assert!(cache.cached_file_id(&file).is_some());
    }

    #[test]
    fn add_path_passes_absolute_paths_to_the_filter() {
        // The walk root has to be a relative path. The process shares its current directory
        // with tests that run in parallel, so the test creates its directory below the current
        // directory instead of changing it.
        let cwd = std::env::current_dir().unwrap();
        let tempdir = tempfile::tempdir_in(&cwd).unwrap();
        let relative = PathBuf::from(tempdir.path().file_name().unwrap());

        let excluded = tempdir.path().join("excluded");
        fs::create_dir(&excluded).unwrap();
        fs::write(excluded.join("file.txt"), b"content").unwrap();
        fs::write(tempdir.path().join("visible.txt"), b"content").unwrap();

        // The filter only rejects the absolute form of the directory.
        let absolute_excluded = cwd.join(&relative).join("excluded");
        let config = WatchPathConfig::new(RecursiveMode::Recursive).with_watch_filter(
            WatchFilter::with_filter(move |p: &Path| !p.starts_with(&absolute_excluded)),
        );

        let mut cache = FileIdMap::new();
        cache.add_path(&relative, &[&WatchRoot::new(&relative, config)]);

        // The cache keys keep the relative form of the walk, because the event paths have it.
        assert!(
            cache
                .cached_file_id(&relative.join("visible.txt"))
                .is_some()
        );
        assert!(
            cache
                .cached_file_id(&tempdir.path().join("visible.txt"))
                .is_none()
        );
        assert!(cache.cached_file_id(&relative.join("excluded")).is_some());
        assert!(
            cache
                .cached_file_id(&relative.join("excluded").join("file.txt"))
                .is_none()
        );
    }

    #[test]
    fn add_path_walks_once_for_the_union_of_several_roots() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path();
        for dir in ["a/deep", "b/deep", "c/deep"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        let reject_a = WatchRoot::new(root, reject_name("a"));
        let reject_b = WatchRoot::new(root, reject_name("b"));

        // Each directory that one of the filters accepts is cached with its entries.
        let mut cache = FileIdMap::new();
        cache.add_path(root, &[&reject_a, &reject_b]);
        for dir in ["a/deep", "b/deep", "c/deep"] {
            assert!(cache.cached_file_id(&root.join(dir)).is_some(), "{dir}");
        }
    }

    #[test]
    fn add_path_walks_the_children_for_a_non_recursive_root_at_the_path() {
        let tempdir = tempfile::tempdir().unwrap();
        let outer = tempdir.path();
        let inner = outer.join("excluded");
        fs::create_dir_all(inner.join("child").join("deep")).unwrap();

        // The outer filter rejects `inner`, but the root on `inner` covers its children.
        let mut cache = FileIdMap::new();
        cache.add_path(
            &inner,
            &[
                &WatchRoot::new(&inner, WatchPathConfig::new(RecursiveMode::NonRecursive)),
                &WatchRoot::new(outer, reject_name("excluded")),
            ],
        );
        assert!(cache.cached_file_id(&inner.join("child")).is_some());
        assert!(
            cache
                .cached_file_id(&inner.join("child").join("deep"))
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn add_path_follows_links_only_when_the_watcher_does() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join("root");
        let target = tempdir.path().join("target");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(target.join("file.txt"), b"content").unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        for follow_symlinks in [false, true] {
            let mut watch_root =
                WatchRoot::new(&root, WatchPathConfig::new(RecursiveMode::Recursive));
            watch_root.follow_symlinks = follow_symlinks;

            // The link is found by the walk of the root.
            let mut cache = FileIdMap::new();
            cache.add_path(&root, &[&watch_root]);
            assert!(cache.cached_file_id(&link).is_some());
            assert_eq!(
                cache.cached_file_id(&link.join("file.txt")).is_some(),
                follow_symlinks
            );

            // The link is the path of an event, for example its creation.
            let mut cache = FileIdMap::new();
            cache.add_path(&link, &[&watch_root]);
            assert!(cache.cached_file_id(&link).is_some());
            assert_eq!(
                cache.cached_file_id(&link.join("file.txt")).is_some(),
                follow_symlinks
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn add_path_does_not_follow_a_link_that_the_watch_does_not_dereference() {
        let tempdir = tempfile::tempdir().unwrap();
        let target = tempdir.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("file.txt"), b"content").unwrap();
        let link = tempdir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let mut root = WatchRoot::new(&link, WatchPathConfig::new(RecursiveMode::NonRecursive));
        root.dereference_symlinks = false;
        let mut cache = FileIdMap::new();
        cache.add_path(&link, &[&root]);
        assert!(cache.cached_file_id(&link).is_some());
        assert!(cache.cached_file_id(&link.join("file.txt")).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn add_path_does_not_follow_a_link_into_an_excluded_directory() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path();
        let excluded = root.join("excluded");
        fs::create_dir(&excluded).unwrap();
        fs::write(excluded.join("file.txt"), b"content").unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&excluded, &link).unwrap();

        let mut cache = FileIdMap::new();
        cache.add_path(root, &[&WatchRoot::new(root, reject_name("excluded"))]);

        // The filter accepts the name of the link, but not its target.
        assert!(cache.cached_file_id(&link).is_some());
        assert!(cache.cached_file_id(&link.join("file.txt")).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn add_path_keeps_the_roots_of_each_depth_below_a_followed_root_link() {
        let tempdir = tempfile::tempdir().unwrap();
        let target = tempdir.path().join("target");
        let dirs = ["a", "b", "c"];
        for dir in dirs {
            fs::create_dir_all(target.join(dir).join("deep")).unwrap();
        }
        let link = tempdir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // The walk lists the rejected directory before its siblings.
        let first = fs::read_dir(&target).unwrap().next().unwrap().unwrap();
        let rejected = dirs
            .into_iter()
            .find(|dir| first.file_name() == *dir)
            .unwrap();

        // The watch on the link follows it, but the watcher does not follow links below it.
        let mut root = WatchRoot::new(&link, reject_name(rejected));
        root.follow_symlinks = false;
        let mut cache = FileIdMap::new();
        cache.add_path(&link, &[&root]);
        assert!(cache.cached_file_id(&link.join(rejected)).is_some());
        assert!(
            cache
                .cached_file_id(&link.join(rejected).join("deep"))
                .is_none()
        );
        for dir in dirs.into_iter().filter(|dir| *dir != rejected) {
            assert!(
                cache.cached_file_id(&link.join(dir).join("deep")).is_some(),
                "{dir}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn add_path_enters_a_link_only_for_the_roots_that_follow_it() {
        let tempdir = tempfile::tempdir().unwrap();
        let outer = tempdir.path().join("outer");
        let target = tempdir.path().join("excluded");
        fs::create_dir(&outer).unwrap();
        fs::create_dir_all(target.join("sub")).unwrap();
        let link = outer.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // The watch on the link does not dereference it, and the outer watch rejects its
        // target.
        let mut on_link = WatchRoot::new(&link, WatchPathConfig::new(RecursiveMode::NonRecursive));
        on_link.dereference_symlinks = false;
        let outer = WatchRoot::new(&outer, reject_name("excluded"));
        let mut cache = FileIdMap::new();
        cache.add_path(&link, &[&on_link, &outer]);
        assert!(cache.cached_file_id(&link).is_some());
        assert!(cache.cached_file_id(&link.join("sub")).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn add_path_does_not_reach_through_a_link_that_the_root_does_not_follow() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join("root");
        let target = tempdir.path().join("target");
        fs::create_dir(&root).unwrap();
        fs::create_dir_all(target.join("inner").join("sub")).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let mut watch_root = WatchRoot::new(&root, WatchPathConfig::new(RecursiveMode::Recursive));
        watch_root.follow_symlinks = false;
        let inner = link.join("inner");
        let mut cache = FileIdMap::new();
        cache.add_path(&inner, &[&watch_root]);
        assert!(cache.cached_file_id(&inner).is_some());
        assert!(cache.cached_file_id(&inner.join("sub")).is_none());
    }

    #[test]
    fn add_path_does_not_call_the_filter_for_a_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let file = tempdir.path().join("file.txt");
        fs::write(&file, b"content").unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let config = WatchPathConfig::new(RecursiveMode::Recursive).with_watch_filter(
            WatchFilter::with_filter({
                let calls = calls.clone();
                move |_: &Path| {
                    calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    true
                }
            }),
        );

        let mut cache = FileIdMap::new();
        cache.add_path(&file, &[&WatchRoot::new(tempdir.path(), config)]);
        assert!(cache.cached_file_id(&file).is_some());
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[cfg(unix)]
    #[test]
    fn add_path_finds_a_link_spelled_with_a_trailing_separator() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().join("root");
        let target = tempdir.path().join("target");
        fs::create_dir(&root).unwrap();
        fs::create_dir_all(target.join("sub")).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let mut watch_root = WatchRoot::new(&root, WatchPathConfig::new(RecursiveMode::Recursive));
        watch_root.follow_symlinks = false;
        let mut cache = FileIdMap::new();
        cache.add_path(
            &PathBuf::from(format!("{}/", link.display())),
            &[&watch_root],
        );
        assert!(cache.cached_file_id(&link.join("sub")).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn add_path_follows_a_link_root_spelled_with_a_trailing_separator() {
        let tempdir = tempfile::tempdir().unwrap();
        let target = tempdir.path().join("target");
        fs::create_dir_all(target.join("child")).unwrap();
        let link = tempdir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // inotify resolves `link/` although the watch does not dereference the link.
        let with_separator = PathBuf::from(format!("{}/", link.display()));
        let config =
            WatchPathConfig::new(RecursiveMode::NonRecursive).with_dereference_symlinks(false);
        let mut root = WatchRoot::new(&with_separator, config);
        root.dereference_symlinks = false;
        let mut cache = FileIdMap::new();
        cache.add_path(&with_separator, &[&root]);
        assert!(cache.cached_file_id(&link.join("child")).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn add_path_follows_links_only_for_roots_that_enter_them() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("watched");
        let target = tempdir.path().join("target");
        fs::create_dir(&path).unwrap();
        fs::create_dir_all(target.join("child/deep")).unwrap();
        let link = path.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let on_path = WatchRoot::new(&path, WatchPathConfig::new(RecursiveMode::NonRecursive));
        for follows in [false, true] {
            let mut above = WatchRoot::new(
                tempdir.path(),
                WatchPathConfig::new(RecursiveMode::Recursive),
            );
            above.follow_symlinks = follows;
            let mut cache = FileIdMap::new();
            cache.add_path(&path, &[&on_path, &above]);
            assert!(cache.cached_file_id(&link).is_some());
            for entry in ["child", "child/deep"] {
                assert_eq!(cache.cached_file_id(&link.join(entry)).is_some(), follows);
            }
        }
    }
}
