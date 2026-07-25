// The backends do not call the watch filter helpers yet.
#![allow(dead_code)]

use crate::{Error, Result, WatchFilter};
use std::{
    env,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub(crate) struct WatchPath {
    pub(crate) absolute: PathBuf,
    pub(crate) requested: PathBuf,
}

/// Returns [`crate::ErrorKind::PathExcluded`] when `watch_filter` rejects the directory that a
/// user asks to watch.
pub(crate) fn check_root(
    watch_filter: &WatchFilter,
    is_dir: bool,
    filter_path: &Path,
    requested: &Path,
) -> Result<()> {
    if is_dir && !watch_filter.allows_root(filter_path) {
        return Err(Error::path_excluded().add_path(requested.to_path_buf()));
    }
    Ok(())
}

impl WatchPath {
    pub(crate) fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            absolute: absolute_path(path)?,
            requested: path.to_path_buf(),
        })
    }
}

/// Returns whether a backend that reports the whole subtree of a watch delivers the event at
/// `path`. FSEvents and ReadDirectoryChangesW take no filter function, so they filter when they
/// deliver an event. The event is dropped when the filter rejects a directory between `root` and
/// `path`, not counting `root` and `path` themselves.
///
/// Only FSEvents and ReadDirectoryChangesW call this function, so it is unused on other
/// targets. Its unit tests run on every target.
#[allow(dead_code)]
pub(crate) fn filter_allows_event_under(filter: &WatchFilter, root: &Path, path: &Path) -> bool {
    if filter.is_accept_all() {
        return true;
    }
    let Some(parent) = path.parent() else {
        return true;
    };
    for ancestor in parent.ancestors() {
        if ancestor == root || !ancestor.starts_with(root) {
            break;
        }
        // Ancestors of an event path are already resolved, so no symlink check is needed.
        if !filter.should_watch(ancestor) {
            return false;
        }
    }
    true
}

/// Returns whether `filter` excludes the walk entry `entry`, and makes `walk` skip the contents
/// of an excluded directory. The filter only applies to directories, so a file is never
/// excluded. The caller decides what to do with the excluded entry itself. The walk starts at
/// the root of a user watch, whose parents are never filtered.
pub(crate) fn prune_walk_entry(
    walk: &mut walkdir::IntoIter,
    filter: &WatchFilter,
    entry: &walkdir::DirEntry,
) -> bool {
    if filter.is_accept_all() {
        return false;
    }
    prune_walk_entry_with(walk, entry, |path, is_symlink| {
        if entry.depth() == 0 {
            filter.allows_root(path)
        } else {
            filter.allows_dir_with_symlink_hint(path, is_symlink)
        }
    })
}

/// Like [`prune_walk_entry`], with `allowed` in place of a filter. `allowed` is only called for
/// a directory, with its path and whether it is a symbolic link.
pub(crate) fn prune_walk_entry_with(
    walk: &mut walkdir::IntoIter,
    entry: &walkdir::DirEntry,
    allowed: impl FnOnce(&Path, bool) -> bool,
) -> bool {
    // `file_type()` describes the link itself when links are not followed, so a symlinked walk
    // root looks like a file. walkdir descends into such a root unless `follow_root_links` is
    // off. Without the second check the filter is never called for that root, and the walk
    // covers the target under the name of the link.
    // walkdir checks the walk root with `lstat`, which follows a link when the root ends with a
    // separator.
    let is_symlink = entry.path_is_symlink() || (entry.depth() == 0 && is_symlink(entry.path()));
    let is_dir = entry.file_type().is_dir() || (is_symlink && entry.path().is_dir());
    if !is_dir || allowed(entry.path(), is_symlink) {
        return false;
    }
    // `skip_current_dir` drops the directory listing that walkdir opened last. walkdir opens a
    // listing for a directory, for a symlink it follows and for a symlinked walk root that it
    // follows. At the walk root without a listing, the call does nothing. For any other entry
    // the call drops the rest of the parent directory instead.
    if entry.file_type().is_dir() || entry.depth() == 0 {
        walk.skip_current_dir();
    }
    true
}

/// Returns `path` without a trailing separator. `lstat` follows a symbolic link when the path
/// ends with a separator.
pub(crate) fn without_trailing_separator(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => parent.join(name),
        _ => path.to_path_buf(),
    }
}

/// Returns whether `path` is a symbolic link, also when `path` ends with a separator.
pub(crate) fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(without_trailing_separator(path))
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
}

pub(crate) fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir().map_err(Error::io)?.join(path))
    }
}

pub(crate) fn reported_path(root_absolute: &Path, root_requested: &Path, path: &Path) -> PathBuf {
    debug_assert!(
        path.starts_with(root_absolute),
        "reported_path called with path outside root: root={}, path={}",
        root_absolute.display(),
        path.display()
    );

    match path.strip_prefix(root_absolute) {
        Ok(relative) if !relative.as_os_str().is_empty() => root_requested.join(relative),
        _ => root_requested.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;
    use crate::test::reject_name;

    #[cfg(unix)]
    #[test]
    fn is_symlink_ignores_a_trailing_separator() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(is_symlink(&link));
        assert!(is_symlink(&PathBuf::from(format!("{}/", link.display()))));
        assert!(!is_symlink(dir.path()));
    }

    #[test]
    fn rejects_filtered_directory_root() {
        let dir = tempfile::tempdir().unwrap();
        let filter = WatchFilter::with_filter({
            let root = dir.path().to_path_buf();
            move |p: &Path| p != root.as_path()
        });

        let result = check_root(&filter, true, dir.path(), dir.path());

        assert!(
            matches!(&result, Err(error) if matches!(error.kind, ErrorKind::PathExcluded)),
            "watching a rejected directory root must fail with PathExcluded: {result:?}"
        );
        assert_eq!(result.unwrap_err().paths, vec![dir.path().to_path_buf()]);
    }

    #[test]
    fn does_not_reject_file_roots() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("watched.txt");
        std::fs::write(&file, "data").unwrap();
        let filter = WatchFilter::with_filter({
            let file = file.clone();
            move |p: &Path| p != file.as_path()
        });

        check_root(&filter, false, &file, &file).expect("file roots are never filtered");
    }

    // walkdir yields a symlinked walk root with `file_type().is_dir() == false` when links are
    // not followed, but still descends into it. Gating on `file_type()` alone would therefore
    // never consult the filter for such a root and would walk the excluded target under the
    // link's name.
    #[cfg(unix)]
    #[test]
    fn walk_entry_gates_a_symlinked_root_that_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let excluded = dir.path().join("excluded");
        std::fs::create_dir(&excluded).unwrap();
        std::fs::write(excluded.join("secret.txt"), "x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&excluded, &link).unwrap();

        let mut walk = walkdir::WalkDir::new(&link).follow_links(false).into_iter();
        let root = walk.next().unwrap().unwrap();
        assert!(
            !root.file_type().is_dir(),
            "precondition: an unfollowed symlink root is not reported as a directory"
        );
        assert!(
            prune_walk_entry(&mut walk, &reject_name("excluded"), &root),
            "a symlinked root resolving to an excluded directory must be pruned"
        );
        assert!(
            walk.next().is_none(),
            "the walk must not list the contents of the excluded target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn walk_entry_gates_a_symlinked_root_with_a_trailing_separator() {
        let dir = tempfile::tempdir().unwrap();
        let excluded = dir.path().join("excluded");
        std::fs::create_dir(&excluded).unwrap();
        std::fs::write(excluded.join("secret.txt"), "x").unwrap();
        std::os::unix::fs::symlink(&excluded, dir.path().join("link")).unwrap();

        let mut walk = walkdir::WalkDir::new(dir.path().join("link/"))
            .follow_links(false)
            .into_iter();
        let root = walk.next().unwrap().unwrap();
        assert!(prune_walk_entry(&mut walk, &reject_name("excluded"), &root));
        assert!(walk.next().is_none());
    }

    #[test]
    fn allows_event_under_gates_on_ancestor_directories() {
        let root = Path::new("/watch/root");
        let filter = reject_name("excluded");
        let allows = |path: &str| filter_allows_event_under(&filter, root, Path::new(path));

        // Files directly under the root are always allowed.
        assert!(allows("/watch/root/file.txt"));
        // An event on the rejected directory itself is delivered (its parent is watched),
        // matching the walk-based backends.
        assert!(allows("/watch/root/excluded"));
        // Events beneath a rejected directory are suppressed, at any depth.
        assert!(!allows("/watch/root/excluded/file.txt"));
        assert!(!allows("/watch/root/excluded/deep/file.txt"));
        assert!(allows("/watch/root/ok/file.txt"));
        // An event on the watch root itself has no gating ancestors.
        assert!(filter_allows_event_under(&filter, root, root));
        // The accept-all fast path never rejects.
        assert!(filter_allows_event_under(
            &WatchFilter::accept_all(),
            root,
            Path::new("/watch/root/excluded/file.txt")
        ));
    }
}
