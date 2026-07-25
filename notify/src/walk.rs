use crate::ErrorKind;

/// What a failed watch installation means for the rest of a recursive walk.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WalkFailure {
    /// Nothing was lost, so the walk carries on.
    Skip,
    /// This path errored, but the rest of the tree will still be walked.
    Report,
    /// The watch limit prevents further additions, so the walk ends here.
    Abort,
}

impl WalkFailure {
    pub(crate) fn of(kind: &ErrorKind) -> Self {
        match kind {
            // TOCTOU: an entry can disappear between being listed and being watched.
            ErrorKind::PathNotFound => Self::Skip,
            ErrorKind::MaxFilesWatch => Self::Abort,
            _ => Self::Report,
        }
    }
}

// Inotify and kqueue manage recursive watches one directory at a time.
pub(crate) mod recursive {
    use crate::paths::{WatchPath, reported_path};
    use crate::{RecursiveMode, Result, WatchFilter};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    #[derive(Clone, Debug, Default)]
    pub(crate) struct WatchMetadata {
        /// Whether a recursive user watch covers this entry, so its new subdirectories are
        /// watched.
        pub(crate) is_recursive: bool,
        pub(crate) reported_path: PathBuf,
        pub(crate) is_user_watch: bool,
        /// The user watches that cover this entry: the user watch on its own path, and each
        /// recursive user watch whose walk reached it. A walk keys its entries by the walked
        /// path, so every path in `roots` is the path of the entry or one of its ancestors.
        pub(crate) roots: Vec<Arc<Path>>,
    }

    /// A user watch of a backend that keeps one entry for each watched path.
    #[derive(Clone, Debug)]
    pub(crate) struct UserRoot {
        pub(crate) requested: PathBuf,
        pub(crate) is_recursive: bool,
        pub(crate) watch_filter: WatchFilter,
    }

    /// The user watches by path. Every entry that a user watch covers keeps a reference to its
    /// key.
    pub(crate) type UserRoots = HashMap<Arc<Path>, UserRoot>;

    impl WatchPath {
        pub(crate) fn from_parts(absolute: PathBuf, requested: PathBuf) -> Self {
            Self {
                absolute,
                requested,
            }
        }

        pub(crate) fn child(&self, path: PathBuf) -> Self {
            let requested = reported_path(&self.absolute, &self.requested, &path);
            Self::from_parts(path, requested)
        }
    }

    impl WatchMetadata {
        /// Adds the user watch `root` to the user watches that cover the entry at `path`.
        pub(crate) fn add_root(&mut self, path: &Path, root: &Path, user_roots: &UserRoots) {
            if let Some((root, _)) = user_roots.get_key_value(root)
                && !self.roots.contains(root)
            {
                // Most entries have one root, and `Vec::push` reserves room for four.
                self.roots.reserve_exact(1);
                self.roots.push(root.clone());
            }
            self.refresh(path, user_roots);
        }

        /// Computes the other fields from `roots`. Events of the entry are reported relative to
        /// the requested path of the closest user watch that covers it.
        pub(crate) fn refresh(&mut self, path: &Path, user_roots: &UserRoots) {
            if let Some(root) = self.closest_root()
                && let Some(user_root) = user_roots.get(root)
            {
                self.reported_path = reported_path(root, &user_root.requested, path);
            }
            let is_recursive = self.recursive_roots(user_roots).next().is_some();
            self.is_recursive = is_recursive;
            self.is_user_watch =
                user_roots.contains_key(path) && self.roots.iter().any(|root| **root == *path);
        }

        /// Returns the recursive user watches that cover the entry.
        pub(crate) fn recursive_roots<'a>(
            &'a self,
            user_roots: &'a UserRoots,
        ) -> impl Iterator<Item = &'a Arc<Path>> {
            self.roots
                .iter()
                .filter(|root| user_roots.get(*root).is_some_and(|root| root.is_recursive))
        }

        /// Returns the closest user watch that covers the entry.
        pub(crate) fn closest_root(&self) -> Option<&Arc<Path>> {
            // Every root is the path of the entry or one of its ancestors, so the closest root
            // has the most components. Comparing the lengths of the paths gives the wrong root,
            // because a path can contain `.` components.
            self.roots
                .iter()
                .max_by_key(|root| root.components().count())
        }
    }

    /// Returns the user watches in the form that [`crate::Watcher::watched_paths`] returns.
    pub(crate) fn watched_paths(user_roots: &UserRoots) -> Vec<(PathBuf, RecursiveMode)> {
        user_roots
            .values()
            .map(|root| {
                let mode = if root.is_recursive {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                };
                (root.requested.clone(), mode)
            })
            .collect()
    }

    /// Removes the user watches that the removal of the entry at `path` ends, and returns
    /// whether the entries at and below `path` lose a user watch.
    ///
    /// With `remove_recursive`, the entry was deleted or moved away, so the entries lose every
    /// user watch. Without it, an unwatch of a user watch removes that user watch from the
    /// entries. An unwatch of an entry that only a walk added stops the user watches above it
    /// from covering the entries.
    pub(crate) fn remove_user_roots<'a>(
        user_roots: &mut UserRoots,
        path: &'a Path,
        remove_recursive: bool,
    ) -> impl Fn(&Path) -> bool + 'a {
        let is_user_watch = user_roots.contains_key(path);
        if remove_recursive {
            user_roots.retain(|root, _| !root.starts_with(path));
        } else if is_user_watch {
            user_roots.remove(path);
        }
        move |root: &Path| {
            if remove_recursive {
                true
            } else if is_user_watch {
                root == path
            } else {
                root != path && path.starts_with(root)
            }
        }
    }

    /// Removes the user watch on `path` when adding it failed before the entry of `path` was
    /// added. A failure later in a recursive walk keeps the user watch, because its entry
    /// exists.
    pub(crate) fn remove_failed_user_root(
        user_roots: &mut UserRoots,
        path: &Path,
        result: &Result<()>,
        entry: Option<&WatchMetadata>,
    ) {
        if result.is_err() && !entry.is_some_and(|entry| entry.is_user_watch) {
            user_roots.remove(path);
        }
    }

    impl UserRoot {
        /// Whether a user rewatch with these parameters requests exactly the current watch, so
        /// the backend can skip the teardown and rebuild.
        ///
        /// Only unfiltered watches can short-circuit. Two filters cannot be compared for
        /// behavioral equality, so any watch involving a filter is rebuilt.
        pub(crate) fn rewatch_is_noop(
            &self,
            requested: &Path,
            requested_is_recursive: bool,
            watch_filter: &WatchFilter,
        ) -> bool {
            self.is_recursive == requested_is_recursive
                && self.requested == requested
                && self.watch_filter.is_accept_all()
                && watch_filter.is_accept_all()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn user_root(requested: &str, is_recursive: bool) -> UserRoot {
            UserRoot {
                requested: PathBuf::from(requested),
                is_recursive,
                watch_filter: WatchFilter::accept_all(),
            }
        }

        #[test]
        fn an_entry_is_reported_under_the_closest_user_watch_that_covers_it() {
            let mut user_roots = UserRoots::new();
            user_roots.insert(Path::new("/repo").into(), user_root("/repo", true));
            user_roots.insert(Path::new("/repo/logs").into(), user_root("logs", true));
            user_roots.insert(Path::new("/repo/flat").into(), user_root("flat", false));

            let path = Path::new("/repo/logs/access");
            let mut entry = WatchMetadata::default();
            entry.add_root(path, Path::new("/repo"), &user_roots);
            assert_eq!(entry.reported_path, Path::new("/repo/logs/access"));
            entry.add_root(path, Path::new("/repo/logs"), &user_roots);
            assert_eq!(entry.reported_path, Path::new("logs/access"));
            assert!(entry.is_recursive && !entry.is_user_watch);

            entry
                .roots
                .retain(|root| **root != *Path::new("/repo/logs"));
            entry.refresh(path, &user_roots);
            assert_eq!(entry.reported_path, Path::new("/repo/logs/access"));

            // A non-recursive user watch covers only its own path, so a recursive watch above it
            // keeps the entry recursive.
            let path = Path::new("/repo/flat");
            let mut entry = WatchMetadata::default();
            entry.add_root(path, Path::new("/repo"), &user_roots);
            entry.add_root(path, path, &user_roots);
            assert_eq!(entry.reported_path, Path::new("flat"));
            assert!(entry.is_user_watch && entry.is_recursive);
        }

        #[test]
        fn the_closest_user_watch_does_not_depend_on_the_length_of_its_path() {
            // `watch("c")` and then `watch(".")` in the directory `/dir`.
            let mut user_roots = UserRoots::new();
            user_roots.insert(Path::new("/dir/c").into(), user_root("c", false));
            user_roots.insert(Path::new("/dir/.").into(), user_root(".", true));

            let path = Path::new("/dir/c");
            let mut entry = WatchMetadata::default();
            entry.add_root(path, path, &user_roots);
            entry.add_root(path, Path::new("/dir/."), &user_roots);
            assert_eq!(entry.reported_path, Path::new("c"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn walk_failure_policy() {
        assert_eq!(WalkFailure::of(&ErrorKind::PathNotFound), WalkFailure::Skip);
        assert_eq!(
            WalkFailure::of(&ErrorKind::MaxFilesWatch),
            WalkFailure::Abort
        );
        assert_eq!(
            WalkFailure::of(&ErrorKind::Io(io::ErrorKind::PermissionDenied.into())),
            WalkFailure::Report
        );
        assert_eq!(
            WalkFailure::of(&ErrorKind::Generic("symbolic link loop".into())),
            WalkFailure::Report
        );
    }
}
