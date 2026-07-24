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

#[derive(Clone, Debug)]
pub(crate) struct WatchMetadata {
    pub(crate) is_dir: bool,
    pub(crate) is_recursive: bool,
    pub(crate) reported_path: PathBuf,
    pub(crate) is_user_watch: bool,
    pub(crate) user_is_recursive: bool,
    /// The filter governing this entry: the user's requested filter for user watches, and the
    /// covering root's filter for entries added by that root's walks and discovery. The
    /// overlap barrier in [`check_watch_barriers`] keeps filtered watches disjoint, so a
    /// single filter per entry is sufficient.
    pub(crate) watch_filter: WatchFilter,
}

/// What the overlap barrier needs to know about an already-registered user watch. Backends
/// store watches in their own shapes, so each one projects its entries into this.
pub(crate) struct WatchSummary<'a> {
    pub(crate) path: &'a Path,
    pub(crate) is_dir: bool,
    pub(crate) is_recursive: bool,
    pub(crate) filter: &'a WatchFilter,
}

impl WatchPath {
    pub(crate) fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            absolute: absolute_path(path)?,
            requested: path.to_path_buf(),
        })
    }

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
    pub(crate) fn summary<'a>(&'a self, path: &'a Path) -> WatchSummary<'a> {
        WatchSummary {
            path,
            is_dir: self.is_dir,
            is_recursive: self.user_is_recursive,
            filter: &self.watch_filter,
        }
    }

    pub(crate) fn new(
        path: &WatchPath,
        is_dir: bool,
        is_recursive: bool,
        is_user_watch: bool,
        existing_watch: Option<&Self>,
        watch_filter: WatchFilter,
    ) -> Self {
        // Merging a non-user entry over an existing user watch must not disturb what the user
        // asked for: the incoming filter belongs to a plain overlapping root, which the overlap
        // barrier guarantees is accept-all.
        let (reported_path, watch_filter) = match existing_watch {
            Some(existing) if !is_user_watch && existing.is_user_watch => (
                existing.reported_path.clone(),
                existing.watch_filter.clone(),
            ),
            _ => (path.requested.clone(), watch_filter),
        };

        Self {
            is_dir,
            is_recursive: is_recursive || existing_watch.is_some_and(|watch| watch.is_recursive),
            reported_path,
            is_user_watch: is_user_watch || existing_watch.is_some_and(|watch| watch.is_user_watch),
            user_is_recursive: if is_user_watch {
                is_recursive
            } else {
                existing_watch.is_some_and(|watch| watch.user_is_recursive)
            },
            watch_filter,
        }
    }

    /// Whether a user rewatch with these parameters requests exactly the current watch, so the
    /// backend can skip the teardown and rebuild.
    ///
    /// Only unfiltered watches can short-circuit. Two filters cannot be compared for
    /// behavioral equality, and treating them as equal when they are not would leave the
    /// previous filter's exclusions in place, so any watch involving a filter is rebuilt.
    pub(crate) fn rewatch_is_noop(
        &self,
        path: &WatchPath,
        requested_is_recursive: bool,
        watch_filter: &WatchFilter,
    ) -> bool {
        self.user_is_recursive == requested_is_recursive
            && self.reported_path == path.requested
            && self.watch_filter.is_accept_all()
            && watch_filter.is_accept_all()
    }
}

/// Enforces both `watch_filtered` barriers for a user watch request, before any backend state
/// is touched: a directory root the filter itself rejects is refused with
/// [`crate::ErrorKind::PathExcluded`], and a directory watch involving a filter may not
/// overlap another user directory watch in either direction, since filters are never merged
/// across watches. Accept-all watches keep the pre-filter overlap semantics; file watches
/// never conflict.
pub(crate) fn check_watch_barriers<'a, I>(
    absolute: &Path,
    requested: &Path,
    is_dir: bool,
    is_recursive: bool,
    watch_filter: &WatchFilter,
    user_watches: I,
) -> Result<()>
where
    I: IntoIterator<Item = WatchSummary<'a>>,
{
    // Only directory watches are gated or reserved; a watched file inside another watch's
    // subtree does not interact with directory filtering.
    if !is_dir {
        return Ok(());
    }
    if !watch_filter.allows_dir(absolute) {
        return Err(Error::path_excluded().add_path(requested.to_path_buf()));
    }

    // Prefer comparing the resolved forms, which collapses `..` and follows symlinks, so two
    // names for the same directory cannot sneak an overlapping watch past the barrier. Fall
    // back to the literal forms only when a path does not resolve at all, which is what
    // happens once a watched directory is deleted: the surviving path still resolves while the
    // deleted one cannot, so a resolved comparison would stop seeing the overlap. The literal
    // forms are unnormalized, so using them unconditionally would make `<root>/x/../y` look
    // like it were inside `<root>/x`.
    // Resolved lazily: a watcher whose watches are all unfiltered never reaches the comparison
    // below, and must not pay a `canonicalize` per watch for a feature it does not use.
    let mut resolved_new = None;
    for candidate in user_watches {
        if !candidate.is_dir || candidate.path == absolute {
            // Rewatching the same path replaces the watch rather than overlapping it.
            continue;
        }
        if watch_filter.is_accept_all() && candidate.filter.is_accept_all() {
            continue;
        }
        let resolved_new = resolved_new.get_or_insert_with(|| std::fs::canonicalize(absolute).ok());
        let resolved_candidate = std::fs::canonicalize(candidate.path).ok();
        let (new, existing) = match (resolved_new.as_deref(), resolved_candidate.as_deref()) {
            (Some(new), Some(existing)) => (new, existing),
            _ => (absolute, candidate.path),
        };
        if (candidate.is_recursive && new.starts_with(existing))
            || (is_recursive && existing.starts_with(new))
        {
            return Err(Error::watch_overlap()
                .add_path(requested.to_path_buf())
                .add_path(candidate.path.to_path_buf()));
        }
    }
    Ok(())
}

/// Event-time equivalent of directory gating, for backends that cannot selectively watch
/// directories (FSEvents, ReadDirectoryChangesW): an event is allowed unless one of the strict
/// ancestors of its path below `root` (exclusive) is rejected by the filter.
///
/// Only those two backends need this, so it is unused on targets that compile neither. The
/// logic is platform independent and is unit tested everywhere.
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

/// Whether walkdir pushed a directory listing for `entry`, i.e. whether `skip_current_dir`
/// would pop this entry's listing rather than its parent's.
///
/// walkdir descends into a directory, into a symlink it followed, and into a symlinked walk
/// root (`follow_root_links` is on by default). Skipping on an entry it never descended into
/// discards the rest of the parent directory instead.
pub(crate) fn walkdir_descended_into(entry: &walkdir::DirEntry) -> bool {
    entry.file_type().is_dir() || entry.depth() == 0
}

/// Shared `WalkDir::filter_entry` predicate implementing the `WatchFilter` pruning contract:
/// the filter gates directories only (files always pass), and a rejected directory is neither
/// yielded nor descended into.
pub(crate) fn filter_keeps_walk_entry(filter: &WatchFilter, entry: &walkdir::DirEntry) -> bool {
    if filter.is_accept_all() {
        return true;
    }
    // `file_type()` reports the link itself when links are not followed, so a symlinked walk
    // root looks like a plain file -- yet walkdir descends into it anyway, because
    // `follow_root_links` is on by default. Gate anything that resolves to a directory, or the
    // filter is never asked about such a root and its whole target subtree is walked under the
    // link's name.
    let is_dir = entry.file_type().is_dir() || (entry.path_is_symlink() && entry.path().is_dir());
    !is_dir || filter.allows_dir_with_symlink_hint(entry.path(), entry.path_is_symlink())
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

pub(crate) fn preserved_watch_mode(
    path: &Path,
    preserved_roots: &[(PathBuf, bool)],
) -> Option<bool> {
    preserved_roots
        .iter()
        .find(|(root, user_is_recursive)| {
            path == root || (*user_is_recursive && path.starts_with(root))
        })
        .map(|(_, user_is_recursive)| *user_is_recursive)
}

pub(crate) fn preserved_watch_roots<'a, I>(
    path: &Path,
    remove_recursive: bool,
    watches: I,
) -> Vec<(PathBuf, bool)>
where
    I: IntoIterator<Item = (&'a PathBuf, &'a WatchMetadata)>,
{
    if remove_recursive {
        Vec::new()
    } else {
        watches
            .into_iter()
            .filter(|(candidate, watch)| {
                *candidate != path && candidate.starts_with(path) && watch.is_user_watch
            })
            .map(|(path, watch)| (path.clone(), watch.user_is_recursive))
            .collect()
    }
}

pub(crate) fn is_preserved_watch_root(path: &Path, preserved_roots: &[(PathBuf, bool)]) -> bool {
    preserved_roots.iter().any(|(root, _)| path == root)
}

/// Finds the nearest recursive user watch that covers `path`.
///
/// Backends use this when replacing an explicit watch that also inherits recursive coverage from an
/// ancestor. Returning the ancestor's reported path lets them rebuild the inherited subtree with the
/// same path representation users expect from that ancestor watch.
pub(crate) fn recursive_user_watch_ancestor<'a, I>(
    path: &Path,
    watches: I,
) -> Option<(PathBuf, PathBuf)>
where
    I: IntoIterator<Item = (&'a PathBuf, &'a WatchMetadata)>,
{
    watches
        .into_iter()
        .filter(|(candidate, watch)| {
            *candidate != path
                && path.starts_with(candidate)
                && watch.is_user_watch
                && watch.user_is_recursive
        })
        .max_by_key(|(candidate, _)| candidate.as_os_str().len())
        .map(|(path, watch)| (path.clone(), watch.reported_path.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::reject_name;
    use crate::ErrorKind;

    struct Existing(PathBuf, bool, bool, WatchFilter);

    fn check(
        absolute: &Path,
        is_dir: bool,
        is_recursive: bool,
        watch_filter: &WatchFilter,
        user_watches: &[Existing],
    ) -> Result<()> {
        check_watch_barriers(
            absolute,
            absolute,
            is_dir,
            is_recursive,
            watch_filter,
            user_watches
                .iter()
                .map(|Existing(path, is_dir, rec, f)| WatchSummary {
                    path,
                    is_dir: *is_dir,
                    is_recursive: *rec,
                    filter: f,
                }),
        )
    }

    #[test]
    fn rejects_filtered_directory_root() {
        let dir = tempfile::tempdir().unwrap();
        let filter = WatchFilter::with_filter({
            let root = dir.path().to_path_buf();
            move |p: &Path| p != root.as_path()
        });

        let result = check(dir.path(), true, true, &filter, &[]);

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

        check(&file, false, false, &filter, &[]).expect("file roots are never filtered");
    }

    #[test]
    fn allows_accept_all_overlaps_and_same_path_rewatch() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let child = root.join("child");
        std::fs::create_dir(&child).unwrap();
        let filtered = reject_name("excluded");

        let accept_all_watch = [Existing(
            root.clone(),
            true,
            true,
            WatchFilter::accept_all(),
        )];
        check(
            &child,
            true,
            true,
            &WatchFilter::accept_all(),
            &accept_all_watch,
        )
        .expect("accept-all directory watches may overlap");

        let same_path_watch = [Existing(root.clone(), true, true, filtered.clone())];
        check(&root, true, true, &filtered, &same_path_watch)
            .expect("rewatching the same path is replacement, not overlap");
    }

    #[test]
    fn rejects_filtered_overlap_in_both_directions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let child = root.join("child");
        std::fs::create_dir(&child).unwrap();
        let grandchild = child.join("grandchild");
        std::fs::create_dir(&grandchild).unwrap();
        let filter = reject_name("excluded");

        let recursive_root = [Existing(
            root.clone(),
            true,
            true,
            WatchFilter::accept_all(),
        )];
        let result = check(&child, true, true, &filter, &recursive_root);
        assert!(
            matches!(&result, Err(error) if matches!(error.kind, ErrorKind::WatchOverlap)),
            "a filtered watch nested under a recursive directory watch must be refused: {result:?}"
        );
        assert_eq!(
            result.unwrap_err().paths,
            vec![child.clone(), root.clone()],
            "the error must name both the requested path and the one it conflicts with"
        );

        let filtered_root = [Existing(root.clone(), true, true, filter.clone())];
        assert!(
            check(
                &child,
                true,
                false,
                &WatchFilter::accept_all(),
                &filtered_root
            )
            .is_err(),
            "a directory watch inside a filtered recursive watch must be refused"
        );

        let nested_directory = [Existing(
            grandchild.clone(),
            true,
            false,
            WatchFilter::accept_all(),
        )];
        assert!(
            check(&child, true, true, &filter, &nested_directory).is_err(),
            "a filtered recursive watch over an existing directory watch must be refused"
        );
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

        let root = walkdir::WalkDir::new(&link)
            .follow_links(false)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert!(
            !root.file_type().is_dir(),
            "precondition: an unfollowed symlink root is not reported as a directory"
        );
        assert!(
            !filter_keeps_walk_entry(&reject_name("excluded"), &root),
            "a symlinked root resolving to an excluded directory must be pruned"
        );
    }

    // The literal fallback must not be used when both paths resolve: literal paths are not
    // normalized, so `<root>/x/../y` lexically starts with `<root>/x` even though it is a
    // disjoint sibling directory.
    #[test]
    fn unnormalized_sibling_is_not_an_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let x = dir.path().join("x");
        let y = dir.path().join("y");
        std::fs::create_dir(&x).unwrap();
        std::fs::create_dir(&y).unwrap();
        let filtered_x = [Existing(x.clone(), true, true, reject_name("excluded"))];

        let unnormalized = x.join("..").join("y");
        check(
            &unnormalized,
            true,
            true,
            &WatchFilter::accept_all(),
            &filtered_x,
        )
        .expect("a sibling reached through `..` must not count as an overlap");
    }

    #[test]
    fn ignores_file_watch_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let file = root.join("file.txt");
        std::fs::write(&file, "data").unwrap();
        let file_watch = [Existing(file, false, false, WatchFilter::accept_all())];

        check(&root, true, true, &reject_name("excluded"), &file_watch)
            .expect("file watches never conflict with filtered directory watches");
    }

    #[cfg(unix)]
    #[test]
    fn detects_symlink_alias_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let alias = dir.path().join("alias");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let real_watch = [Existing(real, true, true, WatchFilter::accept_all())];

        assert!(
            check(&alias, true, true, &reject_name("excluded"), &real_watch).is_err(),
            "resolved aliases must not bypass filtered overlap checks"
        );
    }

    // The resolved-form comparison alone is not enough: on a platform whose temp directory
    // sits behind a symlink (macOS resolves /var to /private/var), the surviving watch
    // resolves through the link while the deleted one cannot be resolved at all, so the two
    // resolved forms share no prefix. The literal comparison is what keeps the region
    // reserved.
    #[cfg(unix)]
    #[test]
    fn deleted_directory_watch_reserves_its_region_behind_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Watched through the link, then deleted, so it no longer resolves.
        let nested = link.join("nested");
        let stale = [Existing(nested, true, true, WatchFilter::accept_all())];

        assert!(
            check(&link, true, true, &reject_name("excluded"), &stale).is_err(),
            "a stale watch behind a symlinked prefix must still reserve its region"
        );
    }

    #[test]
    fn watch_metadata_preserves_a_user_watch_filter_on_non_user_merge() {
        let path = WatchPath::from_parts(PathBuf::from("/root/child"), PathBuf::from("child"));
        let user_filter = reject_name("excluded");
        let existing = WatchMetadata::new(&path, true, false, true, None, user_filter);

        // A recursive walk from an accept-all ancestor merges a non-user entry over the
        // explicit child watch. The child's own filter must survive.
        let merged = WatchMetadata::new(
            &path,
            true,
            true,
            false,
            Some(&existing),
            WatchFilter::accept_all(),
        );

        assert!(
            merged.is_user_watch,
            "the user watch must survive the merge"
        );
        assert!(
            !merged
                .watch_filter
                .allows_dir(Path::new("/root/child/excluded")),
            "the user watch's filter must not be replaced by the walk's filter"
        );

        // A user rewatch does replace the filter.
        let replaced = WatchMetadata::new(
            &path,
            true,
            true,
            true,
            Some(&merged),
            WatchFilter::accept_all(),
        );
        assert!(replaced.watch_filter.is_accept_all());
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

    #[test]
    fn deleted_directory_watch_still_reserves_its_region() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let nested = root.join("nested");

        // `nested` was watched and has since been deleted, so it no longer resolves.
        let stale = [Existing(nested, true, true, WatchFilter::accept_all())];

        assert!(
            check(&root, true, true, &reject_name("excluded"), &stale).is_err(),
            "a stale watch keeps reserving its region until it is unwatched"
        );
    }
}
