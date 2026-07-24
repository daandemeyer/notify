#![cfg_attr(docsrs, feature(doc_cfg))]

//! Cross-platform file system notification library
//!
//! # Installation
//!
//! ```toml
//! [dependencies]
//! notify = "9.0.0-rc.7"
//! ```
//!
//! If you want debounced events (or don't need them in-order), see [notify-debouncer-mini](https://docs.rs/notify-debouncer-mini/latest/notify_debouncer_mini/)
//! or [notify-debouncer-full](https://docs.rs/notify-debouncer-full/latest/notify_debouncer_full/).
//!
//! ## Features
//!
//! List of compilation features, see below for details
//!
//! - `serde` for serialization of events
//! - `macos_fsevent` (default) for the FSEvents backend on macOS
//! - `macos_kqueue` for the kqueue backend on macOS
//! - `freebsd_inotify` enables notify's inotify backend on FreeBSD 14.5+
//!   - inotify is automatically enabled when built natively, this feature is only needed for cross-compilation
//! - `serialization-compat-6` restores the serialization behavior of notify 6, off by default
//!
//! Native FreeBSD builds use inotify on 14.5+ and kqueue on older releases. When
//! cross-compiling for FreeBSD 14.5+, enable `freebsd_inotify` explicitly.
//!
//! ### Serde
//!
//! Events are serializable via [serde](https://serde.rs) if the `serde` feature is enabled:
//!
//! ```toml
//! notify = { version = "9.0.0-rc.7", features = ["serde"] }
//! ```
//!
//! # Known Problems
//!
//! ### Network filesystems
//!
//! Network mounted filesystems like NFS may not emit any events for notify to listen to.
//! In Linux programs running under WSL, [`RecommendedWatcher`] uses inotify.
//! On WSL2, changes made by Windows applications to files on Windows filesystems (such as
//! `/mnt/c/...`) may not produce inotify events, even when [`Watcher::watch`] succeeds.
//! See [issue #254](https://github.com/notify-rs/notify/issues/254) and
//! [microsoft/WSL#4739](https://github.com/microsoft/WSL/issues/4739).
//!
//! A workaround is to use [`PollWatcher`] explicitly for paths affected by these limitations.
//! Set the scan interval with [`Config::with_poll_interval`] (the default is 30 seconds).
//! Shorter intervals reduce detection latency but increase filesystem I/O.
//! Polling compares the state observed at each scan; changes that occur and are reverted between
//! scans may be missed.
//!
//! If modification timestamps do not reliably reflect content changes, enable
//! [`Config::with_compare_contents`] with `true`.
//! This reads and hashes each file on every scan, increasing I/O and CPU usage.
//!
//! ### Docker with Linux on macOS M1
//!
//! Docker on macOS M1 [throws](https://github.com/notify-rs/notify/issues/423) `Function not implemented (os error 38)`.
//! You have to manually use the [`PollWatcher`], as the native backend isn't available inside the emulation.
//!
//! ### macOS, FSEvents and unowned files
//!
//! Due to the inner security model of FSEvents (see [FileSystemEventSecurity](https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/FSEvents_ProgGuide/FileSystemEventSecurity/FileSystemEventSecurity.html)),
//! some events cannot be observed easily when trying to follow files that do not
//! belong to you. In this case, reverting to the pollwatcher can fix the issue,
//! with a slight performance cost.
//!
//! ### macOS/APFS: `std::fs::copy` can trigger events on the source path
//!
//! On APFS, `std::fs::copy` may use copy-on-write cloning (`fclonefileat`/`clonefile`).
//! This can update inode metadata on the source file, and FSEvents may report a metadata change
//! for the source path (see [issue #259](https://github.com/notify-rs/notify/issues/259) and
//! [issue #465](https://github.com/notify-rs/notify/issues/465)).
//!
//! Workarounds are to avoid `std::fs::copy` (use `std::io::copy` or `read`/`write` instead), or
//! filter out metadata-only events if they're not relevant (e.g. don't include
//! `EventKindMask::MODIFY_META` in [`Config::with_event_kinds`]).
//!
//! ### Editor Behavior
//!
//! If you rely on precise events (Write/Delete/Create..), you will notice that the actual events
//! can differ a lot between file editors. Some truncate the file on save, some create a new one and replace the old one.
//! With inotify, a watch follows the file's inode, so replacing the file can stop notifications
//! for subsequent saves.
//!
//! To observe subsequent saves after a file is replaced, watch its parent directory with
//! [`RecursiveMode::NonRecursive`] and filter events whose [`Event::paths`] contain the target
//! file's path. Check all paths in an event, since a rename event can include both the old and
//! new paths.
//! This relies on filesystem notifications; for the WSL2 limitation above, use [`PollWatcher`].
//! See also [issue #247](https://github.com/notify-rs/notify/issues/247) and
//! [issue #113](https://github.com/notify-rs/notify/issues/113#issuecomment-281836995).
//!
//! ### Changes to watched paths
//!
//! Renaming, moving, or deleting a directly watched file or directory affects backends differently:
//!
//! | Backend | Rename / move | Delete | New item at original path |
//! | --- | --- | --- | --- |
//! | inotify | Old object, old paths | Watch ends | Rewatch required |
//! | Windows (directory) | Old object, old paths | Watch ends | Rewatch required |
//! | Windows (file) | Original path | Watch kept | Events possible |
//! | FSEvents (macOS) | Original path | Watch kept | Events possible |
//! | kqueue | Watch ends | Watch ends | Rewatch required |
//! | [`PollWatcher`] | Original path | Watch kept | Detected on scan |
//!
//! Exact events depend on the filesystem and operation; see
//! [issue #554](https://github.com/notify-rs/notify/issues/554).
//! Windows may emit no event for a directory rename or move.
//!
//! To detect changes to `/a/b`, also watch `/a` with [`RecursiveMode::NonRecursive`] and
//! recheck the target when the parent reports a change. Remove any surviving watch with
//! [`Watcher::unwatch`] before watching the desired path again, once it exists.
//! This assumes the parent stays in place; see [issue #403](https://github.com/notify-rs/notify/issues/403).
//!
//! For a fixed path that may disappear and return, use [`PollWatcher`]. The path must exist
//! when registered; changes that occur and are reverted between scans can be missed.
//!
//! ### kqueue: event details
//!
//! kqueue does not identify the type of a deleted entry, and this backend does not cache it,
//! so removal events use [`event::RemoveKind::Any`].
//! A non-recursive directory watch reports changes to directory entries as events on the
//! directory itself, without identifying the affected child. Watch individual files to receive
//! their data changes, or use [`RecursiveMode::Recursive`] to track children.
//! See [issue #644](https://github.com/notify-rs/notify/issues/644).
//!
//! Recursive watches discover new entries by scanning directories after a notification.
//! Files created and removed between scans and intermediate paths in rapid renames can be missed.
//! Descendants found while registering a newly created directory are watched, but do not receive
//! individual creation events. Do not rely on receiving a separate event for every operation.
//!
//! ### kqueue: recursive watches and file descriptor limits
//!
//! The kqueue backend keeps an open file descriptor for each watched file and directory.
//! Large recursive watches, including `/`, can exceed the process or system limit and fail
//! with [`ErrorKind::MaxFilesWatch`]. On macOS, use FSEvents for large trees: keep the default
//! features (or enable `macos_fsevent`) and do not enable `macos_kqueue`. Enabling `macos_kqueue`
//! also changes [`RecommendedWatcher`] to kqueue, even when `macos_fsevent` is enabled.
//!
//! During a recursive kqueue watch, missing children are skipped. Other child errors, such as
//! permission failures or symbolic link cycles, are sent to the event handler while the walk
//! continues through the rest of the tree. A successful `watch()` can therefore leave some
//! descendants unwatched; handle error events to detect incomplete coverage.
//! Failure to watch or read the requested root, reaching the watch limit, or failure to register
//! the watches returns an error from `watch()`. Already installed watches are not rolled back.
//!
//! Recursive kqueue watches skip FIFOs, sockets, and device files without reporting errors.
//! Symbolic links to these special files are also skipped. Watching a special file directly
//! returns an [`ErrorKind::Io`] error with [`std::io::ErrorKind::Unsupported`].
//!
//! When filesystem events trigger further watch additions, failures are sent to the event
//! handler; reaching the watch limit stops the remaining additions in that batch.
//! Repeated recoverable errors for the same known path are reported once per request or event
//! batch. Later changes to the parent directory can retry failed entries and report errors again.
//!
//! See [issue #703](https://github.com/notify-rs/notify/issues/703),
//! [issue #455](https://github.com/notify-rs/notify/issues/455), and
//! [issue #596](https://github.com/notify-rs/notify/issues/596).
//!
//! ### Pseudo Filesystems like /proc, /sys
//!
//! Some filesystems like `/proc` and `/sys` on *nix do not emit change events or use correct file change dates.
//! To circumvent that problem you can use the [`PollWatcher`] with the `compare_contents` option.
//!
//! ### Linux: Bad File Descriptor / No space left on device
//!
//! This may be the case of running into the max-files watched limits of your user or system.
//! (Files also includes folders.) Note that for recursive watched folders each file and folder inside counts towards the limit.
//!
//! You may increase this limit in linux via
//! ```sh
//! sudo sysctl fs.inotify.max_user_instances=8192 # example number
//! sudo sysctl fs.inotify.max_user_watches=524288 # example number
//! sudo sysctl -p
//! ```
//!
//! Note that the [`PollWatcher`] is not restricted by this limitation, so it may be an alternative if your users can't increase the limit.
//!
//! ### Watching large directories
//!
//! When watching a very large amount of files, notify may fail to receive all events.
//! For example the linux backend is documented to not be a 100% reliable source. See also issue [#412](https://github.com/notify-rs/notify/issues/412).
//!
//! ### Watching many paths on macOS
//!
//! Use [`Watcher::update_paths`] to register many paths in one batch. The FSEvents backend
//! rebuilds its stream when adding a path that is not already covered by a recursive watch on
//! the same volume. Adding N independent paths with separate [`Watcher::watch`] calls therefore
//! registers O(N²) paths in total; a single batch rebuilds the stream only once.
//!
//! # Examples
//!
//! For more examples visit the [examples folder](https://github.com/notify-rs/notify/tree/main/examples) in the repository.
//!
//! ```rust
//! use notify::{Event, RecursiveMode, Result, Watcher};
//! use std::{path::Path, sync::mpsc};
//!
//! fn main() -> Result<()> {
//!     let (tx, rx) = mpsc::channel::<Result<Event>>();
//!
//!     // Use recommended_watcher() to automatically select the best implementation
//!     // for your platform. The `EventHandler` passed to this constructor can be a
//!     // closure, a `std::sync::mpsc::Sender`, a `crossbeam_channel::Sender`, or
//!     // another type the trait is implemented for.
//!     let mut watcher = notify::recommended_watcher(tx)?;
//!
//!     // Add a path to be watched. All files and directories at that path and
//!     // below will be monitored for changes.
//! #     #[cfg(not(any(
//! #     target_os = "freebsd",
//! #     target_os = "openbsd",
//! #     target_os = "dragonfly",
//! #     target_os = "netbsd")))]
//! #     { // "." doesn't exist on BSD for some reason in CI
//!     watcher.watch(Path::new("."), RecursiveMode::Recursive)?;
//! #     }
//! #     #[cfg(any())]
//! #     { // don't run this in doctests, it blocks forever
//!     // Block forever, printing out events as they come in
//!     for res in rx {
//!         match res {
//!             Ok(event) => println!("event: {:?}", event),
//!             Err(e) => println!("watch error: {:?}", e),
//!         }
//!     }
//! #     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## With different configurations
//!
//! It is possible to create several watchers with different configurations or implementations that
//! all call the same event function. This can accommodate advanced behavior or work around limits.
//!
//! ```rust
//! # use notify::{RecursiveMode, Result, Watcher};
//! # use std::path::Path;
//! #
//! # fn main() -> Result<()> {
//!       fn event_fn(res: Result<notify::Event>) {
//!           match res {
//!              Ok(event) => println!("event: {:?}", event),
//!              Err(e) => println!("watch error: {:?}", e),
//!           }
//!       }
//!
//!       let mut watcher1 = notify::recommended_watcher(event_fn)?;
//!       // we will just use the same watcher kind again here
//!       let mut watcher2 = notify::recommended_watcher(event_fn)?;
//! #     #[cfg(not(any(
//! #     target_os = "freebsd",
//! #     target_os = "openbsd",
//! #     target_os = "dragonfly",
//! #     target_os = "netbsd")))]
//! #     { // "." doesn't exist on BSD for some reason in CI
//! #     watcher1.watch(Path::new("."), RecursiveMode::Recursive)?;
//! #     watcher2.watch(Path::new("."), RecursiveMode::Recursive)?;
//! #     }
//!       // dropping the watcher1/2 here (no loop etc) will end the program
//! #
//! #     Ok(())
//! # }
//! ```

#![deny(missing_docs)]

pub use config::{Config, PathOp, RecursiveMode, WatchPathConfig, WindowsPathSeparatorStyle};
pub use error::{Error, ErrorKind, Result, UpdatePathsError};
pub use notify_types::event::{self, Event, EventKind, EventKindMask};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) type StdResult<T, E> = std::result::Result<T, E>;
pub(crate) type Receiver<T> = std::sync::mpsc::Receiver<T>;
pub(crate) type Sender<T> = std::sync::mpsc::Sender<T>;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    all(target_os = "freebsd", notify_freebsd_inotify),
    target_os = "windows",
))]
pub(crate) type BoundSender<T> = std::sync::mpsc::SyncSender<T>;

#[inline]
pub(crate) fn unbounded<T>() -> (Sender<T>, Receiver<T>) {
    std::sync::mpsc::channel()
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    all(target_os = "freebsd", notify_freebsd_inotify),
    target_os = "windows",
))]
#[inline]
pub(crate) fn bounded<T>(cap: usize) -> (BoundSender<T>, Receiver<T>) {
    std::sync::mpsc::sync_channel(cap)
}

#[cfg(all(target_os = "macos", not(feature = "macos_kqueue")))]
pub use crate::fsevent::FsEventWatcher;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    all(target_os = "freebsd", notify_freebsd_inotify),
))]
pub use crate::inotify::INotifyWatcher;
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "ios",
    all(target_os = "macos", feature = "macos_kqueue")
))]
pub use crate::kqueue::KqueueWatcher;
pub use null::NullWatcher;
pub use poll::PollWatcher;
#[cfg(target_os = "windows")]
pub use windows::ReadDirectoryChangesWatcher;

#[cfg(all(target_os = "macos", not(feature = "macos_kqueue")))]
pub mod fsevent;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    all(target_os = "freebsd", notify_freebsd_inotify),
))]
pub mod inotify;
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "ios",
    all(target_os = "macos", feature = "macos_kqueue")
))]
pub mod kqueue;
#[cfg(target_os = "windows")]
pub mod windows;

pub mod null;
pub mod poll;

mod config;
mod error;
mod paths;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "ios",
    all(target_os = "macos", feature = "macos_kqueue")
))]
mod walk;

#[cfg(test)]
pub(crate) mod test;

/// The set of requirements for watcher event handling functions.
///
/// # Example implementation
///
/// ```no_run
/// use notify::{Event, Result, EventHandler};
///
/// /// Prints received events
/// struct EventPrinter;
///
/// impl EventHandler for EventPrinter {
///     fn handle_event(&mut self, event: Result<Event>) {
///         if let Ok(event) = event {
///             println!("Event: {:?}", event);
///         }
///     }
/// }
/// ```
pub trait EventHandler: Send + 'static {
    /// Handles an event.
    fn handle_event(&mut self, event: Result<Event>);
}

impl<F> EventHandler for F
where
    F: FnMut(Result<Event>) + Send + 'static,
{
    fn handle_event(&mut self, event: Result<Event>) {
        (self)(event);
    }
}

#[cfg(feature = "crossbeam-channel")]
impl EventHandler for crossbeam_channel::Sender<Result<Event>> {
    fn handle_event(&mut self, event: Result<Event>) {
        let _ = self.send(event);
    }
}

#[cfg(feature = "flume")]
impl EventHandler for flume::Sender<Result<Event>> {
    fn handle_event(&mut self, event: Result<Event>) {
        let _ = self.send(event);
    }
}

#[cfg(feature = "futures")]
impl EventHandler for futures::channel::mpsc::UnboundedSender<Result<Event>> {
    fn handle_event(&mut self, event: Result<Event>) {
        let _ = self.unbounded_send(event);
    }
}

#[cfg(feature = "tokio")]
impl EventHandler for tokio::sync::mpsc::UnboundedSender<Result<Event>> {
    fn handle_event(&mut self, event: Result<Event>) {
        let _ = self.send(event);
    }
}

impl EventHandler for std::sync::mpsc::Sender<Result<Event>> {
    fn handle_event(&mut self, event: Result<Event>) {
        let _ = self.send(event);
    }
}

/// Watcher kind enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WatcherKind {
    /// Inotify backend (Linux, Android, and FreeBSD 14.5+)
    Inotify,
    /// FS-Event backend (mac)
    Fsevent,
    /// KQueue backend (bsd,optionally mac)
    Kqueue,
    /// Polling based backend (fallback)
    PollWatcher,
    /// Windows backend
    ReadDirectoryChangesWatcher,
    /// Fake watcher for testing
    NullWatcher,
}

type FilterFn = dyn Fn(&Path) -> bool + Send + Sync + std::panic::RefUnwindSafe;

/// Directory filter to limit what gets watched.
///
/// A directory for which the filter returns `false` is not watched: recursive scans do not
/// descend into it and events beneath it are suppressed. The filter receives absolute paths,
/// resolved as described on [`Watcher::watch_filtered`]. It is only applied to directories:
/// events for the files in a watched directory are delivered, and a watch on a non-directory
/// path is not affected by it.
#[derive(Clone)]
pub struct WatchFilter(Option<Arc<FilterFn>>);

impl std::fmt::Debug for WatchFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("WatchFilter")
            .field(&self.0.as_ref().map_or("no filter", |_| "filter fn"))
            .finish()
    }
}

impl WatchFilter {
    /// Returns a filter that accepts every path, so a watch with it covers every directory.
    #[must_use]
    pub fn accept_all() -> WatchFilter {
        WatchFilter(None)
    }

    /// A filter to limit the paths that get watched.
    ///
    /// Only directories for which `filter` returns `true` will be watched.
    ///
    /// The filter runs on the thread that calls the watch method and on the threads of the
    /// backend, for example the polling thread of [`PollWatcher`]. Some backends call it while
    /// they hold internal locks, so the filter must not block and must not call the watcher.
    /// It must not panic either: a panic in the filter can stop the event thread of the backend
    /// or abort the process. After the event thread stops, the watcher reports no events, and
    /// later calls on it can fail.
    ///
    /// The closure has to be `RefUnwindSafe`. A closure can capture a value of a type that is
    /// not, for example a `parking_lot::Mutex` or a boxed closure, in
    /// [`std::panic::AssertUnwindSafe`]. The closure then has to use the value through `Deref`,
    /// because a closure that uses the field `.0` captures only the field.
    #[must_use]
    pub fn with_filter(
        filter: impl Fn(&Path) -> bool + Send + Sync + std::panic::RefUnwindSafe + 'static,
    ) -> WatchFilter {
        WatchFilter(Some(Arc::new(filter)))
    }

    /// Returns whether this filter was created with [`WatchFilter::accept_all`].
    ///
    /// A filter built with [`WatchFilter::with_filter`] returns `false` even if its closure
    /// always returns `true`. Two closures cannot be compared, so a rewatch of a path only keeps
    /// the existing watch when the old and the new filter are both [`WatchFilter::accept_all`].
    /// `Watcher` implementations use this to skip filtering work entirely.
    #[must_use]
    pub fn is_accept_all(&self) -> bool {
        self.0.is_none()
    }

    /// Whether the directory at `path` may be watched.
    ///
    /// `Watcher` implementations and the `FileIdCache` implementations of
    /// `notify-debouncer-full` use this check for every directory they find below the root of a
    /// watch. When `path` is a symbolic link, the filter is also called for the target of the
    /// link, and for the directories between the target and the closest parent of the link
    /// that contains the target. The target is named below that parent, so it keeps the form of
    /// `path`. When no parent of the link contains the target, for example for a link to another
    /// volume on Windows, the filter is called for the canonical target and for each of its
    /// parents. A name-based filter therefore also rejects a link into an excluded directory. A
    /// link whose target cannot be resolved is rejected.
    ///
    /// `path` should be absolute, since that is the form the filter is documented to receive.
    #[must_use]
    pub fn allows_dir(&self, path: &Path) -> bool {
        if self.is_accept_all() {
            return true;
        }
        self.allows_dir_with_symlink_hint(path, crate::paths::is_symlink(path))
    }

    /// Checks a directory like [`WatchFilter::allows_dir`] for a caller that already knows
    /// whether `path` is a symbolic link, such as a `walkdir` traversal
    /// (`DirEntry::path_is_symlink`). The check then costs no extra syscall per directory.
    pub(crate) fn allows_dir_with_symlink_hint(&self, path: &Path, is_symlink: bool) -> bool {
        if self.is_accept_all() {
            return true;
        }
        if !self.should_watch(path) {
            return false;
        }
        if !is_symlink {
            return true;
        }
        // The filter cannot be called for the target of a link that does not resolve. Accepting
        // such a link would let a caller that cannot resolve it reach an excluded directory.
        let Some((parent, target)) = link_target(path) else {
            return false;
        };
        // A link can point into an excluded directory, for example `link -> node_modules/pkg`.
        // A filter that rejects `node_modules` accepts `pkg`, so the parents of the target are
        // checked too. The walk that found the link has checked the directories from the watch
        // down to `parent`.
        self.should_watch(&target)
            && target
                .ancestors()
                .skip(1)
                .take_while(|ancestor| {
                    parent.is_none_or(|parent| *ancestor != parent && ancestor.starts_with(parent))
                })
                .all(|ancestor| self.should_watch(ancestor))
    }

    /// Whether the directory at `path` may be watched as the root of a watch.
    ///
    /// `Watcher` implementations use this check before they add a watch, and return
    /// [`ErrorKind::PathExcluded`] when it fails. The parents of a watch root are never
    /// filtered. When `path` is a symbolic link, the filter is also called for the target of the
    /// link, but not for the parents of the target.
    ///
    /// `path` should be absolute, since that is the form the filter is documented to receive.
    #[must_use]
    pub fn allows_root(&self, path: &Path) -> bool {
        if self.is_accept_all() {
            return true;
        }
        if !self.should_watch(path) {
            return false;
        }
        !crate::paths::is_symlink(path)
            || link_target(path).is_some_and(|(_, target)| self.should_watch(&target))
    }

    /// Whether a recursive watch on `root` with this filter reaches `path`.
    ///
    /// The watch reaches `path` when [`WatchFilter::allows_dir`] accepts each directory between
    /// `root` and `path`, not counting `root` and `path` themselves. When several watches cover
    /// `path`, only the watches that reach it report its events.
    ///
    /// `root` and `path` should be absolute, since that is the form the filter is documented to
    /// receive.
    #[must_use]
    pub fn reaches(&self, root: &Path, path: &Path) -> bool {
        path.starts_with(root)
            && (self.is_accept_all()
                || path
                    .ancestors()
                    .skip(1)
                    .take_while(|ancestor| *ancestor != root && ancestor.starts_with(root))
                    .all(|ancestor| self.allows_dir(ancestor)))
    }

    /// Returns whether `path` passes this filter, with no symlink resolution.
    ///
    /// Always returns `true` for [`WatchFilter::accept_all`]. Callers gating a directory on
    /// disk want [`WatchFilter::allows_dir`] instead; this is for paths that are already
    /// resolved, such as the ancestors of an event path.
    pub(crate) fn should_watch(&self, path: &Path) -> bool {
        self.0.as_ref().is_none_or(|filter| filter(path))
    }
}

/// Returns the closest parent of the symbolic link `path` that contains the target of the
/// link, and the target. The target is named below that parent, so it keeps the form of `path`.
/// When no parent contains the target, for example for a link to another volume on Windows,
/// the parent is `None` and the target is canonical.
fn link_target(path: &Path) -> Option<(Option<&Path>, PathBuf)> {
    let target = std::fs::canonicalize(path).ok()?;
    let below_parent = path.ancestors().skip(1).find_map(|parent| {
        let relative = target
            .strip_prefix(std::fs::canonicalize(parent).ok()?)
            .ok()?;
        let target = if relative.as_os_str().is_empty() {
            parent.to_path_buf()
        } else {
            parent.join(relative)
        };
        Some((Some(parent), target))
    });
    Some(below_parent.unwrap_or((None, target)))
}

/// Type that can deliver file activity notifications
///
/// `Watcher` is implemented per platform using the best implementation available on that platform.
/// In addition to such event driven implementations, a polling implementation is also provided
/// that should work on any platform.
///
/// # Creating a watcher
///
/// Because `Watcher` is a trait, Rust usually can't infer the concrete watcher type when calling
/// `Watcher::new(...)` directly. Prefer [`recommended_watcher`] / [`RecommendedWatcher`] (or a
/// specific backend like [`PollWatcher`]) when constructing a watcher.
///
/// ```no_run
/// use notify::{Event, RecursiveMode, Result, Watcher};
/// use std::{path::Path, sync::mpsc};
///
/// fn main() -> Result<()> {
///     let (tx, _rx) = mpsc::channel::<Result<Event>>();
///     let mut watcher = notify::recommended_watcher(tx)?;
///     watcher.watch(Path::new("."), RecursiveMode::Recursive)?;
///     Ok(())
/// }
/// ```
pub trait Watcher {
    /// Create a new watcher with an initial Config.
    fn new<F: EventHandler>(event_handler: F, config: config::Config) -> Result<Self>
    where
        Self: Sized;
    /// Begin watching a new path.
    ///
    /// If the `path` is a directory, `recursive_mode` will be evaluated. If `recursive_mode` is
    /// `RecursiveMode::Recursive` events will be delivered for all files in that tree. Otherwise
    /// only the directory and its immediate children will be watched.
    ///
    /// If the `path` is a file, `recursive_mode` will be ignored and events will be delivered only
    /// for the file.
    ///
    /// Event paths are reported using the same root representation as `path`. If `path` is
    /// relative, emitted event paths are relative to the process current directory at the time this
    /// method is called. If `path` is absolute, emitted event paths are absolute. Convert `path`
    /// before calling this method if your application needs a specific representation.
    ///
    /// On success, calling this method again for the same backend-resolved path replaces the
    /// existing watch for that path. The recursive mode is updated to the new value, a second
    /// independent watch is not added, and a single call to [`Watcher::unwatch`] removes the
    /// watched path.
    ///
    /// To add many paths at once, use [`Watcher::update_paths`]. On macOS, this avoids rebuilding
    /// the FSEvents stream for each path.
    ///
    /// For rename, move, and deletion behavior, see
    /// [Changes to watched paths](crate#changes-to-watched-paths).
    fn watch(&mut self, path: &Path, recursive_mode: RecursiveMode) -> Result<()>;

    /// Begin watching a new path, excluding directories rejected by `watch_filter`.
    ///
    /// Behaves like [`Watcher::watch`], except that directories for which `watch_filter`
    /// returns `false` are not watched: recursive scans do not descend into them, directories
    /// discovered later (e.g. created under a recursive watch) are checked against the filter
    /// before being watched, and events beneath rejected directories are suppressed. Events for
    /// non-directory children of an accepted directory are delivered. Events for an
    /// excluded directory itself may still be reported by a watched parent (for example, its
    /// creation or removal), but events beneath that directory are suppressed.
    ///
    /// # Paths the filter receives
    ///
    /// The filter is always called with an absolute path, but not a normalized one: a relative
    /// `path` is joined to the current directory, and its `.` and `..` components stay in the
    /// path. Every backend passes the directories below `path` in this form, also a backend
    /// that resolves symbolic links for its own use. Prefer matching on [`Path::file_name`] or
    /// on [`Path::components`] over comparing whole paths, and never compare against a path
    /// relative to the watch root. On Windows the filter receives the path independent of
    /// [`Config::with_windows_path_separator_style`], which affects only reported event paths.
    ///
    /// The filter also receives the target of a symbolic link, named below the closest parent of
    /// the link that contains the target. On Windows, no parent contains a target on another
    /// volume, and the filter receives the canonical target, which starts with `\\?\`.
    ///
    /// The filter only applies to directories: watching a non-directory `path` is never
    /// affected by the filter.
    ///
    /// # Overlapping watches
    ///
    /// Watches may overlap, with or without filters. A recursive watch reaches a path when its
    /// filter accepts each directory between the watch and the path, as [`WatchFilter::reaches`]
    /// tells, and it includes a directory that it reaches when its filter also accepts that
    /// directory. A directory is watched when one of the watches that cover it includes it. The
    /// filter of one watch does not exclude a directory that another watch includes. Unwatching one
    /// watch leaves the directories that the other watches include. inotify, kqueue and FSEvents
    /// report an event in a directory that several watches include once, under the path of the
    /// closest of those watches. kqueue reports a change of an entry itself, such as a write to a
    /// file, under the closest watch of the entry, which is the watch on the entry when it has one.
    /// `PollWatcher` and ReadDirectoryChangesW report an event once for each watch that includes
    /// the directory. inotify, `PollWatcher` and ReadDirectoryChangesW also report an event on a
    /// file that has its own watch through the watch of its directory, so the event arrives twice.
    /// A symbolic link makes a directory reachable under a second path. inotify reports the
    /// events of that directory once for each watch that is the closest watch of one of its paths.
    /// kqueue and `PollWatcher` report them once for each path that a watch includes.
    ///
    /// # Errors
    ///
    /// Watching a directory the filter itself rejects returns [`ErrorKind::PathExcluded`] and
    /// leaves all watches unchanged. A `path` that is a symlink to a directory is checked
    /// against both the link path and its resolved target. The parents of the target are not
    /// checked, because the parents of a watch root are never filtered.
    ///
    /// Backend notes: inotify and kqueue apply the filter while walking and discovering new
    /// directories. `PollWatcher` applies it while scanning, so it is called for each directory
    /// on every poll. FSEvents (macOS) and ReadDirectoryChangesW (Windows) report
    /// the whole subtree of a watch, and neither API accepts a filter function. On FSEvents and
    /// Windows, an event is dropped when the filter rejects a directory between the watch root
    /// and the event path. There the filter is called once for each of those directories on
    /// every event, on a backend thread, so keep it cheap and free of blocking work. Windows
    /// also drops a modification of a path that the filter rejects and that no longer exists,
    /// because the backend cannot tell whether the path was a directory.
    ///
    /// This is a shorthand for [`Watcher::watch_with`] with
    /// [`WatchPathConfig::with_watch_filter`]. A `Watcher` that does not support filters
    /// returns an error for any filter except [`WatchFilter::accept_all`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use notify::{RecursiveMode, WatchFilter, Watcher};
    /// use std::path::Path;
    ///
    /// # fn main() -> notify::Result<()> {
    /// let mut watcher = notify::recommended_watcher(|_res| {})?;
    /// // The filter is called with absolute paths even though the watch root is relative,
    /// // so match on the file name rather than on a path relative to the root.
    /// watcher.watch_filtered(
    ///     Path::new("."),
    ///     RecursiveMode::Recursive,
    ///     WatchFilter::with_filter(|path: &Path| {
    ///         path.file_name() != Some(std::ffi::OsStr::new(".git"))
    ///     }),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    fn watch_filtered(
        &mut self,
        path: &Path,
        recursive_mode: RecursiveMode,
        watch_filter: WatchFilter,
    ) -> Result<()> {
        self.watch_with(
            path,
            WatchPathConfig::new(recursive_mode).with_watch_filter(watch_filter),
        )
    }

    /// Begin watching a path with per-path settings.
    ///
    /// Behaves like [`Watcher::watch`], with the options in `config` applied to this watch alone.
    /// A backend ignores the options that it does not implement. The watch filter is an
    /// exception. A backend that does not support [`WatchPathConfig::with_watch_filter`] returns
    /// an error for a filter instead of watching the directories that the filter rejects. The
    /// default implementation supports only [`WatchPathConfig::recursive_mode`].
    ///
    /// # Errors
    ///
    /// Returns an error in the case that `path` does not exist or if adding the watch fails.
    /// See [`Watcher::watch_filtered`] for the errors a watch filter adds.
    fn watch_with(&mut self, path: &Path, config: WatchPathConfig) -> Result<()> {
        if !config.watch_filter().is_accept_all() {
            return Err(Error::generic(
                "this watcher does not support watch filters",
            ));
        }
        self.watch(path, config.recursive_mode())
    }

    /// Stop watching a path.
    ///
    /// # Errors
    ///
    /// Returns an error in the case that `path` has not been watched or if removing the watch
    /// fails.
    fn unwatch(&mut self, path: &Path) -> Result<()>;

    /// Add/remove paths to watch in batch.
    ///
    /// For some [`Watcher`] implementations this method provides better performance than multiple
    /// calls to [`Watcher::watch`] and [`Watcher::unwatch`] if you want to add/remove many paths at once.
    /// In particular, the FSEvents backend on macOS rebuilds its stream only once for the whole batch.
    ///
    /// # Errors
    ///
    /// Returns [`UpdatePathsError`] if any operation fails. Operations are applied sequentially.
    /// When an error occurs, processing stops: operations before `origin` have been applied,
    /// `origin` is the operation that failed (if known), and `remaining` are the operations that
    /// were not attempted. `remaining` does not include `origin`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use notify::{Watcher, RecursiveMode, PathOp};
    /// # use std::path::{Path, PathBuf};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let many_paths_to_add: Vec<PathBuf> = vec![];
    /// # let many_paths_to_remove: Vec<PathBuf> = vec![];
    /// let mut watcher = notify::NullWatcher;
    /// let mut batch = Vec::new();
    ///
    /// for path in many_paths_to_add {
    ///     batch.push(PathOp::watch_recursive(path));
    /// }
    ///
    /// for path in many_paths_to_remove {
    ///     batch.push(PathOp::unwatch(path));
    /// }
    ///
    /// // real work is done there
    /// watcher.update_paths(batch)?;
    /// # Ok(())
    /// # }
    /// ```
    // The error returns the failed and the remaining `PathOp`s to the caller. That makes it
    // larger than the size at which clippy reports `result_large_err`.
    #[allow(clippy::result_large_err)]
    fn update_paths(&mut self, ops: Vec<PathOp>) -> StdResult<(), UpdatePathsError> {
        update_paths(ops, |op| match op {
            PathOp::Watch(path, config) => self
                .watch_with(&path, config.clone())
                .map_err(|e| (PathOp::Watch(path, config), e)),
            PathOp::Unwatch(path) => self.unwatch(&path).map_err(|e| (PathOp::Unwatch(path), e)),
        })
    }

    /// Configure the watcher at runtime.
    ///
    /// See the [`Config`] struct for all configuration options.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` on success.
    /// - `Ok(false)` if the watcher does not support or implement the option.
    /// - `Err(notify::Error)` on failure.
    fn configure(&mut self, _option: Config) -> Result<bool> {
        Ok(false)
    }

    /// Returns the currently watched paths and their recursive modes.
    ///
    /// Returned paths use the same representation that was passed to [`Watcher::watch`] or
    /// [`Watcher::update_paths`].
    ///
    /// # Errors
    ///
    /// Returns an error if the watcher implementation cannot provide this information.
    fn watched_paths(&self) -> Result<Vec<(PathBuf, RecursiveMode)>> {
        Err(Error::generic(
            "listing watched paths is not supported by this watcher",
        ))
    }

    /// Returns the watcher kind, allowing to perform backend-specific tasks
    fn kind() -> WatcherKind
    where
        Self: Sized;
}

/// The recommended [`Watcher`] implementation for the current platform
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    all(target_os = "freebsd", notify_freebsd_inotify),
))]
pub type RecommendedWatcher = INotifyWatcher;
/// The recommended [`Watcher`] implementation for the current platform
#[cfg(all(target_os = "macos", not(feature = "macos_kqueue")))]
pub type RecommendedWatcher = FsEventWatcher;
/// The recommended [`Watcher`] implementation for the current platform
#[cfg(target_os = "windows")]
pub type RecommendedWatcher = ReadDirectoryChangesWatcher;
/// The recommended [`Watcher`] implementation for the current platform
#[cfg(any(
    all(target_os = "freebsd", not(notify_freebsd_inotify)),
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "ios",
    all(target_os = "macos", feature = "macos_kqueue")
))]
pub type RecommendedWatcher = KqueueWatcher;
/// The recommended [`Watcher`] implementation for the current platform
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "windows",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "ios"
)))]
pub type RecommendedWatcher = PollWatcher;

/// Convenience method for creating the [`RecommendedWatcher`] for the current platform.
///
/// This is often the most ergonomic way to construct a watcher, because calling `Watcher::new(...)`
/// requires specifying the concrete watcher type.
///
/// ```no_run
/// use notify::{RecursiveMode, Result, Watcher};
/// use std::path::Path;
///
/// fn main() -> Result<()> {
///     let mut watcher = notify::recommended_watcher(|res| println!("event: {res:?}"))?;
///     watcher.watch(Path::new("."), RecursiveMode::Recursive)?;
///     Ok(())
/// }
/// ```
pub fn recommended_watcher<F>(event_handler: F) -> Result<RecommendedWatcher>
where
    F: EventHandler,
{
    // All recommended watchers currently implement `new`, so just call that.
    RecommendedWatcher::new(event_handler, Config::default())
}

#[allow(clippy::result_large_err)]
pub(crate) fn update_paths<F>(ops: Vec<PathOp>, mut apply: F) -> StdResult<(), UpdatePathsError>
where
    F: FnMut(PathOp) -> StdResult<(), (PathOp, Error)>,
{
    let mut iter = ops.into_iter();
    while let Some(op) = iter.next() {
        if let Err((error_op, source)) = apply(op) {
            return Err(UpdatePathsError {
                source,
                origin: Some(error_op),
                remaining: iter.collect(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        fs, iter,
        path::{Path, PathBuf},
        sync::mpsc,
        time::{Duration, Instant},
    };

    use tempfile::tempdir;

    use super::{
        Config, Error, ErrorKind, Event, NullWatcher, PathOp, PollWatcher, RecommendedWatcher,
        RecursiveMode, Result, StdResult, WatchFilter, WatchPathConfig, Watcher, WatcherKind,
    };
    use crate::test::*;

    #[test]
    fn test_object_safe() {
        let _watcher: &dyn Watcher = &NullWatcher;
    }

    #[test]
    fn watch_filter_accept_all_accepts_everything() {
        let filter = WatchFilter::accept_all();
        assert!(filter.is_accept_all());
        assert!(filter.allows_dir(Path::new("/any/path")));
    }

    #[test]
    fn watch_filter_applies_closure() {
        let filter = reject_name("excluded");
        assert!(!filter.is_accept_all());
        assert!(filter.allows_dir(Path::new("/root/included")));
        assert!(!filter.allows_dir(Path::new("/root/excluded")));
    }

    #[cfg(unix)]
    #[test]
    fn watch_filter_allows_dir_checks_symlink_target() {
        let dir = tempdir().unwrap();
        let excluded = dir.path().join("excluded");
        let alias = dir.path().join("alias");
        fs::create_dir(&excluded).unwrap();
        std::os::unix::fs::symlink(&excluded, &alias).unwrap();

        let filter = reject_name("excluded");
        assert!(
            !filter.allows_dir(&alias),
            "a symlink to an excluded directory must be rejected"
        );
        assert!(
            !filter.allows_dir_with_symlink_hint(&alias, true),
            "the hint-taking form must reject it too"
        );
        assert!(
            filter.allows_dir_with_symlink_hint(&alias, false),
            "a caller that says the path is not a link only gets the link path checked"
        );
        assert!(
            WatchFilter::accept_all().allows_dir(&alias),
            "accept-all must not pay for symlink resolution"
        );
    }

    #[cfg(unix)]
    #[test]
    fn watch_filter_allows_dir_checks_the_parents_of_a_symlink_target() {
        let dir = tempdir().unwrap();
        let package = dir.path().join("excluded").join("package");
        fs::create_dir_all(&package).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&package, &link).unwrap();

        let filter = reject_name("excluded");
        assert!(
            !filter.allows_dir(&link),
            "a link into an excluded directory must be rejected"
        );
        assert!(
            !filter.allows_dir(&dir.path().join("link/")),
            "a trailing separator must not hide the link"
        );

        let included = dir.path().join("included");
        fs::create_dir(&included).unwrap();
        let other = dir.path().join("other");
        std::os::unix::fs::symlink(&included, &other).unwrap();
        assert!(filter.allows_dir(&other));
    }

    #[cfg(unix)]
    #[test]
    fn watch_filter_passes_a_symlink_target_in_the_form_of_the_link() {
        let dir = tempdir().unwrap();
        let project = dir.path().join("real").join("project");
        fs::create_dir_all(project.join("sub")).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(dir.path().join("real"), &alias).unwrap();
        std::os::unix::fs::symlink("sub", project.join("link")).unwrap();

        // The link is found below `alias`, so its target is named below `alias` as well.
        let watched = alias.join("project");
        let filter = WatchFilter::with_filter({
            let watched = watched.clone();
            move |path: &Path| path.starts_with(&watched)
        });
        assert!(filter.allows_dir(&watched.join("link")));
        assert!(filter.allows_root(&watched.join("link")));
    }

    #[test]
    fn watch_filter_reaches_a_path_below_accepted_directories() {
        let filter = reject_name("excluded");
        let root = Path::new("/root");

        assert!(filter.reaches(root, Path::new("/root/included/file")));
        assert!(filter.reaches(root, Path::new("/root/excluded")));
        assert!(!filter.reaches(root, Path::new("/root/excluded/file")));
        assert!(!filter.reaches(root, Path::new("/other/file")));
        assert!(WatchFilter::accept_all().reaches(root, Path::new("/root/excluded/file")));
        // The parents of the root are not checked.
        let root = Path::new("/excluded/root");
        assert!(filter.reaches(root, root));
        assert!(filter.reaches(root, Path::new("/excluded/root/file")));
    }

    #[cfg(unix)]
    #[test]
    fn watch_filter_does_not_call_the_filter_above_a_link_to_an_ancestor() {
        let dir = tempdir().unwrap();
        let watched = dir.path().join("excluded").join("project").join("watched");
        fs::create_dir_all(&watched).unwrap();
        let up = watched.join("up");
        std::os::unix::fs::symlink("..", &up).unwrap();

        // `up` leads to `project`. The directories above `project` are not checked.
        assert!(reject_name("excluded").allows_dir(&up));
    }

    #[test]
    fn watch_filter_keeps_config_types_unwind_safe() {
        fn assert_unwind_safe<T: std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
        assert_unwind_safe::<WatchFilter>();
        assert_unwind_safe::<WatchPathConfig>();
        assert_unwind_safe::<PathOp>();
    }

    #[cfg(unix)]
    #[test]
    fn watch_filter_allows_dir_rejects_an_unresolvable_link() {
        let dir = tempdir().unwrap();
        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("missing"), &dangling).unwrap();

        // The target cannot be resolved, so the filter cannot be called for it. Accepting the
        // link would let a watch reach an excluded directory through a link that the check
        // cannot resolve.
        assert!(
            !reject_name("excluded").allows_dir(&dangling),
            "a link whose target cannot be resolved must be rejected"
        );
        assert!(
            WatchFilter::accept_all().allows_dir(&dangling),
            "accept-all still accepts everything"
        );
    }

    #[test]
    fn watch_path_config_carries_watch_filter() {
        let config = WatchPathConfig::new(RecursiveMode::Recursive)
            .with_watch_filter(reject_name("excluded"));
        assert!(config.watch_filter().allows_dir(Path::new("/root/other")));
        assert!(
            !config
                .watch_filter()
                .allows_dir(Path::new("/root/excluded"))
        );
    }

    #[test]
    fn default_watch_with_refuses_a_filter() {
        #[derive(Default)]
        struct PlainWatcher {
            watched: Vec<PathBuf>,
        }

        impl Watcher for PlainWatcher {
            fn new<F: super::EventHandler>(_event_handler: F, _config: Config) -> Result<Self> {
                Ok(Self::default())
            }

            fn watch(&mut self, path: &Path, _recursive_mode: RecursiveMode) -> Result<()> {
                self.watched.push(path.to_path_buf());
                Ok(())
            }

            fn unwatch(&mut self, _path: &Path) -> Result<()> {
                Ok(())
            }

            fn kind() -> WatcherKind {
                WatcherKind::NullWatcher
            }
        }

        let mut watcher = PlainWatcher::default();
        let path = Path::new("/root");
        assert!(
            watcher
                .watch_filtered(path, RecursiveMode::Recursive, reject_name("excluded"))
                .is_err()
        );
        assert!(
            watcher
                .update_paths(vec![PathOp::Watch(
                    path.to_path_buf(),
                    WatchPathConfig::new(RecursiveMode::Recursive)
                        .with_watch_filter(reject_name("excluded")),
                )])
                .is_err()
        );
        assert!(watcher.watched.is_empty());

        watcher
            .watch_filtered(path, RecursiveMode::Recursive, WatchFilter::accept_all())
            .unwrap();
        assert_eq!(watcher.watched, [path]);
    }

    #[test]
    fn watch_filter_debug_names_the_type() {
        assert!(format!("{:?}", WatchFilter::accept_all()).contains("WatchFilter"));
        assert!(format!("{:?}", WatchFilter::with_filter(|_: &Path| true)).contains("WatchFilter"));
    }

    #[test]
    fn test_debug_impl() {
        macro_rules! assert_debug_impl {
            ($t:ty) => {{
                #[allow(dead_code)]
                trait NeedsDebug: std::fmt::Debug {}
                impl NeedsDebug for $t {}
            }};
        }

        assert_debug_impl!(Config);
        assert_debug_impl!(Error);
        assert_debug_impl!(ErrorKind);
        assert_debug_impl!(NullWatcher);
        assert_debug_impl!(PollWatcher);
        assert_debug_impl!(RecommendedWatcher);
        assert_debug_impl!(RecursiveMode);
        assert_debug_impl!(WatchPathConfig);
        assert_debug_impl!(WatcherKind);
    }

    include!("freebsd_version.rs");

    fn freebsd_inotify_supported(output: &str) -> bool {
        parse_freebsd_release(output).is_some_and(|release| release >= FREEBSD_INOTIFY_MIN)
    }

    #[test]
    fn freebsd_inotify_release_threshold() {
        for (version, expected) in [
            ("13.5-RELEASE", false),
            ("14.4-RELEASE", false),
            ("14.4-RELEASE-p3", false),
            ("14.4-STABLE", false),
            ("14.5-BETA1", true),
            ("14.5-RELEASE", true),
            ("14.5-RELEASE-p1", true),
            ("14.5-STABLE", true),
            ("14.6-RELEASE", true),
            ("15.0-RELEASE", true),
            ("15.1-RELEASE", true),
            ("16.0-CURRENT", true),
        ] {
            assert_eq!(freebsd_inotify_supported(version), expected, "{version}");
        }
        assert_eq!(parse_freebsd_release(""), None);
        assert_eq!(parse_freebsd_release("14"), None);
        assert_eq!(parse_freebsd_release("14."), None);
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn recommended_watcher_matches_freebsd_version() {
        let output = std::process::Command::new("/bin/freebsd-version")
            .arg("-u")
            .output()
            .expect("run freebsd-version");
        assert!(output.status.success(), "freebsd-version failed");

        let version = std::str::from_utf8(&output.stdout).expect("parse freebsd-version output");
        let expected = if cfg!(feature = "freebsd_inotify") || freebsd_inotify_supported(version) {
            WatcherKind::Inotify
        } else {
            WatcherKind::Kqueue
        };

        assert_eq!(RecommendedWatcher::kind(), expected);
    }

    fn iter_with_timeout(rx: &mpsc::Receiver<Result<Event>>) -> impl Iterator<Item = Event> + '_ {
        // wait for up to 10 seconds for the events
        let deadline = Instant::now() + Duration::from_secs(10);
        iter::from_fn(move || {
            if Instant::now() >= deadline {
                return None;
            }
            Some(
                rx.recv_timeout(deadline - Instant::now())
                    .expect("did not receive expected event")
                    .expect("received an error"),
            )
        })
    }

    fn canonical_or_path(path: &Path) -> PathBuf {
        path.canonicalize()
            .expect("test paths should always be canonicalizable")
    }

    fn canonical_watch_set(
        paths: Vec<(PathBuf, RecursiveMode)>,
    ) -> HashSet<(PathBuf, RecursiveMode)> {
        paths
            .into_iter()
            .map(|(path, recursive_mode)| (canonical_or_path(&path), recursive_mode))
            .collect()
    }

    fn matches_path(path: &Path, expected: &Path, canonical_expected: Option<&PathBuf>) -> bool {
        path == expected || canonical_expected.is_some_and(|canonical| path == canonical)
    }

    fn watch_with_retry(
        watcher: &mut RecommendedWatcher,
        path: impl AsRef<Path>,
        recursive_mode: RecursiveMode,
    ) -> Result<()> {
        const FSEVENT_WATCH_RETRIES: usize = 5;
        const FSEVENT_WATCH_RETRY_BASE_DELAY: Duration = Duration::from_millis(50);

        let path = path.as_ref();
        for attempt in 0..=FSEVENT_WATCH_RETRIES {
            match watcher.watch(path, recursive_mode) {
                Ok(()) => return Ok(()),
                Err(err)
                    if RecommendedWatcher::kind() == WatcherKind::Fsevent
                        && matches!(
                            &err.kind,
                            ErrorKind::Generic(message)
                                if message == "unable to start FSEvent stream"
                        )
                        && attempt < FSEVENT_WATCH_RETRIES =>
                {
                    let _ = watcher.unwatch(path);
                    let delay_factor = 1u32 << attempt;
                    std::thread::sleep(FSEVENT_WATCH_RETRY_BASE_DELAY * delay_factor);
                }
                Err(err) => return Err(err),
            }
        }

        unreachable!("watch() retries must return or error")
    }

    fn update_paths_unwatch_with_retry(
        watcher: &mut RecommendedWatcher,
        path: &Path,
    ) -> Result<()> {
        const FSEVENT_UNWATCH_RETRIES: usize = 5;
        const FSEVENT_UNWATCH_RETRY_BASE_DELAY: Duration = Duration::from_millis(50);

        for attempt in 0..=FSEVENT_UNWATCH_RETRIES {
            match watcher.update_paths(vec![PathOp::unwatch(path)]) {
                Ok(()) => return Ok(()),
                Err(err)
                    if RecommendedWatcher::kind() == WatcherKind::Fsevent
                        && matches!(
                            &err.source.kind,
                            ErrorKind::Io(io_err) if io_err.raw_os_error() == Some(9)
                        )
                        && attempt < FSEVENT_UNWATCH_RETRIES =>
                {
                    let delay_factor = 1u32 << attempt;
                    std::thread::sleep(FSEVENT_UNWATCH_RETRY_BASE_DELAY * delay_factor);
                }
                Err(err) => return Err(err.into()),
            }
        }

        unreachable!("fsevent unwatch retries must return or error")
    }

    #[test]
    fn integration() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;

        // set up the watcher
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
        watch_with_retry(&mut watcher, dir.path(), RecursiveMode::Recursive)?;

        // create a new file
        let file_path = dir.path().join("file.txt");
        fs::write(&file_path, b"Lorem ipsum")?;

        println!("waiting for event at {}", file_path.display());

        // wait for the create event, ignore all other events
        for event in iter_with_timeout(&rx) {
            if event.paths == vec![file_path.clone()]
                || event.paths == vec![file_path.canonicalize()?]
            {
                return Ok(());
            }

            println!("unexpected event: {event:?}");
        }

        panic!("did not receive expected event");
    }

    #[test]
    fn event_paths_preserve_relative_watch_root()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let cwd = std::env::current_dir()?;
        let dir = tempfile::Builder::new()
            .prefix("notify-relative-")
            .tempdir_in(&cwd)?;
        let relative_dir = dir.path().strip_prefix(&cwd)?.to_path_buf();
        let relative_file = relative_dir.join("file.txt");
        let absolute_file = dir.path().join("file.txt");

        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
        watch_with_retry(&mut watcher, &relative_dir, RecursiveMode::Recursive)?;

        assert!(
            watcher
                .watched_paths()?
                .iter()
                .any(|(path, mode)| path == &relative_dir && *mode == RecursiveMode::Recursive),
            "watched_paths() did not preserve relative watch path"
        );

        fs::write(&absolute_file, b"Lorem ipsum")?;

        for event in iter_with_timeout(&rx) {
            if event.paths.iter().any(|path| path == &relative_file) {
                assert!(
                    event.paths.iter().all(|path| path.is_relative()),
                    "relative watch emitted absolute path: {event:?}"
                );
                return Ok(());
            }

            println!("unexpected event: {event:?}");
        }

        panic!("did not receive expected relative event path");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_trash_dir() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::recommended_watcher;

        let dir = tempdir()?;
        let child_dir = dir.path().join("child");
        fs::create_dir(&child_dir)?;

        let mut watcher = recommended_watcher(|_| {
            // Do something with the event
        })?;
        watcher.watch(&child_dir, RecursiveMode::NonRecursive)?;

        trash::delete(&child_dir)?;

        watcher.watch(dir.path(), RecursiveMode::NonRecursive)?;

        Ok(())
    }

    #[test]
    fn test_update_paths() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;

        let dir_a = dir.path().join("a");
        let dir_b = dir.path().join("b");

        fs::create_dir(&dir_a)?;
        fs::create_dir(&dir_b)?;

        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

        // start watching a and b
        const FSEVENT_UPDATE_PATHS_RETRIES: usize = 5;
        const FSEVENT_UPDATE_PATHS_RETRY_BASE_DELAY: Duration = Duration::from_millis(50);
        for attempt in 0..=FSEVENT_UPDATE_PATHS_RETRIES {
            match watcher.update_paths(vec![
                PathOp::Watch(
                    dir_a.clone(),
                    WatchPathConfig::new(RecursiveMode::Recursive),
                ),
                PathOp::Watch(
                    dir_b.clone(),
                    WatchPathConfig::new(RecursiveMode::Recursive),
                ),
            ]) {
                Ok(()) => break,
                Err(err)
                    if RecommendedWatcher::kind() == WatcherKind::Fsevent
                        && matches!(
                            &err.source.kind,
                            ErrorKind::Generic(message)
                            if message == "unable to start FSEvent stream"
                        )
                        && attempt < FSEVENT_UPDATE_PATHS_RETRIES =>
                {
                    let delay_factor = 1u32 << attempt;
                    std::thread::sleep(FSEVENT_UPDATE_PATHS_RETRY_BASE_DELAY * delay_factor);
                }
                Err(err) => return Err(err.into()),
            }
        }

        // create file1 in both a and b
        let a_file1 = dir_a.join("file1");
        let b_file1 = dir_b.join("file1");
        fs::write(&a_file1, b"Lorem ipsum")?;
        fs::write(&b_file1, b"Lorem ipsum")?;
        let a_file1_canonical = a_file1.canonicalize().ok();
        let b_file1_canonical = b_file1.canonicalize().ok();

        // wait for create events of a/file1 and b/file1
        let mut a_file1_encountered: bool = false;
        let mut b_file1_encountered: bool = false;
        for event in iter_with_timeout(&rx) {
            for path in event.paths {
                a_file1_encountered = a_file1_encountered
                    || matches_path(&path, &a_file1, a_file1_canonical.as_ref());
                b_file1_encountered = b_file1_encountered
                    || matches_path(&path, &b_file1, b_file1_canonical.as_ref());
            }
            if a_file1_encountered && b_file1_encountered {
                break;
            }
        }
        assert!(a_file1_encountered, "Did not receive event of {a_file1:?}");
        assert!(b_file1_encountered, "Did not receive event of {b_file1:?}");

        // stop watching a
        update_paths_unwatch_with_retry(&mut watcher, &dir_a)?;

        // create file2 in both a and b
        let a_file2 = dir_a.join("file2");
        let b_file2 = dir_b.join("file2");
        fs::write(&a_file2, b"Lorem ipsum")?;
        fs::write(&b_file2, b"Lorem ipsum")?;
        let a_file2_canonical = a_file2.canonicalize().ok();
        let b_file2_canonical = b_file2.canonicalize().ok();

        // wait for the create event of b/file2 only
        for event in iter_with_timeout(&rx) {
            for path in event.paths {
                assert!(
                    !matches_path(&path, &a_file2, a_file2_canonical.as_ref()),
                    "Event of {a_file2:?} should not be received"
                );
                if matches_path(&path, &b_file2, b_file2_canonical.as_ref()) {
                    return Ok(());
                }
            }
        }
        panic!("Did not receive the event of {b_file2:?}");
    }

    #[test]
    fn watched_paths_reflect_watch_and_unwatch()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let dir_a = dir.path().join("a");
        let dir_b = dir.path().join("b");
        fs::create_dir(&dir_a)?;
        fs::create_dir(&dir_b)?;

        let (tx, _rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

        watch_with_retry(&mut watcher, &dir_a, RecursiveMode::Recursive)?;
        watch_with_retry(&mut watcher, &dir_b, RecursiveMode::NonRecursive)?;

        let watched = canonical_watch_set(watcher.watched_paths()?);
        assert!(watched.contains(&(canonical_or_path(&dir_a), RecursiveMode::Recursive)));
        assert!(watched.contains(&(canonical_or_path(&dir_b), RecursiveMode::NonRecursive)));

        watcher.unwatch(&dir_a)?;

        let watched = canonical_watch_set(watcher.watched_paths()?);
        assert!(!watched.contains(&(canonical_or_path(&dir_a), RecursiveMode::Recursive)));
        assert!(watched.contains(&(canonical_or_path(&dir_b), RecursiveMode::NonRecursive)));

        Ok(())
    }

    #[test]
    fn rewatching_same_path_replaces_recursive_mode()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let root = canonical_or_path(dir.path());

        let (tx, _rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

        watch_with_retry(&mut watcher, dir.path(), RecursiveMode::Recursive)?;
        watch_with_retry(&mut watcher, dir.path(), RecursiveMode::NonRecursive)?;

        let watched = canonical_watch_set(watcher.watched_paths()?);
        assert!(watched.contains(&(root.clone(), RecursiveMode::NonRecursive)));
        assert!(!watched.contains(&(root.clone(), RecursiveMode::Recursive)));
        assert_eq!(
            watched.iter().filter(|(path, _mode)| path == &root).count(),
            1
        );

        watcher.unwatch(dir.path())?;

        let watched = canonical_watch_set(watcher.watched_paths()?);
        assert!(!watched.iter().any(|(path, _mode)| path == &root));

        Ok(())
    }

    #[test]
    fn overlapping_recursive_watch_preserves_explicit_child()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let child = dir.path().join("child");
        fs::create_dir(&child)?;

        let (tx, _rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

        watch_with_retry(&mut watcher, &child, RecursiveMode::NonRecursive)?;
        watch_with_retry(&mut watcher, dir.path(), RecursiveMode::Recursive)?;

        let watched = canonical_watch_set(watcher.watched_paths()?);
        assert!(watched.contains(&(canonical_or_path(dir.path()), RecursiveMode::Recursive)));
        assert!(watched.contains(&(canonical_or_path(&child), RecursiveMode::NonRecursive)));

        watcher.unwatch(dir.path())?;

        let watched = canonical_watch_set(watcher.watched_paths()?);
        assert!(!watched.contains(&(canonical_or_path(dir.path()), RecursiveMode::Recursive)));
        assert!(watched.contains(&(canonical_or_path(&child), RecursiveMode::NonRecursive)));

        Ok(())
    }

    #[test]
    fn overlapping_recursive_child_rewrites_descendant_event_paths()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let cwd = std::env::current_dir()?;
        let dir = tempfile::Builder::new()
            .prefix("notify-overlap-")
            .tempdir_in(&cwd)?;
        let relative_dir = dir.path().strip_prefix(&cwd)?.to_path_buf();
        let child = dir.path().join("child");
        let grandchild = child.join("grandchild");
        fs::create_dir_all(&grandchild)?;

        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

        watch_with_retry(&mut watcher, &relative_dir, RecursiveMode::Recursive)?;
        watch_with_retry(&mut watcher, &child, RecursiveMode::Recursive)?;
        watcher.unwatch(&relative_dir)?;

        let watched = watcher.watched_paths()?;
        assert!(
            watched
                .iter()
                .any(|(path, mode)| path == &child && *mode == RecursiveMode::Recursive),
            "watched_paths() did not preserve explicit child path: {watched:?}"
        );

        let file = grandchild.join("file.txt");
        let stale_file = relative_dir
            .join("child")
            .join("grandchild")
            .join("file.txt");
        fs::write(&file, b"Lorem ipsum")?;

        for event in iter_with_timeout(&rx) {
            if event.paths.iter().any(|path| path == &file) {
                assert!(
                    event.paths.iter().all(|path| path.is_absolute()),
                    "absolute child watch emitted non-absolute path: {event:?}"
                );
                return Ok(());
            }

            assert!(
                !event.paths.iter().any(|path| path == &stale_file),
                "stale parent-relative file path after parent unwatch: {event:?}"
            );
        }

        panic!("did not receive expected child event path");
    }

    #[test]
    fn update_paths_in_a_loop_with_errors() -> StdResult<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let existing_dir_1 = dir.path().join("existing_dir_1");
        let not_existent_file = dir.path().join("not_existent_file");
        let existing_dir_2 = dir.path().join("existing_dir_2");

        fs::create_dir(&existing_dir_1)?;
        fs::create_dir(&existing_dir_2)?;

        let mut paths_to_add = vec![
            PathOp::watch_recursive(existing_dir_1.clone()),
            PathOp::watch_recursive(not_existent_file.clone()),
            PathOp::watch_recursive(existing_dir_2.clone()),
        ];

        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

        while !paths_to_add.is_empty() {
            if let Err(e) = watcher.update_paths(std::mem::take(&mut paths_to_add)) {
                paths_to_add = e.remaining;
            }
        }

        fs::write(existing_dir_1.join("1"), "")?;
        fs::write(&not_existent_file, "")?;
        let waiting_path = existing_dir_2.join("1");
        fs::write(&waiting_path, "")?;
        let waiting_path_canonical = waiting_path.canonicalize().ok();

        for event in iter_with_timeout(&rx) {
            let path = event
                .paths
                .first()
                .unwrap_or_else(|| panic!("event must have a path: {event:?}"));
            assert!(
                path != &not_existent_file,
                "unexpected {not_existent_file:?} event"
            );
            if matches_path(path, &waiting_path, waiting_path_canonical.as_ref()) {
                return Ok(());
            }
        }

        panic!("Did not receive the event of {waiting_path:?}");
    }

    #[test]
    fn create_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = recommended_channel();
        watcher.watch_recursively(&tmpdir);

        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("create");

        rx.wait_unordered([expected(path).create()]);
    }

    #[test]
    fn create_dir() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = recommended_channel();
        watcher.watch_recursively(&tmpdir);

        let path = tmpdir.path().join("entry");
        std::fs::create_dir(&path).expect("create");

        rx.wait_unordered([expected(path).create()]);
    }

    #[test]
    fn modify_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = recommended_channel();

        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("create");

        watcher.watch_recursively(&tmpdir);
        std::fs::write(&path, b"123").expect("write");

        rx.wait_unordered([expected(path).modify()]);
    }

    #[test]
    fn remove_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = recommended_channel();

        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("create");

        watcher.watch_recursively(&tmpdir);
        std::fs::remove_file(&path).expect("remove");

        rx.wait_unordered([expected(path).remove()]);
    }

    #[cfg(feature = "futures")]
    #[tokio::test]
    async fn futures_unbounded_sender_as_handler() {
        use crate::recommended_watcher;
        use futures::StreamExt;

        let tmpdir = testdir();
        let (tx, mut rx) = futures::channel::mpsc::unbounded();
        let mut watcher = recommended_watcher(tx).unwrap();
        watcher
            .watch(tmpdir.path(), RecursiveMode::NonRecursive)
            .unwrap();

        std::fs::create_dir(tmpdir.path().join("1")).unwrap();

        tokio::time::timeout(Duration::from_secs(5), rx.next())
            .await
            .expect("timeout")
            .expect("No event")
            .expect("Error");
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn tokio_unbounded_sender_as_handler() {
        use crate::recommended_watcher;

        let tmpdir = testdir();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut watcher = recommended_watcher(tx).unwrap();
        watcher
            .watch(tmpdir.path(), RecursiveMode::NonRecursive)
            .unwrap();

        std::fs::create_dir(tmpdir.path().join("1")).unwrap();

        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout")
            .expect("No event")
            .expect("Error");
    }

    #[test]
    fn update_paths_error_contains_errored_path() {
        let err = super::update_paths(
            [
                PathOp::unwatch("1"),
                PathOp::unwatch("2"),
                PathOp::unwatch("3"),
            ]
            .into(),
            |op| {
                if op.as_path() == Path::new("2") {
                    Err((op, super::Error::path_not_found()))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(
            &err.into_iter().map(PathOp::into_path).collect::<Vec<_>>(),
            &[PathBuf::from("2"), PathBuf::from("3"),]
        )
    }
}
