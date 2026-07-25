//! Inotify watcher implementation for Linux, Android, and FreeBSD 14.5+.
//!
//! The inotify API provides a mechanism for monitoring filesystem events.  Inotify can be used to
//! monitor individual files, or to monitor directories.  When a directory is monitored, inotify
//! will return events for the directory itself, and for files inside the directory.

use super::event::*;
use super::{
    Config, Error, ErrorKind, EventHandler, PathOp, RecursiveMode, Result, UpdatePathsError,
    WatchFilter, WatchPathConfig, Watcher,
};
use crate::paths::{WatchPath, absolute_path, reported_path};
use crate::walk::{
    WalkFailure,
    recursive::{
        UserRoot, UserRoots, WatchMetadata, remove_failed_user_root, remove_user_roots,
        watched_paths,
    },
};
use crate::{BoundSender, Receiver, Sender, bounded, unbounded};
use inotify as inotify_sys;
use inotify_sys::{EventMask, Inotify, WatchDescriptor, WatchMask};
use notify_types::event::EventKindMask;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{Metadata, metadata, read_dir, symlink_metadata};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

const INOTIFY: mio::Token = mio::Token(0);
const MESSAGE: mio::Token = mio::Token(1);

/// Convert an EventKindMask to the corresponding inotify WatchMask.
///
/// When `is_recursive` is true, CREATE and MOVED_TO are always included
/// to enable tracking of newly created subdirectories.
fn event_kind_mask_to_watch_mask(mask: EventKindMask, is_recursive: bool) -> WatchMask {
    let mut watch_mask = WatchMask::empty();

    if is_recursive {
        watch_mask |= WatchMask::CREATE | WatchMask::MOVED_TO;
    }

    if mask.intersects(EventKindMask::CREATE) {
        watch_mask |= WatchMask::CREATE | WatchMask::MOVED_TO;
    }

    if mask.intersects(EventKindMask::REMOVE) {
        watch_mask |= WatchMask::DELETE | WatchMask::MOVED_FROM;
    }

    if mask.intersects(EventKindMask::MODIFY_DATA) {
        // Note: CLOSE_WRITE is intentionally NOT included here because it generates
        // Access(Close(Write)) events, not Modify events. Users who want CLOSE_WRITE
        // events should use ACCESS_CLOSE.
        watch_mask |= WatchMask::MODIFY;
    }

    if mask.intersects(EventKindMask::MODIFY_META) {
        watch_mask |= WatchMask::ATTRIB;
    }

    if mask.intersects(EventKindMask::MODIFY_NAME) {
        watch_mask |= WatchMask::MOVE_SELF;
    }

    if mask.intersects(EventKindMask::ACCESS_OPEN) {
        watch_mask |= WatchMask::OPEN;
    }

    if mask.intersects(EventKindMask::ACCESS_CLOSE) {
        watch_mask |= WatchMask::CLOSE_WRITE;
    }

    if mask.intersects(EventKindMask::ACCESS_CLOSE_NOWRITE) {
        watch_mask |= WatchMask::CLOSE_NOWRITE;
    }

    watch_mask
}

// The EventLoop will set up a mio::Poll and use it to wait for the following:
//
// -  messages telling it what to do
//
// -  events telling it that something has happened on one of the watched files.

struct EventLoop {
    running: bool,
    poll: mio::Poll,
    event_loop_waker: Arc<mio::Waker>,
    event_loop_tx: Sender<EventLoopMsg>,
    event_loop_rx: Receiver<EventLoopMsg>,
    inotify: Option<Inotify>,
    event_handler: Box<dyn EventHandler>,
    /// Absolute path -> inotify descriptor and watch metadata.
    watches: HashMap<PathBuf, Watch>,
    user_roots: UserRoots,
    /// inotify descriptor -> the paths in `watches` that use it, in the order they were added.
    /// Symlinks and hard links let several paths name one inode, and inotify returns the same
    /// descriptor for all of them.
    paths: HashMap<WatchDescriptor, Vec<PathBuf>>,
    /// The sources of the last rename, with the user watch that reports each of them.
    rename_events: Vec<(Option<Arc<Path>>, Event)>,
    follow_links: bool,
    event_kind_mask: EventKindMask,
}

struct Watch {
    watch_descriptor: WatchDescriptor,
    is_dir: bool,
    watch_mask: WatchMask,
    dereference: bool,
    metadata: WatchMetadata,
}

impl Watch {
    /// Whether the walks of recursive user watches stop at the path of this watch. A user watch
    /// on a link that does not dereference the link watches the link itself.
    fn is_walk_barrier(&self) -> bool {
        self.metadata.is_user_watch && !self.dereference && !self.is_dir
    }
}

/// Watcher implementation based on inotify
#[derive(Debug)]
pub struct INotifyWatcher {
    channel: Sender<EventLoopMsg>,
    waker: Arc<mio::Waker>,
}

enum EventLoopMsg {
    AddWatch(WatchPath, WatchPathConfig, Sender<Result<()>>),
    RemoveWatch(PathBuf, Sender<Result<()>>),
    UpdatePaths(
        Vec<(PathOp, Result<PathBuf>)>,
        Sender<std::result::Result<(), UpdatePathsError>>,
    ),
    GetWatchedPaths(Sender<Vec<(PathBuf, RecursiveMode)>>),
    Shutdown,
    Configure(Config, BoundSender<Result<bool>>),
}

#[inline]
fn watch_metadata(path: &Path, dereference: bool) -> std::io::Result<Metadata> {
    if dereference {
        metadata(path)
    } else {
        symlink_metadata(path)
    }
}

/// Queues a walk of a new directory for the recursive user watches that cover its parent.
///
/// A user watch can reach a new directory under several paths, and the event loop walks each
/// path. Only the walk of the path that `reported` the event reports the subdirectories that it
/// finds. Each subdirectory is then reported once for each user watch.
#[inline]
fn add_watch_by_event(
    path: &Path,
    event: &inotify_sys::Event<&OsStr>,
    reported: bool,
    watches: &HashMap<PathBuf, Watch>,
    user_roots: &UserRoots,
    add_watches: &mut Vec<(PathBuf, Vec<Arc<Path>>, bool)>,
) {
    if !event.mask.contains(EventMask::ISDIR) {
        return;
    }
    let roots = parent_recursive_roots(path, watches, user_roots);
    if !roots.is_empty() {
        add_watches.push((
            path.to_owned(),
            roots,
            reported && event.mask.contains(EventMask::CREATE),
        ));
    }
}

/// Returns the directories above `path` through the nearest recursive user watch, inclusive.
/// A nested recursive watch can follow links outside its own root independently of outer watches.
fn walked_ancestors(
    path: &Path,
    watches: &HashMap<PathBuf, Watch>,
    user_roots: &UserRoots,
) -> Vec<PathBuf> {
    let mut ancestors = Vec::new();
    for ancestor in path.ancestors().skip(1) {
        if !watches
            .get(ancestor)
            .is_some_and(|watch| watch.metadata.is_recursive)
        {
            break;
        }
        ancestors.push(ancestor.to_path_buf());
        if user_roots
            .get(ancestor)
            .is_some_and(|root| root.is_recursive)
        {
            break;
        }
    }
    ancestors
}

/// Returns the recursive user watches that cover the parent of `path`.
fn parent_recursive_roots(
    path: &Path,
    watches: &HashMap<PathBuf, Watch>,
    user_roots: &UserRoots,
) -> Vec<Arc<Path>> {
    path.parent()
        .and_then(|parent| watches.get(parent))
        .map(|parent| {
            parent
                .metadata
                .recursive_roots(user_roots)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// A path that an inotify event concerns.
struct EventTarget {
    /// The path that the event names, below the watched path or the watched path itself.
    path: PathBuf,
    /// `path` in the form of the user watch that covers it, or `None` when the event is not
    /// reported under `path`.
    event_path: Option<PathBuf>,
    /// The closest user watch that covers the watched path.
    user_watch: Option<Arc<Path>>,
    /// The mask that the watch of the watched path requested.
    watch_mask: WatchMask,
}

/// Returns the paths that an event on `descriptor` concerns, in the order of `paths`.
///
/// A descriptor that several paths share through symlinks or bind mounts concerns all of them.
/// The event is reported once for each closest user watch of the paths. A bind mount below a
/// user watch can lead back to the directory of the user watch, and only the path of the user
/// watch requests `IN_DELETE_SELF`. The event is then reported under the path of the user watch.
/// Otherwise it is reported under the last of the paths in `paths`, because a renamed directory
/// keeps its descriptor and its new path is added last. Without `every_path`, only the paths that
/// report the event are returned.
fn event_targets(
    paths: &HashMap<WatchDescriptor, Vec<PathBuf>>,
    watches: &HashMap<PathBuf, Watch>,
    descriptor: &WatchDescriptor,
    name: Option<&OsStr>,
    every_path: bool,
) -> Vec<EventTarget> {
    let watched_paths = paths.get(descriptor).map_or(&[][..], Vec::as_slice);
    let user_watches: Vec<_> = watched_paths
        .iter()
        .map(|watched_path| {
            let watch = &watches[watched_path];
            watch.metadata.closest_root().cloned()
        })
        .collect();
    let mut reporters: Vec<usize> = Vec::new();
    for (index, user_watch) in user_watches.iter().enumerate() {
        match reporters
            .iter_mut()
            .find(|reporter| user_watches[**reporter] == *user_watch)
        {
            None => reporters.push(index),
            Some(reporter) => {
                if user_watch.as_deref() != Some(watched_paths[*reporter].as_path()) {
                    *reporter = index;
                }
            }
        }
    }
    watched_paths
        .iter()
        .zip(user_watches)
        .enumerate()
        .filter_map(|(index, (watched_path, user_watch))| {
            let reported = reporters.contains(&index);
            if !reported && !every_path {
                return None;
            }
            let watch = &watches[watched_path];
            let path = match name {
                Some(name) => watched_path.join(name),
                None => watched_path.clone(),
            };
            let event_path =
                reported.then(|| reported_path(watched_path, &watch.metadata.reported_path, &path));
            Some(EventTarget {
                path,
                event_path,
                user_watch,
                watch_mask: watch.watch_mask,
            })
        })
        .collect()
}

/// Returns the entries in `watches` for each of the queued paths in `remove_watches`, when more
/// than one path is queued.
///
/// A deleted directory that many symlinks reach queues each of its paths, and deleting a tree
/// queues each of its directories. One scan of `watches` then finds the entries below every
/// queued path, instead of one scan for each queued path. An entry is only added to the closest
/// queued path at or above it. The removals of a batch run from the deepest path up, and each
/// removes every entry at and below its path, so the removal of that path removes the entry.
fn entries_below(
    watches: &HashMap<PathBuf, Watch>,
    remove_watches: &BTreeMap<PathBuf, WatchRemoval>,
) -> HashMap<PathBuf, Vec<PathBuf>> {
    let mut entries = HashMap::new();
    if remove_watches.len() < 2 {
        return entries;
    }
    let fewest_components = remove_watches
        .keys()
        .map(|path| path.components().count())
        .min()
        .unwrap_or(0);
    for entry in watches.keys() {
        // Each ancestor has one component less, so the ancestors with fewer components than
        // every queued path are not looked up.
        let ancestors = (entry.components().count() + 1).saturating_sub(fewest_components);
        if let Some(closest) = entry
            .ancestors()
            .take(ancestors)
            .find(|ancestor| remove_watches.contains_key(*ancestor))
        {
            entries
                .entry(closest.to_path_buf())
                .or_insert_with(Vec::new)
                .push(entry.clone());
        }
    }
    entries
}

/// `Listings` maps each directory that the walks of a batch read to the names of the entries
/// that the walks visit in it. A directory is identified by its device, its inode and its change
/// time. A directory that is deleted during a batch can pass its inode number to a new
/// directory, and the two directories have different change times.
type Listings = HashMap<(u64, u64, i64, i64), Vec<OsString>>;

/// Queue `path` for removal, if it is watched and `descriptor` still matches its watch.
#[inline]
fn queue_watch_removal(
    path: &Path,
    descriptor: Option<&WatchDescriptor>,
    watches: &HashMap<PathBuf, Watch>,
    remove_watches: &mut BTreeMap<PathBuf, WatchRemoval>,
    removal: WatchRemoval,
) {
    let watched = watches
        .get(path)
        .is_some_and(|watch| descriptor.is_none_or(|wd| &watch.watch_descriptor == wd));
    if watched {
        let pending = remove_watches.entry(path.to_owned()).or_insert(removal);
        *pending = (*pending).max(removal);
    }
}

/// The entries that removals took out of `watches`, and the descriptors to remove with them.
#[derive(Default)]
struct RemovedWatches {
    paths: Vec<(WatchDescriptor, PathBuf)>,
    descriptors: Vec<WatchDescriptor>,
}

/// Variant order is load-bearing: coalescing keeps the greater of two pending removals.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum WatchRemoval {
    /// The watch may still be installed, so remove it from inotify as well as local state.
    WithOsCall,
    /// The kernel removed the event's root descriptor, but descendant descriptors may still be
    /// installed if their filesystem objects survived, for example after being moved elsewhere.
    DescriptorAlreadyRemoved,
}

#[inline]
fn unmount_event(path: PathBuf) -> Event {
    Event::new(EventKind::Remove(RemoveKind::Other))
        .add_path(path)
        .set_info("unmount")
}

impl EventLoop {
    pub fn new(
        inotify: Inotify,
        event_handler: Box<dyn EventHandler>,
        config: &Config,
    ) -> Result<Self> {
        let (event_loop_tx, event_loop_rx) = unbounded::<EventLoopMsg>();
        let poll = mio::Poll::new()?;

        let event_loop_waker = Arc::new(mio::Waker::new(poll.registry(), MESSAGE)?);

        let inotify_fd = inotify.as_raw_fd();
        let mut evented_inotify = mio::unix::SourceFd(&inotify_fd);
        poll.registry()
            .register(&mut evented_inotify, INOTIFY, mio::Interest::READABLE)?;

        let event_loop = EventLoop {
            running: true,
            poll,
            event_loop_waker,
            event_loop_tx,
            event_loop_rx,
            inotify: Some(inotify),
            event_handler,
            watches: HashMap::new(),
            user_roots: UserRoots::new(),
            paths: HashMap::new(),
            rename_events: Vec::new(),
            follow_links: config.follow_symlinks(),
            event_kind_mask: config.event_kinds(),
        };
        Ok(event_loop)
    }

    // Run the event loop.
    pub fn run(self) {
        let _ = thread::Builder::new()
            .name("notify-rs inotify loop".to_string())
            .spawn(|| self.event_loop_thread());
    }

    fn event_loop_thread(mut self) {
        let mut events = mio::Events::with_capacity(16);
        loop {
            // Wait for something to happen.
            match self.poll.poll(&mut events, None) {
                Err(ref e) if matches!(e.kind(), std::io::ErrorKind::Interrupted) => {
                    // System call was interrupted, we will retry
                    // TODO: Not covered by tests (to reproduce likely need to setup signal handlers)
                }
                Err(e) => panic!("poll failed: {e}"),
                Ok(()) => {}
            }

            // Process whatever happened.
            for event in &events {
                self.handle_event(event);
            }

            // Stop, if we're done.
            if !self.running {
                break;
            }
        }
    }

    // Handle a single event.
    fn handle_event(&mut self, event: &mio::event::Event) {
        match event.token() {
            MESSAGE => {
                // The channel is readable - handle messages.
                self.handle_messages()
            }
            INOTIFY => {
                // inotify has something to tell us.
                self.handle_inotify()
            }
            _ => unreachable!(),
        }
    }

    fn handle_messages(&mut self) {
        while let Ok(msg) = self.event_loop_rx.try_recv() {
            match msg {
                EventLoopMsg::AddWatch(path, config, tx) => {
                    let _ = tx.send(self.add_watch(path, config));
                }
                EventLoopMsg::RemoveWatch(path, tx) => {
                    let _ = tx.send(self.unwatch(path));
                }
                EventLoopMsg::UpdatePaths(ops, tx) => {
                    // Buffer events so a bounded handler cannot block the batch reply.
                    let (events_tx, events_rx) = unbounded();
                    let event_handler =
                        std::mem::replace(&mut self.event_handler, Box::new(events_tx));
                    let mut ops = ops.into_iter();
                    let mut result = Ok(());
                    let mut applied = 0;
                    while let Some((op, path)) = ops.next() {
                        let operation = path.and_then(|absolute| match &op {
                            PathOp::Watch(requested, config) => self.add_watch(
                                WatchPath::from_parts(absolute, requested.clone()),
                                config.clone(),
                            ),
                            PathOp::Unwatch(_) => self.remove_watch(absolute),
                        });
                        if let Err(source) = operation {
                            result = Err(UpdatePathsError {
                                source,
                                origin: Some(op),
                                remaining: ops.map(|(op, _)| op).collect(),
                            });
                            break;
                        }
                        applied += 1;
                        // Drain events during large batches instead of overflowing the kernel queue.
                        if applied % 1024 == 0 {
                            self.handle_inotify();
                        }
                    }
                    self.handle_inotify();
                    self.event_handler = event_handler;
                    let _ = tx.send(result);
                    for event in events_rx.try_iter() {
                        self.event_handler.handle_event(event);
                    }
                }
                EventLoopMsg::GetWatchedPaths(tx) => {
                    let _ = tx.send(watched_paths(&self.user_roots));
                }
                EventLoopMsg::Shutdown => {
                    let _ = self.remove_all_watches();
                    if let Some(inotify) = self.inotify.take() {
                        let _ = inotify.close();
                    }
                    self.running = false;
                    break;
                }
                EventLoopMsg::Configure(config, tx) => {
                    self.configure_raw_mode(config, tx);
                }
            }
        }
    }

    fn configure_raw_mode(&mut self, _config: Config, tx: BoundSender<Result<bool>>) {
        tx.send(Ok(false))
            .expect("configuration channel disconnected");
    }

    fn handle_inotify(&mut self) {
        let mut add_watches = Vec::new();
        let mut remove_watches = BTreeMap::new();

        if let Some(ref mut inotify) = self.inotify {
            let mut buffer = [0; 1024];
            // Read all buffers available.
            loop {
                match inotify.read_events(&mut buffer) {
                    Ok(events) => {
                        let mut num_events = 0;
                        for event in events {
                            log::trace!("inotify event: {event:?}");

                            num_events += 1;
                            if event.mask.contains(EventMask::Q_OVERFLOW) {
                                let ev = Ok(Event::new(EventKind::Other).set_flag(Flag::Rescan));
                                self.event_handler.handle_event(ev);
                            }

                            if event.mask.contains(EventMask::IGNORED) {
                                // The kernel sends IGNORED whenever it removes a descriptor,
                                // regardless of the configured mask. Every path that uses the
                                // descriptor lost its watch.
                                let removed =
                                    self.paths.get(&event.wd).cloned().unwrap_or_default();
                                for path in removed {
                                    queue_watch_removal(
                                        &path,
                                        None,
                                        &self.watches,
                                        &mut remove_watches,
                                        WatchRemoval::DescriptorAlreadyRemoved,
                                    );
                                }
                                continue;
                            }

                            // A new directory, a removal or a move can change the watches below
                            // each path of a shared descriptor. Other events only concern the
                            // paths that report them.
                            let every_path =
                                event.mask.intersects(
                                    EventMask::MOVED_FROM
                                        | EventMask::DELETE
                                        | EventMask::DELETE_SELF
                                        | EventMask::MOVED_TO
                                        | EventMask::UNMOUNT,
                                ) || event.mask.contains(EventMask::ISDIR | EventMask::CREATE);
                            let targets = event_targets(
                                &self.paths,
                                &self.watches,
                                &event.wd,
                                event.name,
                                every_path,
                            );
                            if targets.is_empty() {
                                log::debug!("inotify event with unknown descriptor: {event:?}");
                                continue;
                            }
                            let mut evs = Vec::new();
                            if event.mask.contains(EventMask::MOVED_FROM) {
                                self.rename_events.clear();
                            }
                            // A rename reports its source and its destination once for each user
                            // watch. A source and a destination that the same user watch reports
                            // form a pair. The other sources and destinations pair up in order.
                            let mut rename_sources = if event.mask.contains(EventMask::MOVED_TO)
                                && self.rename_events.first().and_then(|(_, e)| e.tracker())
                                    == Some(event.cookie as usize)
                            {
                                std::mem::take(&mut self.rename_events)
                            } else {
                                Vec::new()
                            };
                            let destination_watches: Vec<_> = targets
                                .iter()
                                .filter(|target| target.event_path.is_some())
                                .map(|target| &target.user_watch)
                                .collect();

                            for target in &targets {
                                let EventTarget {
                                    path,
                                    event_path,
                                    user_watch,
                                    watch_mask,
                                } = target;
                                // The configured event kinds set most of the mask of each path.
                                // Only a recursive path requests `IN_MOVED_TO` when the event kinds
                                // lack `CREATE`, and only the path of a user watch requests
                                // `IN_DELETE_SELF`. The kernel sends an event when any path of the
                                // descriptor requested it, so each path checks its own mask before
                                // it reports `IN_MOVED_TO` or `IN_DELETE_SELF`. The masks can also
                                // differ in `IN_CREATE` and `IN_MOVE_SELF`, but the event kinds
                                // filter out `Create` and `Modify(Name)` events in that case.
                                let requested = EventMask::from_bits_truncate(watch_mask.bits());
                                if event.mask.contains(EventMask::MOVED_FROM) {
                                    queue_watch_removal(
                                        path,
                                        None,
                                        &self.watches,
                                        &mut remove_watches,
                                        WatchRemoval::WithOsCall,
                                    );

                                    if let Some(event_path) = event_path {
                                        let event = Event::new(EventKind::Modify(
                                            ModifyKind::Name(RenameMode::From),
                                        ))
                                        .add_path(event_path.clone())
                                        .set_tracker(event.cookie as usize);

                                        self.rename_events
                                            .push((user_watch.clone(), event.clone()));

                                        evs.push(event);
                                    }
                                } else if event.mask.contains(EventMask::MOVED_TO) {
                                    // A rename replaces the entry at its destination. When that
                                    // entry is a symlink to a directory, its path would otherwise
                                    // keep the watch of the old target.
                                    queue_watch_removal(
                                        path,
                                        None,
                                        &self.watches,
                                        &mut remove_watches,
                                        WatchRemoval::WithOsCall,
                                    );
                                    if let Some(event_path) = event_path
                                        && requested.contains(EventMask::MOVED_TO)
                                    {
                                        evs.push(
                                            Event::new(EventKind::Modify(ModifyKind::Name(
                                                RenameMode::To,
                                            )))
                                            .set_tracker(event.cookie as usize)
                                            .add_path(event_path.clone()),
                                        );

                                        let source = rename_sources
                                            .iter()
                                            .position(|(watch, _)| watch == user_watch)
                                            .or_else(|| {
                                                rename_sources.iter().position(|(watch, _)| {
                                                    !destination_watches.contains(&watch)
                                                })
                                            });
                                        if let Some(source) = source {
                                            let (_, rename_event) = rename_sources.remove(source);
                                            evs.push(
                                                Event::new(EventKind::Modify(ModifyKind::Name(
                                                    RenameMode::Both,
                                                )))
                                                .set_tracker(event.cookie as usize)
                                                .add_some_path(rename_event.paths.first().cloned())
                                                .add_path(event_path.clone()),
                                            );
                                        }
                                    }
                                    add_watch_by_event(
                                        path,
                                        &event,
                                        event_path.is_some(),
                                        &self.watches,
                                        &self.user_roots,
                                        &mut add_watches,
                                    );
                                }
                                if event.mask.contains(EventMask::MOVE_SELF)
                                    && let Some(event_path) = event_path
                                {
                                    evs.push(
                                        Event::new(EventKind::Modify(ModifyKind::Name(
                                            RenameMode::From,
                                        )))
                                        .add_path(event_path.clone()),
                                    );
                                    // TODO stat the path and get to new path
                                    // - emit To and Both events
                                    // - change prefix for further events
                                }
                                if event.mask.contains(EventMask::CREATE) {
                                    if let Some(event_path) = event_path {
                                        evs.push(
                                            Event::new(EventKind::Create(
                                                if event.mask.contains(EventMask::ISDIR) {
                                                    CreateKind::Folder
                                                } else {
                                                    CreateKind::File
                                                },
                                            ))
                                            .add_path(event_path.clone()),
                                        );
                                    }
                                    add_watch_by_event(
                                        path,
                                        &event,
                                        event_path.is_some(),
                                        &self.watches,
                                        &self.user_roots,
                                        &mut add_watches,
                                    );
                                }
                                if event.mask.contains(EventMask::DELETE) {
                                    if let Some(event_path) = event_path {
                                        evs.push(
                                            Event::new(EventKind::Remove(
                                                if event.mask.contains(EventMask::ISDIR) {
                                                    RemoveKind::Folder
                                                } else {
                                                    RemoveKind::File
                                                },
                                            ))
                                            .add_path(event_path.clone()),
                                        );
                                    }
                                    queue_watch_removal(
                                        path,
                                        None,
                                        &self.watches,
                                        &mut remove_watches,
                                        WatchRemoval::WithOsCall,
                                    );
                                }
                                if event.mask.contains(EventMask::DELETE_SELF) {
                                    if let Some(event_path) = event_path
                                        && requested.contains(EventMask::DELETE_SELF)
                                    {
                                        let remove_kind = match self.watches.get(path) {
                                            Some(watch) if watch.is_dir => RemoveKind::Folder,
                                            Some(_) => RemoveKind::File,
                                            None => RemoveKind::Other,
                                        };
                                        evs.push(
                                            Event::new(EventKind::Remove(remove_kind))
                                                .add_path(event_path.clone()),
                                        );
                                    }
                                    // Deleting a watched inode removes its watch in the kernel
                                    // and queues IGNORED, so calling inotify_rm_watch would
                                    // return EINVAL.
                                    queue_watch_removal(
                                        path,
                                        Some(&event.wd),
                                        &self.watches,
                                        &mut remove_watches,
                                        WatchRemoval::DescriptorAlreadyRemoved,
                                    );
                                }
                                if event.mask.contains(EventMask::UNMOUNT) {
                                    if let Some(event_path) = event_path {
                                        evs.push(unmount_event(event_path.clone()));
                                    }
                                    // The kernel has already removed this watch descriptor and
                                    // will emit IGNORED; clean up internal state without
                                    // inotify_rm_watch.
                                    // ref. https://www.man7.org/linux/man-pages/man7/inotify.7.html
                                    queue_watch_removal(
                                        path,
                                        Some(&event.wd),
                                        &self.watches,
                                        &mut remove_watches,
                                        WatchRemoval::DescriptorAlreadyRemoved,
                                    );
                                }
                                let Some(event_path) = event_path else {
                                    continue;
                                };
                                if event.mask.contains(EventMask::MODIFY) {
                                    evs.push(
                                        Event::new(EventKind::Modify(ModifyKind::Data(
                                            DataChange::Any,
                                        )))
                                        .add_path(event_path.clone()),
                                    );
                                }
                                if event.mask.contains(EventMask::CLOSE_WRITE) {
                                    evs.push(
                                        Event::new(EventKind::Access(AccessKind::Close(
                                            AccessMode::Write,
                                        )))
                                        .add_path(event_path.clone()),
                                    );
                                }
                                if event.mask.contains(EventMask::CLOSE_NOWRITE) {
                                    evs.push(
                                        Event::new(EventKind::Access(AccessKind::Close(
                                            AccessMode::Read,
                                        )))
                                        .add_path(event_path.clone()),
                                    );
                                }
                                if event.mask.contains(EventMask::ATTRIB) {
                                    evs.push(
                                        Event::new(EventKind::Modify(ModifyKind::Metadata(
                                            MetadataKind::Any,
                                        )))
                                        .add_path(event_path.clone()),
                                    );
                                }
                                if event.mask.contains(EventMask::OPEN) {
                                    evs.push(
                                        Event::new(EventKind::Access(AccessKind::Open(
                                            AccessMode::Any,
                                        )))
                                        .add_path(event_path.clone()),
                                    );
                                }
                            }

                            // Filter events based on EventKindMask before delivery
                            for ev in evs {
                                if self.event_kind_mask.matches(&ev.kind) {
                                    self.event_handler.handle_event(Ok(ev));
                                }
                            }
                        }

                        // All events read. Break out.
                        if num_events == 0 {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No events read. Break out.
                        break;
                    }
                    Err(e) => {
                        self.event_handler.handle_event(Err(Error::io(e)));
                    }
                }
            }
        }

        // An ancestor sorts before its descendants, so reverse order removes descendants first:
        // recursive ancestor cleanup then neither repeats syscalls for kernel-removed watches nor
        // drops the mapping for a live, moved-out descendant.
        let mut entries = entries_below(&self.watches, &remove_watches);
        let mut removed = RemovedWatches::default();
        for (path, removal) in remove_watches.into_iter().rev() {
            let candidates = entries.remove(&path);
            let root_os_call = removal == WatchRemoval::WithOsCall;
            if let Err(err) =
                self.remove_entries(path, true, root_os_call, candidates, &mut removed)
            {
                log::warn!("Unable to remove the path from the watches: {err:?}");
            }
        }
        // The removals of a batch release their paths and descriptors together, so the paths of
        // a descriptor that thousands of symlinks share are scanned once.
        self.release(removed);

        // A new directory below a directory that thousands of symlinks reach is walked once for
        // each path of that directory. The walks do not add user watches, so the barriers stay
        // the same.
        let barriers = if add_watches.is_empty() {
            HashSet::new()
        } else {
            self.recursive_walk_barriers()
        };
        let mut listings = Listings::new();
        for (path, roots, report_created) in add_watches {
            // The walk starts below the recursive watches that cover `path`. A link back to a
            // directory above `path` is a loop, as it is in a walk of a whole watch.
            let above = walked_ancestors(&path, &self.watches, &self.user_roots);
            if let Err(err) = self.add_discovered_dir(
                path,
                &roots,
                &barriers,
                above,
                &mut listings,
                report_created,
            ) {
                match WalkFailure::of(&err.kind) {
                    WalkFailure::Skip => {}
                    WalkFailure::Report => self.event_handler.handle_event(Err(err)),
                    WalkFailure::Abort => {
                        self.event_handler.handle_event(Err(err));
                        break;
                    }
                }
            }
        }
    }

    fn add_watch(&mut self, path: WatchPath, config: WatchPathConfig) -> Result<()> {
        let is_recursive = config.recursive_mode().is_recursive();
        // a recursive watch has to resolve the path before it can walk it
        let dereference = config.dereference_symlinks() || is_recursive;
        // add_single_watch validates new paths after registration; no preliminary stat is needed.
        if !is_recursive && !self.watches.contains_key(&path.absolute) {
            return self.add_user_watch(path, /*is_recursive*/ false, dereference);
        }
        let path_is_dir = watch_metadata(&path.absolute, dereference)
            .map_err(Error::io_watch)?
            .is_dir();
        let requested_is_recursive = is_recursive && path_is_dir;
        let was_walk_barrier = self
            .watches
            .get(&path.absolute)
            .is_some_and(Watch::is_walk_barrier);

        if let Some(root) = self.user_roots.get(path.absolute.as_path()) {
            if root.rewatch_is_noop(
                &path.requested,
                requested_is_recursive,
                &WatchFilter::accept_all(),
            ) && self
                .watches
                .get(&path.absolute)
                .is_some_and(|watch| watch.dereference == dereference)
            {
                return Ok(());
            }
            // The entries that other user watches cover stay.
            self.remove_watch(path.absolute.clone())?;
        }
        if self.watches.get(&path.absolute).is_some_and(|watch| {
            !dereference && !path_is_dir && watch.is_dir && watch.metadata.is_recursive
        }) {
            // A recursive walk already followed this link. Remove its inherited subtree before
            // replacing the root with an explicit watch on the link itself.
            self.remove_watch(path.absolute.clone())?;
        }

        let root = path.absolute.clone();
        let result = self.add_user_watch(path, requested_is_recursive, dereference);
        if was_walk_barrier
            && result.is_ok()
            && !self.watches.get(&root).is_some_and(Watch::is_walk_barrier)
        {
            self.walk_link_again(root);
        }
        result
    }

    fn add_user_watch(
        &mut self,
        path: WatchPath,
        is_recursive: bool,
        dereference: bool,
    ) -> Result<()> {
        let root: Arc<Path> = Arc::from(path.absolute.as_path());
        self.user_roots.insert(
            root.clone(),
            UserRoot {
                requested: path.requested.clone(),
                is_recursive,
                watch_filter: WatchFilter::accept_all(),
            },
        );
        let result = if is_recursive {
            let barriers = self.recursive_walk_barriers();
            let entries = walk_dirs(
                path.absolute.clone(),
                path,
                self.follow_links,
                &barriers,
                Vec::new(),
                None,
            );
            self.add_watches_for_paths(
                std::slice::from_ref(&root),
                entries,
                dereference,
                true,
                /*report_created*/ false,
            )
        } else {
            self.add_single_watch(path, std::slice::from_ref(&root), dereference, true)
        };
        remove_failed_user_root(
            &mut self.user_roots,
            &root,
            &result,
            self.watches.get(&*root).map(|watch| &watch.metadata),
        );
        result
    }

    /// Removes the user watch on `path`.
    fn unwatch(&mut self, path: PathBuf) -> Result<()> {
        let was_walk_barrier = self.watches.get(&path).is_some_and(Watch::is_walk_barrier);
        self.remove_watch(path.clone())?;
        if was_walk_barrier {
            self.walk_link_again(path);
        }
        Ok(())
    }

    /// Walks the link at `path` for the recursive user watches that cover its parent.
    ///
    /// The walks of the recursive user watches above a link stop at the link when a user watch
    /// on the link does not dereference it. Adding such a user watch removes the entries that
    /// the walks added through the link. After the user watch on the link is removed or
    /// dereferences the link, each recursive user watch walks the link as a new walk of its
    /// tree would.
    fn walk_link_again(&mut self, path: PathBuf) {
        if !self.follow_links {
            return;
        }
        // `lstat` follows a link that is spelled with a trailing separator. The walk has to see the
        // link itself, because it checks for a loop only at a link.
        let path = crate::paths::without_trailing_separator(&path);
        let barriers = self.recursive_walk_barriers();
        let mut listings = Listings::new();
        for root in parent_recursive_roots(&path, &self.watches, &self.user_roots) {
            // The walk of `root` reports a link to a directory that it passed through as a loop.
            let above = path
                .ancestors()
                .skip(1)
                .take_while(|ancestor| ancestor.starts_with(&root))
                .map(Path::to_path_buf)
                .collect();
            let roots = std::slice::from_ref(&root);
            if let Err(err) = self.add_discovered_dir(
                path.clone(),
                roots,
                &barriers,
                above,
                &mut listings,
                /*report_created*/ false,
            ) {
                self.event_handler.handle_event(Err(err));
            }
        }
    }

    /// Walks a directory that appeared below a directory that the recursive user watches
    /// `roots` cover. One walk adds every root, so each directory is watched once. `above`
    /// contains the directories above `path` that the walks of `roots` passed through. The walk
    /// reports a link to a directory in `above` as a loop.
    fn add_discovered_dir(
        &mut self,
        path: PathBuf,
        roots: &[Arc<Path>],
        barriers: &HashSet<PathBuf>,
        above: Vec<PathBuf>,
        listings: &mut Listings,
        report_created: bool,
    ) -> Result<()> {
        let roots: Vec<_> = roots
            .iter()
            .filter(|root| self.user_roots.contains_key(*root))
            .cloned()
            .collect();
        let Some(first) = roots.first() else {
            return Ok(());
        };
        // An error names the directory in the form of the first root.
        let root_path = WatchPath::from_parts(
            first.to_path_buf(),
            self.user_roots[first].requested.clone(),
        );
        let entries = walk_dirs(
            path,
            root_path,
            self.follow_links,
            barriers,
            above,
            Some(listings),
        );
        self.add_watches_for_paths(&roots, entries, true, false, report_created)
    }

    fn recursive_walk_barriers(&self) -> HashSet<PathBuf> {
        self.watches
            .iter()
            .filter(|(_, watch)| watch.is_walk_barrier())
            .map(|(path, _)| path.clone())
            .collect()
    }

    fn add_watches_for_paths<I>(
        &mut self,
        roots: &[Arc<Path>],
        paths: I,
        dereference: bool,
        mut watch_self: bool,
        report_created: bool,
    ) -> Result<()>
    where
        I: IntoIterator<Item = Result<WatchPath>>,
    {
        let mut last_failed = None;

        // For a CREATE-triggered walk, the first entry is the root whose event was already delivered.
        // Only directories are recovered: files created before their parent's watch remain unreported.
        // A child created after its parent was watched can also have a queued native CREATE, so
        // synthesized events may duplicate native ones.
        for (index, path) in paths.into_iter().enumerate() {
            let created_path = path
                .as_ref()
                .ok()
                .filter(|path| {
                    report_created && index > 0 && !self.watches.contains_key(&path.absolute)
                })
                .map(|path| path.absolute.clone());
            // entries below the root were reached by following links, so they observe what they
            // resolved to
            let entry_dereference = if watch_self { dereference } else { true };
            // A path the walk could not reach fails the same way one it could not watch does.
            match path
                .and_then(|path| self.add_single_watch(path, roots, entry_dereference, watch_self))
            {
                Ok(()) => {
                    last_failed = None;
                    if let Some(watch) = created_path.and_then(|path| self.watches.get(&path)) {
                        let event = Event::new(EventKind::Create(CreateKind::Folder))
                            .add_path(watch.metadata.reported_path.clone());
                        if self.event_kind_mask.matches(&event.kind) {
                            self.event_handler.handle_event(Ok(event));
                        }
                    }
                }
                // The requested path itself failing is the caller's problem.
                Err(err) if watch_self => return Err(err),
                // A directory that cannot be read cannot be watched either, and the walk reports
                // it right after the directory itself. Report the pair once. Errors that name no
                // path are never the same failure twice, so they stay out of this.
                Err(err) if last_failed.is_some() && last_failed.as_ref() == err.paths.first() => {}
                Err(err) => {
                    last_failed = err.paths.first().cloned();
                    match WalkFailure::of(&err.kind) {
                        WalkFailure::Skip => {}
                        WalkFailure::Report => self.event_handler.handle_event(Err(err)),
                        WalkFailure::Abort => return Err(err),
                    }
                }
            }
            watch_self = false;
        }

        Ok(())
    }

    fn watch_mask(&self, metadata: &WatchMetadata) -> WatchMask {
        // Build watch mask from configured event kinds for kernel-level filtering
        let mut watchmask =
            event_kind_mask_to_watch_mask(self.event_kind_mask, metadata.is_recursive);
        if metadata.is_user_watch {
            watchmask.insert(WatchMask::DELETE_SELF);
            watchmask.insert(WatchMask::MOVE_SELF);
        }
        watchmask
    }

    /// Adds `roots` to the user watches that cover `path`, and watches `path`.
    fn add_single_watch(
        &mut self,
        path: WatchPath,
        roots: &[Arc<Path>],
        requested_dereference: bool,
        watch_self: bool,
    ) -> Result<()> {
        let existing_watch = self.watches.get(&path.absolute);
        // an explicit watch decides for its own path, a walk must not overrule it #255
        let dereference = if watch_self {
            requested_dereference
        } else {
            existing_watch
                .filter(|watch| watch.metadata.is_user_watch)
                .map_or(requested_dereference, |watch| watch.dereference)
        };
        let previous_descriptor = existing_watch.map(|watch| watch.watch_descriptor.clone());
        let mut metadata =
            existing_watch.map_or_else(WatchMetadata::default, |watch| watch.metadata.clone());
        for root in roots {
            metadata.add_root(&path.absolute, root, &self.user_roots);
        }
        let watchmask = self.watch_mask(&metadata);

        // Another path can watch the same inode, for example a walk that followed a symlink,
        // and inotify then returns the descriptor of that watch. Without `IN_MASK_ADD`, the new
        // mask replaces the mask of the other path. The other path then stops receiving the
        // events that only it requested.
        let mut add_mask = watchmask | WatchMask::MASK_ADD;
        if !dereference {
            add_mask.insert(WatchMask::DONT_FOLLOW);
        }

        if let Some(ref mut inotify) = self.inotify {
            log::trace!("adding inotify watch: {}", path.absolute.display());

            let (watch_result, directory_verified) =
                if !metadata.is_recursive && existing_watch.is_none() {
                    // ONLYDIR classifies the watched inode without a second pathname lookup.
                    match inotify
                        .watches()
                        .add(&path.absolute, add_mask | WatchMask::ONLYDIR)
                    {
                        Ok(watch) => (Ok(watch), true),
                        Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => {
                            (inotify.watches().add(&path.absolute, add_mask), false)
                        }
                        Err(error) => (Err(error), false),
                    }
                } else {
                    (inotify.watches().add(&path.absolute, add_mask), false)
                };

            match watch_result {
                Err(e) => {
                    Err(if e.raw_os_error() == Some(libc::ENOSPC) {
                        // do not report inotify limits as "no more space" on linux #266
                        Error::new(ErrorKind::MaxFilesWatch)
                    } else if e.kind() == std::io::ErrorKind::NotFound {
                        Error::new(ErrorKind::PathNotFound)
                    } else {
                        Error::io(e)
                    }
                    .add_path(path.requested))
                }
                Ok(w) => {
                    let is_dir = if directory_verified {
                        true
                    } else {
                        match watch_metadata(&path.absolute, dereference) {
                            Ok(metadata) => metadata.is_dir(),
                            Err(e) => {
                                // Avoid leaking an inotify watch if we can't stat after adding it.
                                // This can happen due to racy deletions. A watch that another path
                                // uses stays for that path.
                                if !self.paths.contains_key(&w) {
                                    let _ = inotify.watches().remove(w.clone());
                                }
                                return Err(Error::io_watch(e).add_path(path.requested));
                            }
                        }
                    };

                    self.insert_watch(
                        path.absolute,
                        Watch {
                            watch_descriptor: w.clone(),
                            is_dir,
                            watch_mask: watchmask,
                            dereference,
                            metadata,
                        },
                    );
                    // re-resolving a path can land on a different inode, so release the old
                    // descriptor or it keeps reporting under this path. A walk that followed the
                    // link can still use the old descriptor #255.
                    if let Some(previous) = previous_descriptor.filter(|previous| *previous != w) {
                        self.release_descriptors([previous]);
                    }
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }

    /// Removes the user watch on `path`.
    ///
    /// An `unwatch` of a user watch removes that watch from the entries it covers, and the
    /// entries that another user watch covers stay. An `unwatch` of a directory that only a walk
    /// added stops the user watches above it from covering it.
    fn remove_watch(&mut self, path: PathBuf) -> Result<()> {
        let mut removed = RemovedWatches::default();
        let result = self.remove_entries(path, false, true, None, &mut removed);
        self.release(removed);
        result
    }

    /// Like [`Self::remove_watch`] for a directory that was deleted or moved away, after the
    /// kernel has already removed the descriptor of `path`.
    #[cfg(test)]
    fn remove_watch_without_root_os_call(&mut self, path: PathBuf) -> Result<()> {
        let mut removed = RemovedWatches::default();
        let result = self.remove_entries(path, true, false, None, &mut removed);
        self.release(removed);
        result
    }

    /// Takes the entries at and below `path` out of `watches`, and adds them to `removed`.
    ///
    /// With `remove_recursive`, the directory was deleted or moved away, so every entry below it
    /// is removed, including the user watches. Without `root_os_call`, the kernel has already
    /// removed the descriptor of `path`. The descriptors below `path` are still removed one by
    /// one, because their files can still exist, for example after they were moved elsewhere.
    ///
    /// `candidates` contains the entries at and below `path` that no other removal of the same
    /// batch takes out. Without it, the entries are looked up.
    fn remove_entries(
        &mut self,
        path: PathBuf,
        remove_recursive: bool,
        root_os_call: bool,
        candidates: Option<Vec<PathBuf>>,
        removed: &mut RemovedWatches,
    ) -> Result<()> {
        if !self.watches.contains_key(&path) {
            return Err(Error::watch_not_found().add_path(path));
        }
        log::trace!("removing inotify watch for {path:?}, remove_recursive: {remove_recursive:?}");

        let drops = remove_user_roots(&mut self.user_roots, &path, remove_recursive);

        let candidates = candidates.unwrap_or_else(|| {
            self.watches
                .keys()
                .filter(|candidate| candidate.starts_with(&path))
                .cloned()
                .collect()
        });
        for candidate in candidates {
            let mut watch = self
                .watches
                .remove(&candidate)
                .expect("candidate is watched");
            let before = watch.metadata.roots.len();
            watch.metadata.roots.retain(|root| !drops(root));
            if watch.metadata.roots.is_empty() {
                if root_os_call || candidate != path {
                    removed.descriptors.push(watch.watch_descriptor.clone());
                }
                removed.paths.push((watch.watch_descriptor, candidate));
                continue;
            }
            if watch.metadata.roots.len() != before {
                watch.metadata.refresh(&candidate, &self.user_roots);
                watch.watch_mask = self.watch_mask(&watch.metadata);
            }
            self.watches.insert(candidate, watch);
        }
        Ok(())
    }

    /// Removes the paths in `removed` from the paths of their descriptors, and removes the
    /// descriptors that no path uses any more.
    fn release(&mut self, removed: RemovedWatches) {
        self.forget_paths(removed.paths);
        self.release_descriptors(removed.descriptors);
    }

    /// Removes the descriptors that no path in `watches` uses any more.
    fn release_descriptors<I>(&mut self, descriptors: I)
    where
        I: IntoIterator<Item = WatchDescriptor>,
    {
        let descriptors: HashSet<_> = descriptors.into_iter().collect();
        for descriptor in descriptors {
            if self.paths.contains_key(&descriptor) {
                continue;
            }

            if let Some(ref mut inotify) = self.inotify {
                Self::remove_single_descriptor(&mut inotify.watches(), descriptor);
            }
        }
    }

    /// Inserts the watch of `path`, making it the last path of its descriptor even on re-add.
    fn insert_watch(&mut self, path: PathBuf, watch: Watch) {
        let descriptor = watch.watch_descriptor.clone();
        if let Some(previous) = self.watches.insert(path.clone(), watch) {
            self.forget_paths([(previous.watch_descriptor, path.clone())]);
        }
        // Most descriptors have one path, and `Vec::push` reserves room for four.
        self.paths
            .entry(descriptor)
            .or_insert_with(|| Vec::with_capacity(1))
            .push(path);
    }

    fn forget_paths<I>(&mut self, forgotten: I)
    where
        I: IntoIterator<Item = (WatchDescriptor, PathBuf)>,
    {
        // Thousands of symlinks can lead to one directory. Removing its paths one at a time
        // would scan the paths of the descriptor once for each removed path.
        let mut by_descriptor: HashMap<WatchDescriptor, HashSet<PathBuf>> = HashMap::new();
        for (descriptor, path) in forgotten {
            by_descriptor.entry(descriptor).or_default().insert(path);
        }
        for (descriptor, forgotten) in by_descriptor {
            if let Some(paths) = self.paths.get_mut(&descriptor) {
                paths.retain(|path| !forgotten.contains(path));
                if paths.is_empty() {
                    self.paths.remove(&descriptor);
                }
            }
        }
    }

    /// Remove a descriptor while tolerating the deletion race documented by inotify.
    ///
    /// Linux may invalidate a watch before its queued deletion event is handled. In that case
    /// `inotify_rm_watch` returns EINVAL, but the requested end state has already been reached.
    /// Other errors indicate an unexpected descriptor or inotify-instance failure and stay visible.
    fn remove_single_descriptor(watches: &mut inotify::Watches, wd: WatchDescriptor) {
        if let Err(err) = watches.remove(wd) {
            if err.raw_os_error() == Some(libc::EINVAL) {
                log::trace!("watch descriptor was already removed from inotify: {err:?}");
            } else {
                log::warn!("unable to remove watch descriptor from inotify: {err:?}");
            }
        }
    }

    fn remove_all_watches(&mut self) -> Result<()> {
        if let Some(ref mut inotify) = self.inotify {
            let mut inotify_watches = inotify.watches();
            for (w, paths) in &self.paths {
                inotify_watches
                    .remove(w.clone())
                    .map_err(|e| Error::io(e).add_path(paths[0].clone()))?;
            }
            self.watches.clear();
            self.user_roots.clear();
            self.paths.clear();
        }
        Ok(())
    }
}

/// Returns the names of the subdirectories of `path`, and with `follow_links` also the names
/// of its symbolic links. The errors of the entries whose type cannot be read are added to
/// `errors`.
fn visited_entries(
    path: &WatchPath,
    root: &WatchPath,
    follow_links: bool,
    errors: &mut Vec<Error>,
) -> Result<Vec<OsString>> {
    let entries = read_dir(&path.absolute)
        .map_err(|err| Error::io_watch(err).add_path(path.requested.clone()))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                errors.push(Error::io_watch(err).add_path(path.requested.clone()));
                continue;
            }
        };
        match entry.file_type() {
            Ok(kind) if kind.is_dir() || (follow_links && kind.is_symlink()) => {
                names.push(entry.file_name());
            }
            Ok(_) => {}
            Err(err) => {
                errors.push(Error::io_watch(err).add_path(root.child(entry.path()).requested));
            }
        }
    }
    Ok(names)
}

/// Yields the directories to watch below `from`, and the errors that hid part of the tree.
///
/// Each directory is named the way `root` was asked for, and `barriers` are the paths the walk
/// must not descend into. Dropping the walk's errors would leave whole subtrees unwatched with
/// nothing to notice, the same silence a failed watch used to cause. `above` contains the
/// directories above `from` that a walk of the recursive watch passed through to reach `from`.
fn walk_dirs(
    from: PathBuf,
    root: WatchPath,
    follow_links: bool,
    barriers: &HashSet<PathBuf>,
    above: Vec<PathBuf>,
    mut listings: Option<&mut Listings>,
) -> impl Iterator<Item = Result<WatchPath>> {
    enum Step {
        Visit(WatchPath),
        Read(WatchPath, (u64, u64, i64, i64)),
        Leave,
        Error(Error),
    }

    let mut pending = vec![Step::Visit(root.child(from))];
    let mut ancestors = Vec::new();
    // Most walks find no link, so the walk only calls `stat` on the directories in `above` when
    // it finds the first link.
    let mut above_identities: Option<Vec<(u64, u64)>> = None;

    std::iter::from_fn(move || {
        loop {
            match pending.pop()? {
                Step::Visit(path) => {
                    // Exclude links before resolving them: resolution errors may not name the link.
                    if barriers.contains(&path.absolute) {
                        continue;
                    }
                    // Recheck descendant types after enumeration; the walk root is always followed.
                    let mut metadata = match symlink_metadata(&path.absolute) {
                        Ok(metadata) => metadata,
                        Err(err) => {
                            return Some(Err(Error::io_watch(err).add_path(path.requested)));
                        }
                    };
                    let is_symlink = metadata.file_type().is_symlink();
                    if is_symlink && (follow_links || ancestors.is_empty()) {
                        metadata = match std::fs::metadata(&path.absolute) {
                            Ok(metadata) => metadata,
                            Err(err) => {
                                return Some(Err(Error::io_watch(err).add_path(path.requested)));
                            }
                        };
                    }
                    if !metadata.is_dir() {
                        // The walk of a user watch checked that its root is a directory. A
                        // root that was replaced since then is not watched at all.
                        if ancestors.is_empty() && path.absolute == root.absolute {
                            return Some(Err(Error::io_watch(std::io::Error::from(
                                std::io::ErrorKind::NotADirectory,
                            ))
                            .add_path(path.requested)));
                        }
                        continue;
                    }
                    let identity = (metadata.dev(), metadata.ino());
                    // A bind mount can share an ancestor's inode without forming a symlink loop.
                    if is_symlink
                        && (ancestors.contains(&identity)
                            || above_identities
                                .get_or_insert_with(|| {
                                    above
                                        .iter()
                                        .filter_map(|path| std::fs::metadata(path).ok())
                                        .map(|metadata| (metadata.dev(), metadata.ino()))
                                        .collect()
                                })
                                .contains(&identity))
                    {
                        return Some(Err(
                            Error::generic("symbolic link loop").add_path(path.requested)
                        ));
                    }
                    ancestors.push(identity);
                    pending.push(Step::Leave);
                    // Yield the directory before reading its contents so its watch is installed first.
                    let key = (
                        identity.0,
                        identity.1,
                        metadata.ctime(),
                        metadata.ctime_nsec(),
                    );
                    pending.push(Step::Read(path.clone(), key));
                    return Some(Ok(path));
                }
                Step::Read(path, key) => {
                    // Each read of a directory makes inotify report an open and a close of the
                    // directory. A batch can walk a new directory once for each of its paths,
                    // so `listings` keeps the names that the first walk reads.
                    let cached = listings.as_deref().and_then(|listings| listings.get(&key));
                    let mut read = None;
                    let names = match cached {
                        Some(names) => names,
                        None => {
                            let mut errors = Vec::new();
                            let names =
                                match visited_entries(&path, &root, follow_links, &mut errors) {
                                    Ok(names) => names,
                                    Err(err) => return Some(Err(err)),
                                };
                            pending.extend(errors.into_iter().map(Step::Error));
                            read.insert(names)
                        }
                    };
                    let start = pending.len();
                    // Buffer paths, not directory handles, so deep trees do not exhaust descriptors.
                    for name in names {
                        let absolute = path.absolute.join(name);
                        if !barriers.contains(&absolute) {
                            pending.push(Step::Visit(root.child(absolute)));
                        }
                    }
                    pending[start..].reverse();
                    if let (Some(listings), Some(names)) = (listings.as_deref_mut(), read) {
                        listings.insert(key, names);
                    }
                }
                Step::Leave => {
                    ancestors.pop();
                }
                Step::Error(err) => return Some(Err(err)),
            }
        }
    })
}

impl INotifyWatcher {
    fn from_event_handler(event_handler: Box<dyn EventHandler>, config: &Config) -> Result<Self> {
        let inotify = Inotify::init()?;
        let event_loop = EventLoop::new(inotify, event_handler, config)?;
        let channel = event_loop.event_loop_tx.clone();
        let waker = event_loop.event_loop_waker.clone();
        event_loop.run();
        Ok(INotifyWatcher { channel, waker })
    }

    fn watch_inner(&mut self, path: &Path, config: WatchPathConfig) -> Result<()> {
        let pb = WatchPath::new(path)?;
        let (tx, rx) = unbounded();
        let msg = EventLoopMsg::AddWatch(pb, config, tx);

        self.channel.send(msg)?;
        self.waker.wake()?;
        rx.recv().map_err(Error::from)?
    }

    fn unwatch_inner(&mut self, path: &Path) -> Result<()> {
        let pb = absolute_path(path)?;
        let (tx, rx) = unbounded();
        let msg = EventLoopMsg::RemoveWatch(pb, tx);

        self.channel.send(msg)?;
        self.waker.wake()?;
        rx.recv().map_err(Error::from)?
    }

    fn watched_paths_inner(&self) -> Result<Vec<(PathBuf, RecursiveMode)>> {
        let (tx, rx) = unbounded();
        self.channel.send(EventLoopMsg::GetWatchedPaths(tx))?;
        self.waker.wake()?;
        rx.recv().map_err(Error::from)
    }
}

impl Watcher for INotifyWatcher {
    /// Create a new watcher.
    fn new<F: EventHandler>(event_handler: F, config: Config) -> Result<Self> {
        Self::from_event_handler(Box::new(event_handler), &config)
    }

    fn watch(&mut self, path: &Path, recursive_mode: RecursiveMode) -> Result<()> {
        self.watch_inner(path, WatchPathConfig::new(recursive_mode))
    }

    fn watch_with(&mut self, path: &Path, config: WatchPathConfig) -> Result<()> {
        if !config.watch_filter().is_accept_all() {
            return Err(Error::generic(
                "this watcher does not support watch filters yet",
            ));
        }
        self.watch_inner(path, config)
    }

    fn unwatch(&mut self, path: &Path) -> Result<()> {
        self.unwatch_inner(path)
    }

    fn update_paths(&mut self, ops: Vec<PathOp>) -> std::result::Result<(), UpdatePathsError> {
        // Resolve relative paths on the caller, as watch() and unwatch() do.
        let prepared = ops
            .iter()
            .map(|op| {
                let copy = match op {
                    PathOp::Watch(path, config) => PathOp::Watch(path.clone(), config.clone()),
                    PathOp::Unwatch(path) => PathOp::Unwatch(path.clone()),
                };
                (copy, absolute_path(op.as_path()))
            })
            .collect();
        let (tx, rx) = unbounded();
        self.channel
            .send(EventLoopMsg::UpdatePaths(prepared, tx))
            .map_err(|source| UpdatePathsError {
                source: Error::from(source),
                origin: None,
                remaining: ops,
            })?;
        self.waker
            .wake()
            .map_err(Error::from)
            .and_then(|()| rx.recv().map_err(Error::from))
            .map_err(|source| UpdatePathsError {
                source,
                origin: None,
                // The batch was enqueued; the applied prefix is unknown without its reply.
                remaining: Vec::new(),
            })?
    }

    fn configure(&mut self, config: Config) -> Result<bool> {
        let (tx, rx) = bounded(1);
        self.channel.send(EventLoopMsg::Configure(config, tx))?;
        self.waker.wake()?;
        rx.recv()?
    }

    fn watched_paths(&self) -> Result<Vec<(PathBuf, RecursiveMode)>> {
        self.watched_paths_inner()
    }

    fn kind() -> crate::WatcherKind {
        crate::WatcherKind::Inotify
    }
}

impl Drop for INotifyWatcher {
    fn drop(&mut self) {
        // we expect the event loop to live => unwrap must not panic
        self.channel.send(EventLoopMsg::Shutdown).unwrap();
        self.waker.wake().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        sync::{Arc, atomic::AtomicBool, mpsc},
        thread::{self, available_parallelism},
        time::Duration,
    };

    use super::inotify_sys::WatchMask;
    use super::{
        Config, Error, ErrorKind, Event, EventKind, EventLoop, INotifyWatcher, RecursiveMode,
        Result, WatchFilter, WatchPath, WatchPathConfig, Watcher,
    };
    use notify_types::event::{
        CreateKind, DataChange, EventKindMask, ModifyKind, RemoveKind, RenameMode,
    };

    use crate::test::*;

    /// Only data changes, so access events do not disturb exact assertions.
    fn watcher_with_data_events() -> (TestWatcher<INotifyWatcher>, Receiver) {
        channel_with_config(
            ChannelConfig::default().with_watcher_config(
                Config::default().with_event_kinds(EventKindMask::MODIFY_DATA),
            ),
        )
    }

    fn recursive_watch() -> WatchPathConfig {
        WatchPathConfig::new(RecursiveMode::Recursive)
    }

    fn non_recursive_watch() -> WatchPathConfig {
        WatchPathConfig::new(RecursiveMode::NonRecursive)
    }

    fn watcher() -> (TestWatcher<INotifyWatcher>, Receiver) {
        channel()
    }

    fn test_event_loop_with_config(config: &Config) -> EventLoop {
        let inotify = super::inotify_sys::Inotify::init().unwrap();
        EventLoop::new(inotify, Box::new(|_| {}), config).unwrap()
    }

    fn test_event_loop() -> EventLoop {
        test_event_loop_with_config(&Config::default())
    }

    fn test_event_loop_with_events() -> (EventLoop, mpsc::Receiver<crate::Result<Event>>) {
        let (tx, rx) = mpsc::channel();
        let inotify = super::inotify_sys::Inotify::init().unwrap();
        let event_loop = EventLoop::new(inotify, Box::new(tx), &Config::default()).unwrap();
        (event_loop, rx)
    }

    /// Create a watcher configured to receive ALL events including Access events.
    /// Use this for tests that verify Access event behavior.
    fn watcher_with_all_events() -> (TestWatcher<INotifyWatcher>, Receiver) {
        channel_with_config(
            ChannelConfig::default()
                .with_timeout(std::time::Duration::from_secs(1))
                .with_watcher_config(Config::default().with_event_kinds(EventKindMask::ALL)),
        )
    }

    #[test]
    fn inotify_watcher_is_send_and_sync() {
        fn check<T: Send + Sync>() {}
        check::<INotifyWatcher>();
    }

    #[test]
    fn native_error_type_on_missing_path() {
        let mut watcher = INotifyWatcher::new(|_| {}, Config::default()).unwrap();

        let result = watcher.watch(
            &PathBuf::from("/some/non/existant/path"),
            RecursiveMode::NonRecursive,
        );

        assert!(matches!(
            result,
            Err(Error {
                paths: _,
                kind: ErrorKind::PathNotFound
            })
        ))
    }

    // Regression test for https://github.com/notify-rs/notify/issues/579.
    #[test]
    fn recursive_watch_ignores_missing_subdir_during_initial_scan() {
        use std::fs;

        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().to_path_buf();
        let disappearing = root.join("disappearing");
        fs::create_dir(&disappearing).unwrap();
        fs::remove_dir_all(&disappearing).unwrap();

        let mut event_loop = test_event_loop();

        // Simulate the TOCTOU: we *intend* to watch a subdirectory discovered during initial scan,
        // but it's already gone by the time we call `inotify_add_watch`.
        let user_root: Arc<Path> = root.as_path().into();
        event_loop.user_roots.insert(
            user_root.clone(),
            crate::walk::recursive::UserRoot {
                requested: root.clone(),
                is_recursive: true,
                watch_filter: WatchFilter::accept_all(),
            },
        );
        let result = event_loop.add_watches_for_paths(
            &[user_root],
            [root, disappearing]
                .into_iter()
                .map(|path| Ok(WatchPath::new(&path).unwrap())),
            true,
            true,
            false,
        );
        assert!(
            result.is_ok(),
            "expected recursive watch to succeed, got: {result:?}"
        );
    }

    /// Create a directory `inotify_add_watch` refuses; false if it stayed readable
    /// (happens when running as root)
    fn unwatchable_dir(path: &Path) -> bool {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o000)).unwrap();
        fs::read_dir(path).is_err()
    }

    /// Undo `unwatchable_dir`, so that the tempdir can be removed again.
    fn make_readable(path: &Path) {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Wait for an event the predicate accepts, repeating `poke` until one arrives. The event
    /// loop installs watches in the background, so a change made once can be made before the
    /// watch that would report it exists.
    fn wait_for(
        rx: &mpsc::Receiver<Result<Event>>,
        poke: impl Fn(),
        accept: impl Fn(&Result<Event>) -> bool,
    ) -> Option<Result<Event>> {
        use std::time::Instant;

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            poke();
            if let Ok(event) = rx.recv_timeout(Duration::from_millis(200)) {
                if accept(&event) {
                    return Some(event);
                }
            }
        }
        None
    }

    /// A directory that cannot be watched must not cause the later ones to get ignored.
    #[test]
    fn recursive_watch_survives_an_unwatchable_subdir() {
        use std::fs;
        use std::sync::Mutex;

        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().to_path_buf();
        let unwatchable = root.join("unwatchable");
        let readable = root.join("readable");
        let deeper = readable.join("deeper");
        fs::create_dir_all(&deeper).unwrap();
        if !unwatchable_dir(&unwatchable) {
            return; // running as root, which can watch a directory it cannot read
        }

        let errors = Arc::new(Mutex::new(Vec::new()));
        let collected = errors.clone();
        let inotify = super::inotify_sys::Inotify::init().unwrap();
        let mut event_loop = EventLoop::new(
            inotify,
            Box::new(move |event: Result<Event>| {
                if let Err(e) = event {
                    collected.lock().unwrap().push(e);
                }
            }),
            &Config::default(),
        )
        .unwrap();

        let result = event_loop.add_watch(WatchPath::new(&root).unwrap(), recursive_watch());
        // Before the asserts: a directory the test cannot read is one tempfile cannot remove.
        make_readable(&unwatchable);

        assert!(
            result.is_ok(),
            "expected the watch to succeed, got: {result:?}"
        );
        assert!(event_loop.watches.contains_key(&readable));
        assert!(event_loop.watches.contains_key(&deeper));
        let errors = errors.lock().unwrap();
        // Once, not twice: it can neither be watched nor be read, which is one loss to the caller.
        assert_eq!(
            errors
                .iter()
                .filter(|e| e.paths.contains(&unwatchable))
                .count(),
            1,
            "expected the unwatchable directory to be reported once, got: {errors:?}"
        );
    }

    /// A subtree the walk cannot enter is as unwatched as one that cannot be watched, so it has to
    /// be reported too. Symlinks are followed by default, so a link into its own ancestor is the
    /// easiest walk error to provoke.
    #[test]
    fn recursive_watch_reports_a_walk_error() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::sync::Mutex;

        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().to_path_buf();
        let readable = root.join("readable");
        fs::create_dir(&readable).unwrap();
        symlink(&root, root.join("loop")).unwrap();

        let errors = Arc::new(Mutex::new(Vec::new()));
        let collected = errors.clone();
        let inotify = super::inotify_sys::Inotify::init().unwrap();
        let mut event_loop = EventLoop::new(
            inotify,
            Box::new(move |event: Result<Event>| {
                if let Err(e) = event {
                    collected.lock().unwrap().push(e);
                }
            }),
            &Config::default(),
        )
        .unwrap();

        let result = event_loop.add_watch(WatchPath::new(&root).unwrap(), recursive_watch());

        assert!(
            result.is_ok(),
            "expected the watch to succeed, got: {result:?}"
        );
        assert!(event_loop.watches.contains_key(&readable));
        let errors = errors.lock().unwrap();
        assert!(
            errors
                .iter()
                .any(|e| e.paths.iter().any(|p| p.ends_with("loop"))),
            "expected the symlink loop to be reported, got: {errors:?}"
        );
    }

    #[test]
    fn recursive_walk_reports_loops_without_skipping_directory_aliases() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().join("root");
        let destination = tmpdir.path().join("destination");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir_all(destination.join("nested")).unwrap();
        std::os::unix::fs::symlink(".", destination.join("loop")).unwrap();
        for alias in ["a", "b"] {
            std::os::unix::fs::symlink(&destination, root.join(alias)).unwrap();
        }

        let reported = PathBuf::from("relative-root");
        let barriers = Default::default();
        let entries = super::walk_dirs(
            root.clone(),
            WatchPath::from_parts(root, reported.clone()),
            true,
            &barriers,
            Vec::new(),
            None,
        );
        let mut watched = Vec::new();
        let mut failures = Vec::new();
        for entry in entries {
            match entry {
                Ok(path) => watched.push(path.requested),
                Err(err) => failures.extend(err.paths),
            }
        }
        watched.sort();
        failures.sort();
        assert_eq!(
            watched,
            ["", "a", "a/nested", "b", "b/nested"].map(|path| reported.join(path))
        );
        assert_eq!(failures, [reported.join("a/loop"), reported.join("b/loop")]);
    }

    #[test]
    fn a_new_directory_with_a_link_back_to_the_root_reports_a_loop() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let moved = tmp.path().join("moved");
        std::fs::create_dir(&moved).unwrap();
        std::os::unix::fs::symlink(&root, moved.join("back")).unwrap();
        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();

        std::fs::rename(&moved, root.join("moved")).unwrap();
        event_loop.handle_inotify();

        let back = root.join("moved").join("back");
        let failures: Vec<_> = rx
            .try_iter()
            .filter_map(Result::err)
            .flat_map(|err| err.paths)
            .collect();
        assert_eq!(failures, [back.clone()]);
        assert!(!event_loop.watches.contains_key(&back));
    }

    #[test]
    fn nested_recursive_watch_keeps_new_parent_link_after_outer_unwatch() {
        let tmp = tempfile::tempdir().unwrap();
        let outer = tmp.path().join("outer");
        let inner = outer.join("inner");
        let sibling = outer.join("sibling");
        let staging = tmp.path().join("staging");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::create_dir(&sibling).unwrap();
        std::fs::create_dir(&staging).unwrap();
        std::os::unix::fs::symlink(&outer, staging.join("back")).unwrap();
        let (mut event_loop, rx) = test_event_loop_with_events();
        for root in [&outer, &inner] {
            event_loop
                .add_watch(WatchPath::new(root).unwrap(), recursive_watch())
                .unwrap();
        }

        // The inner watch must follow this link even though the outer watch covers its target.
        std::fs::rename(&staging, inner.join("moved")).unwrap();
        event_loop.handle_inotify();
        event_loop.remove_watch(outer).unwrap();
        event_loop.handle_inotify();
        // Ignore uninteresting events.
        rx.try_iter().for_each(drop);

        std::fs::write(sibling.join("probe"), "content").unwrap();
        event_loop.handle_inotify();
        let events: Vec<_> = rx.try_iter().map(Result::unwrap).collect();
        let expected = Event::new(EventKind::Create(CreateKind::File))
            .add_path(inner.join("moved/back/sibling/probe"));
        assert!(
            events.contains(&expected),
            "the inner watch lost coverage through its parent link: {events:?}"
        );
    }

    #[test]
    fn recursive_walk_visits_directory_aliases_under_a_parent_link() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().join("child");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::os::unix::fs::symlink("..", root.join("parent")).unwrap();

        let reported = PathBuf::from("relative-root");
        let barriers = Default::default();
        let entries = super::walk_dirs(
            root.clone(),
            WatchPath::from_parts(root, reported.clone()),
            true,
            &barriers,
            Vec::new(),
            None,
        );
        let mut watched = Vec::new();
        let mut failures = Vec::new();
        for entry in entries {
            match entry {
                Ok(path) => watched.push(path.requested),
                Err(err) => failures.extend(err.paths),
            }
        }
        watched.sort();
        // The parent link reaches `child` again through a regular directory entry.
        assert_eq!(
            watched,
            [
                "",
                "nested",
                "parent",
                "parent/child",
                "parent/child/nested"
            ]
            .map(|path| reported.join(path))
        );
        assert_eq!(failures, [reported.join("parent/child/parent")]);
    }

    #[test]
    fn recursive_walk_honors_follow_symlinks_after_directory_replacement() {
        for follow_links in [false, true] {
            let tmpdir = tempfile::tempdir().unwrap();
            let root = tmpdir.path().join("root");
            let children = ["a", "b", "c"].map(|name| root.join(name));
            for child in &children {
                std::fs::create_dir_all(child).unwrap();
            }
            let destination = tmpdir.path().join("destination");
            std::fs::create_dir_all(destination.join("nested")).unwrap();

            let barriers = Default::default();
            let mut entries = super::walk_dirs(
                root.clone(),
                WatchPath::new(&root).unwrap(),
                follow_links,
                &barriers,
                Vec::new(),
                None,
            );
            assert_eq!(entries.next().unwrap().unwrap().absolute, root);
            let first = entries.next().unwrap().unwrap().absolute;

            // The siblings have been listed but not visited. Pick one regardless of entry order.
            let replaced = children
                .iter()
                .find(|path| **path != first)
                .unwrap()
                .clone();
            std::fs::remove_dir(&replaced).unwrap();
            std::os::unix::fs::symlink(&destination, &replaced).unwrap();

            let mut remaining: Vec<_> = entries.map(|entry| entry.unwrap().absolute).collect();
            let mut expected: Vec<_> = children
                .into_iter()
                .filter(|path| *path != first && (follow_links || *path != replaced))
                .collect();
            if follow_links {
                expected.push(replaced.join("nested"));
            }
            remaining.sort();
            expected.sort();
            assert_eq!(remaining, expected, "follow_links = {follow_links}");
        }
    }

    // FIXME: FreeBSD 15.1 does not generate IN_IGNORED unless IN_DELETE_SELF was requested.
    // Remove this ignore once CI uses a release containing the fix:
    // https://cgit.freebsd.org/src/commit/?id=242c9c86c8cad6aa29bc1af9161d4f0eec45f29b
    #[cfg_attr(
        target_os = "freebsd",
        ignore = "FreeBSD 15.1 does not generate IN_IGNORED unconditionally"
    )]
    #[test]
    fn deleting_a_directory_that_a_walk_reached_through_a_link_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let outer = tmp.path().join("outer");
        let shared = tmp.path().join("shared");
        std::fs::create_dir(&outer).unwrap();
        std::fs::create_dir(&shared).unwrap();
        std::os::unix::fs::symlink(&shared, outer.join("link")).unwrap();

        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&shared).unwrap(), non_recursive_watch())
            .unwrap();
        // The walk reaches `shared` again through `outer/link` and adds the same inode.
        event_loop
            .add_watch(WatchPath::new(&outer).unwrap(), recursive_watch())
            .unwrap();

        std::fs::remove_dir(&shared).unwrap();
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(50));
            event_loop.handle_inotify();
        }
        let removed = rx
            .try_iter()
            .filter_map(Result::ok)
            .any(|event| event.kind.is_remove());
        assert!(removed, "deleting the watched directory must be reported");
    }

    #[test]
    fn deleting_a_directory_shared_through_a_link_removes_every_path() {
        let tmp = tempfile::tempdir().unwrap();
        let outer = tmp.path().join("outer");
        let shared = tmp.path().join("shared");
        std::fs::create_dir(&outer).unwrap();
        std::fs::create_dir_all(shared.join("sub")).unwrap();
        let link = outer.join("link");
        std::os::unix::fs::symlink(&shared, &link).unwrap();

        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&shared).unwrap(), recursive_watch())
            .unwrap();
        event_loop
            .add_watch(WatchPath::new(&outer).unwrap(), recursive_watch())
            .unwrap();

        std::fs::remove_dir_all(&shared).unwrap();
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(50));
            event_loop.handle_inotify();
        }

        let mut remaining: Vec<_> = event_loop.watches.keys().cloned().collect();
        remaining.sort();
        assert_eq!(
            remaining,
            [outer],
            "the deleted directory must not stay watched under any of its paths"
        );
        let removed = rx
            .try_iter()
            .filter_map(Result::ok)
            .any(|event| event.kind.is_remove() && event.paths == [shared.clone()]);
        assert!(
            removed,
            "the user watch of the deleted directory must report it under its own path"
        );
    }

    #[test]
    fn deleting_a_file_with_two_watched_hard_links_removes_both_watches() {
        let tmp = tempfile::tempdir().unwrap();
        let first = tmp.path().join("first");
        let second = tmp.path().join("second");
        std::fs::write(&first, b"content").unwrap();
        std::fs::hard_link(&first, &second).unwrap();

        let (mut event_loop, rx) = test_event_loop_with_events();
        for path in [&first, &second] {
            event_loop
                .add_watch(WatchPath::new(path).unwrap(), non_recursive_watch())
                .unwrap();
        }

        std::fs::remove_file(&first).unwrap();
        std::fs::remove_file(&second).unwrap();
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(50));
            event_loop.handle_inotify();
        }

        assert!(
            event_loop.watches.is_empty(),
            "{:?}",
            event_loop.watches.keys()
        );
        assert!(event_loop.paths.is_empty());
        let mut removed: Vec<_> = rx
            .try_iter()
            .filter_map(Result::ok)
            .filter(|event| event.kind.is_remove())
            .flat_map(|event| event.paths)
            .collect();
        removed.sort();
        assert_eq!(removed, [first, second]);
    }

    #[test]
    fn unwatching_a_shared_directory_stops_reporting_its_deletion() {
        let tmp = tempfile::tempdir().unwrap();
        let outer = tmp.path().join("outer");
        let shared = tmp.path().join("shared");
        std::fs::create_dir(&outer).unwrap();
        std::fs::create_dir(&shared).unwrap();
        let link = outer.join("link");
        std::os::unix::fs::symlink(&shared, &link).unwrap();

        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&shared).unwrap(), non_recursive_watch())
            .unwrap();
        event_loop
            .add_watch(WatchPath::new(&outer).unwrap(), recursive_watch())
            .unwrap();
        event_loop.remove_watch(shared.clone()).unwrap();

        // Only the user watch of `shared` requested `IN_DELETE_SELF`. `outer/link` itself still
        // exists, so its deletion must not be reported.
        std::fs::remove_dir(&shared).unwrap();
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(50));
            event_loop.handle_inotify();
        }
        let removed: Vec<_> = rx
            .try_iter()
            .filter_map(Result::ok)
            .filter(|event| event.kind.is_remove())
            .collect();
        assert!(removed.is_empty(), "{removed:?}");
    }

    #[test]
    fn a_removed_root_keeps_a_descendant_that_another_path_shares() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let shared = root.join("shared");
        let other = tmp.path().join("other");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::create_dir(&other).unwrap();
        let link = other.join("link");
        std::os::unix::fs::symlink(&shared, &link).unwrap();

        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&other).unwrap(), recursive_watch())
            .unwrap();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();

        // The kernel removed the descriptor of `root`, but `other/link` still uses the
        // descriptor of `root/shared`.
        event_loop
            .remove_watch_without_root_os_call(root.clone())
            .unwrap();
        std::fs::write(shared.join("file"), b"content").unwrap();
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(50));
            event_loop.handle_inotify();
        }
        let created = rx
            .try_iter()
            .filter_map(Result::ok)
            .any(|event| event.kind.is_create() && event.paths == [link.join("file")]);
        assert!(created, "`other/link` must keep receiving events");
    }

    /// Creates `outer` and `shared` in a temporary directory, and the link `outer/link` to
    /// `shared`.
    fn outer_with_a_link_to_shared() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let outer = tmp.path().join("outer");
        let shared = tmp.path().join("shared");
        std::fs::create_dir(&outer).unwrap();
        std::fs::create_dir(&shared).unwrap();
        std::os::unix::fs::symlink(&shared, outer.join("link")).unwrap();
        (tmp, outer, shared)
    }

    fn handle_pending_events(event_loop: &mut EventLoop) {
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(50));
            event_loop.handle_inotify();
        }
    }

    fn drain_events(
        event_loop: &mut EventLoop,
        rx: &mpsc::Receiver<crate::Result<Event>>,
    ) -> Vec<Event> {
        handle_pending_events(event_loop);
        rx.try_iter().filter_map(Result::ok).collect()
    }

    #[test]
    fn a_shared_directory_reports_under_the_path_of_each_watch() {
        for shared_first in [false, true] {
            let (_tmp, outer, shared) = outer_with_a_link_to_shared();
            let (mut event_loop, rx) = test_event_loop_with_events();
            let mut watches = [
                (WatchPath::new(&outer).unwrap(), recursive_watch()),
                (WatchPath::new(&shared).unwrap(), non_recursive_watch()),
            ];
            if shared_first {
                watches.reverse();
            }
            for (path, config) in watches {
                event_loop.add_watch(path, config).unwrap();
            }

            std::fs::write(shared.join("file"), b"content").unwrap();
            let created: Vec<_> = drain_events(&mut event_loop, &rx)
                .into_iter()
                .filter(|event| event.kind.is_create())
                .flat_map(|event| event.paths)
                .collect();
            assert!(
                created.contains(&shared.join("file")),
                "shared_first = {shared_first}: {created:?}"
            );
            assert!(
                created.contains(&outer.join("link").join("file")),
                "shared_first = {shared_first}: {created:?}"
            );
        }
    }

    #[test]
    fn a_recursive_path_of_a_shared_directory_watches_its_new_subdirectories() {
        for shared_first in [false, true] {
            let (_tmp, outer, shared) = outer_with_a_link_to_shared();
            let (mut event_loop, rx) = test_event_loop_with_events();
            let mut watches = [
                (WatchPath::new(&outer).unwrap(), recursive_watch()),
                (WatchPath::new(&shared).unwrap(), non_recursive_watch()),
            ];
            if shared_first {
                watches.reverse();
            }
            for (path, config) in watches {
                event_loop.add_watch(path, config).unwrap();
            }

            std::fs::create_dir(shared.join("new")).unwrap();
            drain_events(&mut event_loop, &rx);
            assert!(
                event_loop
                    .watches
                    .contains_key(&outer.join("link").join("new")),
                "shared_first = {shared_first}: the recursive watch of `outer` must watch the new \
                 directory"
            );
        }
    }

    #[test]
    fn moving_a_directory_out_of_a_shared_directory_removes_it_under_every_path() {
        let (tmp, outer, shared) = outer_with_a_link_to_shared();
        std::fs::create_dir(shared.join("sub")).unwrap();
        let (mut event_loop, rx) = test_event_loop_with_events();
        for root in [&shared, &outer] {
            event_loop
                .add_watch(WatchPath::new(root).unwrap(), recursive_watch())
                .unwrap();
        }

        std::fs::rename(shared.join("sub"), tmp.path().join("moved")).unwrap();
        drain_events(&mut event_loop, &rx);
        assert!(!event_loop.watches.contains_key(&shared.join("sub")));
        assert!(
            !event_loop
                .watches
                .contains_key(&outer.join("link").join("sub"))
        );
    }

    #[test]
    fn a_non_recursive_watch_on_an_ancestor_does_not_report_through_a_link() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("a").join("b")).unwrap();
        std::os::unix::fs::symlink(root.join("a").join("b"), root.join("l")).unwrap();
        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();
        event_loop
            .add_watch(
                WatchPath::new(&root.join("a")).unwrap(),
                non_recursive_watch(),
            )
            .unwrap();

        // The watch on `root` reaches `a/b` twice. The watch on `a` does not cover `a/b`.
        std::fs::write(root.join("a").join("b").join("file"), b"content").unwrap();
        let created: Vec<_> = drain_events(&mut event_loop, &rx)
            .into_iter()
            .filter(|event| event.kind.is_create())
            .collect();
        assert_eq!(created.len(), 1, "{created:?}");
    }

    #[test]
    fn a_rename_in_a_shared_directory_pairs_the_paths_of_each_watch() {
        use notify_types::event::{ModifyKind, RenameMode};

        let (_tmp, outer, shared) = outer_with_a_link_to_shared();
        std::fs::write(shared.join("from"), b"content").unwrap();
        let (mut event_loop, rx) = test_event_loop_with_events();
        for root in [&outer, &shared] {
            event_loop
                .add_watch(WatchPath::new(root).unwrap(), recursive_watch())
                .unwrap();
        }

        std::fs::rename(shared.join("from"), shared.join("to")).unwrap();
        let mut renames: Vec<_> = drain_events(&mut event_loop, &rx)
            .into_iter()
            .filter(|event| {
                matches!(
                    event.kind,
                    EventKind::Modify(ModifyKind::Name(RenameMode::Both))
                )
            })
            .map(|event| event.paths)
            .collect();
        renames.sort();
        let link = outer.join("link");
        assert_eq!(
            renames,
            [
                vec![link.join("from"), link.join("to")],
                vec![shared.join("from"), shared.join("to")],
            ]
        );
    }

    #[test]
    fn moving_a_directory_that_one_watch_reaches_twice_is_reported_once() {
        use notify_types::event::{ModifyKind, RenameMode};

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();

        std::fs::rename(root.join("real"), root.join("moved")).unwrap();
        // `IN_MOVE_SELF` reports the move of the directory itself, without a tracker.
        let moved: Vec<_> = drain_events(&mut event_loop, &rx)
            .into_iter()
            .filter(|event| {
                matches!(
                    event.kind,
                    EventKind::Modify(ModifyKind::Name(RenameMode::From))
                ) && event.tracker().is_none()
            })
            .collect();
        assert_eq!(moved.len(), 1, "{moved:?}");
    }

    #[test]
    fn a_directory_that_one_watch_reaches_twice_reports_a_new_directory_under_one_path() {
        use notify_types::event::CreateKind;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();

        std::fs::create_dir(root.join("real").join("new")).unwrap();
        let folders: Vec<_> = drain_events(&mut event_loop, &rx)
            .into_iter()
            .filter(|event| event.kind == EventKind::Create(CreateKind::Folder))
            .flat_map(|event| event.paths)
            .collect();
        assert_eq!(folders.len(), 1, "{folders:?}");

        std::fs::write(root.join("real").join("new").join("file"), b"content").unwrap();
        let files: Vec<_> = drain_events(&mut event_loop, &rx)
            .into_iter()
            .filter(|event| event.kind == EventKind::Create(CreateKind::File))
            .flat_map(|event| event.paths)
            .collect();
        assert_eq!(files, [folders[0].join("file")]);
    }

    #[test]
    fn a_renamed_directory_is_reported_under_its_new_path() {
        use notify_types::event::CreateKind;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::os::unix::fs::symlink("a", root.join("link")).unwrap();
        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();

        // `link` still points to `a`, which no longer exists.
        std::fs::rename(root.join("a"), root.join("b")).unwrap();
        drain_events(&mut event_loop, &rx);
        std::fs::write(root.join("b").join("file"), b"content").unwrap();
        let files: Vec<_> = drain_events(&mut event_loop, &rx)
            .into_iter()
            .filter(|event| event.kind == EventKind::Create(CreateKind::File))
            .flat_map(|event| event.paths)
            .collect();
        assert_eq!(files, [root.join("b").join("file")]);
    }

    #[test]
    fn a_nested_new_directory_that_one_watch_reaches_twice_is_reported_once() {
        use notify_types::event::CreateKind;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();

        // The walk of `new` finds `nested`, which was created before `new` was watched.
        std::fs::create_dir_all(root.join("real").join("new").join("nested")).unwrap();
        let folders: Vec<_> = drain_events(&mut event_loop, &rx)
            .into_iter()
            .filter(|event| event.kind == EventKind::Create(CreateKind::Folder))
            .flat_map(|event| event.paths)
            .collect();
        assert_eq!(folders.len(), 2, "{folders:?}");
        assert_eq!(folders[1], folders[0].join("nested"));
    }

    #[test]
    fn a_path_without_moved_to_does_not_report_a_rename_into_a_shared_directory() {
        use notify_types::event::{ModifyKind, RenameMode};

        let (_tmp, outer, shared) = outer_with_a_link_to_shared();
        std::fs::write(shared.join("from"), b"content").unwrap();
        // Without `EventKindMask::CREATE`, only the recursive walk of `outer` requests
        // `IN_MOVED_TO` for `shared`.
        let (tx, rx) = mpsc::channel();
        let inotify = super::inotify_sys::Inotify::init().unwrap();
        let config = Config::default().with_event_kinds(EventKindMask::MODIFY_NAME);
        let mut event_loop = EventLoop::new(inotify, Box::new(tx), &config).unwrap();
        event_loop
            .add_watch(WatchPath::new(&shared).unwrap(), non_recursive_watch())
            .unwrap();
        event_loop
            .add_watch(WatchPath::new(&outer).unwrap(), recursive_watch())
            .unwrap();

        std::fs::rename(shared.join("from"), shared.join("to")).unwrap();
        let renamed: Vec<_> = drain_events(&mut event_loop, &rx)
            .into_iter()
            .filter(|event| event.kind == EventKind::Modify(ModifyKind::Name(RenameMode::To)))
            .flat_map(|event| event.paths)
            .collect();
        assert_eq!(renamed, [outer.join("link").join("to")]);
    }

    #[test]
    fn a_path_without_delete_self_does_not_report_the_deletion_of_a_shared_directory() {
        let (_tmp, outer, shared) = outer_with_a_link_to_shared();
        let (mut event_loop, rx) = test_event_loop_with_events();
        // Only the user watch on `shared` requests `IN_DELETE_SELF`.
        event_loop
            .add_watch(WatchPath::new(&outer).unwrap(), recursive_watch())
            .unwrap();
        event_loop
            .add_watch(WatchPath::new(&shared).unwrap(), non_recursive_watch())
            .unwrap();

        std::fs::remove_dir(&shared).unwrap();
        let removed: Vec<_> = drain_events(&mut event_loop, &rx)
            .into_iter()
            .filter(|event| event.kind.is_remove())
            .flat_map(|event| event.paths)
            .collect();
        assert_eq!(removed, [shared]);
    }

    #[test]
    fn a_rename_between_two_watches_pairs_its_source_and_destination() {
        use notify_types::event::{ModifyKind, RenameMode};

        let tmp = tempfile::tempdir().unwrap();
        let from = tmp.path().join("from");
        let to = tmp.path().join("to");
        std::fs::create_dir(&from).unwrap();
        std::fs::create_dir(&to).unwrap();
        std::fs::write(from.join("file"), b"content").unwrap();
        let (mut event_loop, rx) = test_event_loop_with_events();
        for path in [&from, &to] {
            event_loop
                .add_watch(WatchPath::new(path).unwrap(), non_recursive_watch())
                .unwrap();
        }

        std::fs::rename(from.join("file"), to.join("file")).unwrap();
        let renames: Vec<_> = drain_events(&mut event_loop, &rx)
            .into_iter()
            .filter(|event| event.kind == EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .map(|event| event.paths)
            .collect();
        assert_eq!(renames, [vec![from.join("file"), to.join("file")]]);
    }

    #[test]
    fn a_link_that_a_rename_replaces_loses_its_watch() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let target = tmp.path().join("target");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, root.join("link")).unwrap();
        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();
        assert!(event_loop.watches.contains_key(&root.join("link")));

        std::fs::write(root.join("file"), b"").unwrap();
        std::fs::rename(root.join("file"), root.join("link")).unwrap();
        drain_events(&mut event_loop, &rx);
        std::fs::write(target.join("file"), b"").unwrap();
        let events = drain_events(&mut event_loop, &rx);

        assert!(!event_loop.watches.contains_key(&root.join("link")));
        assert!(events.is_empty(), "{events:?}");
    }

    #[test]
    fn a_new_directory_that_is_replaced_by_a_file_before_its_walk_is_not_watched() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let mut event_loop = test_event_loop();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();

        let path = root.join("dir");
        std::fs::create_dir(&path).unwrap();
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, b"").unwrap();
        event_loop.handle_inotify();

        assert!(!event_loop.watches.contains_key(&path));
    }

    #[test]
    fn a_new_directory_that_several_links_reach_is_read_once() {
        use notify_types::event::AccessKind;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let target = root.join("target");
        std::fs::create_dir_all(&target).unwrap();
        for link in ["a", "b", "c"] {
            std::os::unix::fs::symlink(&target, root.join(link)).unwrap();
        }
        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();
        drain_events(&mut event_loop, &rx);

        std::fs::create_dir(target.join("new")).unwrap();
        let opens = drain_events(&mut event_loop, &rx)
            .into_iter()
            .filter(|event| matches!(event.kind, EventKind::Access(AccessKind::Open(_))))
            .count();
        // The walks of `new` for the four paths of `target` read `new` once. inotify reports the
        // read as an open of `new` on the watch of `new` and on the watch of `target`.
        assert_eq!(opens, 2);
    }

    #[test]
    fn recursive_parent_added_after_non_recursive_alias_watches_new_subdirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let child = root.join("child");
        let alias = tmp.path().join("alias");
        std::fs::create_dir_all(&child).unwrap();
        std::os::unix::fs::symlink(&child, &alias).unwrap();

        let (mut event_loop, rx) = test_event_loop_with_events();
        for path in [&child, &alias] {
            event_loop
                .add_watch(WatchPath::new(path).unwrap(), non_recursive_watch())
                .unwrap();
        }
        // The parent's walk must use `child` for events again, so new directories
        // inherit its recursive coverage instead of the alias's non-recursive mode.
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();

        let new_dir = child.join("new_dir");
        std::fs::create_dir(&new_dir).unwrap();
        event_loop.handle_inotify();

        let file = new_dir.join("file");
        std::fs::write(&file, b"content").unwrap();
        event_loop.handle_inotify();

        let events: Vec<_> = rx.try_iter().map(Result::unwrap).collect();
        assert!(
            events
                .iter()
                .any(|event| event.kind.is_create() && event.paths == [file.clone()]),
            "the recursive parent must receive events from new subdirectories: {events:?}"
        );
    }

    #[test]
    fn watch_failure_after_a_directory_appears_is_reported() {
        use std::fs;

        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().join("root");
        let staging = tmpdir.path().join("staging");
        fs::create_dir(&root).unwrap();
        fs::create_dir_all(staging.join("readable")).unwrap();
        if !unwatchable_dir(&staging.join("unwatchable")) {
            return; // running as root, which can watch a directory it cannot read
        }

        let (tx, rx) = mpsc::channel();
        let mut watcher = INotifyWatcher::new(
            move |event| {
                let _ = tx.send(event);
            },
            Config::default(),
        )
        .unwrap();
        watcher.watch(&root, RecursiveMode::Recursive).unwrap();

        // Moved in whole, so the walk it triggers is certain to meet the unwatchable directory.
        let appearing = root.join("appearing");
        fs::rename(&staging, &appearing).unwrap();

        let reported = wait_for(&rx, || {}, Result::is_err);
        make_readable(&appearing.join("unwatchable"));
        let reported = reported
            .expect("expected the unwatchable directory to be reported")
            .unwrap_err();
        assert!(
            reported.paths.iter().any(|p| p.ends_with("unwatchable")),
            "expected the unwatchable directory to be named, got: {reported:?}"
        );

        // Its sibling is watched, so changes under it are still reported. The failure can reach
        // the handler before the walk reaches the sibling, so keep writing until it does.
        let file = appearing.join("readable").join("file");
        assert!(
            wait_for(
                &rx,
                || fs::write(&file, "x").unwrap(),
                |event| matches!(event, Ok(event) if event.paths.contains(&file))
            )
            .is_some(),
            "expected a change under the sibling directory to be reported"
        );
    }

    // An unfiltered rewatch that asks for exactly the current watch still short-circuits.
    #[test]
    fn identical_unfiltered_rewatch_is_noop() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().to_path_buf();

        let mut event_loop = test_event_loop();

        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .expect("watch root");

        let newdir = root.join("newdir");
        std::fs::create_dir(&newdir).unwrap();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .expect("identical rewatch");
        assert!(
            !event_loop.watches.contains_key(&newdir),
            "an identical unfiltered rewatch must be a no-op, not a rebuild"
        );
    }

    #[test]
    fn rewatching_same_path_replaces_recursive_state() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().to_path_buf();
        let child = root.join("child");
        std::fs::create_dir(&child).unwrap();

        let mut event_loop = test_event_loop();

        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .expect("watch recursively");
        assert!(event_loop.watches.contains_key(&child));

        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), non_recursive_watch())
            .expect("rewatch non-recursively");

        let watch = event_loop.watches.get(&root).expect("root watch");
        assert!(watch.metadata.is_user_watch);
        assert!(!event_loop.user_roots[root.as_path()].is_recursive);
        assert!(!watch.metadata.is_recursive);
        assert!(!event_loop.watches.contains_key(&child));
    }

    #[test]
    fn rewatching_child_preserves_recursive_parent_state() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().to_path_buf();
        let child = root.join("child");
        let grandchild = child.join("grandchild");
        std::fs::create_dir_all(&grandchild).unwrap();

        let (mut event_loop, rx) = test_event_loop_with_events();

        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .expect("watch root recursively");
        event_loop
            .add_watch(WatchPath::new(&child).unwrap(), non_recursive_watch())
            .expect("watch child non-recursively");
        event_loop
            .add_watch(
                WatchPath::from_parts(child.clone(), PathBuf::from("reported-child")),
                non_recursive_watch(),
            )
            .expect("rewatch child non-recursively");

        let child_watch = event_loop.watches.get(&child).expect("child watch");
        assert!(child_watch.metadata.is_user_watch);
        assert!(!event_loop.user_roots[child.as_path()].is_recursive);
        assert!(child_watch.metadata.is_recursive);
        assert_eq!(
            child_watch.metadata.reported_path,
            PathBuf::from("reported-child")
        );

        let grandchild_watch = event_loop
            .watches
            .get(&grandchild)
            .expect("grandchild still covered by recursive parent");
        assert!(!grandchild_watch.metadata.is_user_watch);
        assert!(grandchild_watch.metadata.is_recursive);

        event_loop.handle_inotify();
        assert!(rx.try_iter().all(|event| !event.unwrap().kind.is_create()));
    }

    #[test]
    fn nested_recursive_watch_keeps_its_spelling_under_an_outer_watch() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().to_path_buf();
        let child = root.join("child");
        let grandchild = child.join("grandchild");
        std::fs::create_dir_all(&grandchild).unwrap();

        let mut event_loop = test_event_loop();

        event_loop
            .add_watch(
                WatchPath::from_parts(child.clone(), PathBuf::from("reported-child")),
                recursive_watch(),
            )
            .expect("watch child recursively under its own spelling");
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .expect("watch root recursively");

        let reported = |event_loop: &EventLoop, path: &Path| {
            let watch = event_loop.watches.get(path).expect("watch");
            watch.metadata.reported_path.clone()
        };
        assert_eq!(reported(&event_loop, &root), root);
        assert_eq!(reported(&event_loop, &child), Path::new("reported-child"));
        assert_eq!(
            reported(&event_loop, &grandchild),
            Path::new("reported-child/grandchild")
        );

        event_loop.remove_watch(root.clone()).expect("unwatch root");

        assert_eq!(
            reported(&event_loop, &grandchild),
            Path::new("reported-child/grandchild")
        );
    }

    #[test]
    fn late_create_event_keeps_the_spelling_of_a_watch_added_since() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().to_path_buf();
        let child = root.join("child");
        let grandchild = child.join("grandchild");

        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .expect("watch root recursively");
        std::fs::create_dir_all(&grandchild).unwrap();
        event_loop
            .add_watch(
                WatchPath::from_parts(child.clone(), PathBuf::from("reported-child")),
                recursive_watch(),
            )
            .expect("watch child before its create event is handled");

        event_loop.handle_inotify();

        let watch = event_loop.watches.get(&grandchild).expect("grandchild");
        assert_eq!(
            watch.metadata.reported_path,
            Path::new("reported-child/grandchild")
        );
        let created: Vec<_> = rx
            .try_iter()
            .map(Result::unwrap)
            .filter(|event| event.kind.is_create())
            .collect();
        assert_eq!(
            created,
            [Event::new(EventKind::Create(CreateKind::Folder)).add_path(child)]
        );
    }

    #[test]
    fn rewatching_carved_out_child_does_not_restore_parent_recursive_state() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().to_path_buf();
        let child = root.join("child");
        let grandchild = child.join("grandchild");
        std::fs::create_dir_all(&grandchild).unwrap();

        let mut event_loop = test_event_loop();

        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .expect("watch root recursively");
        event_loop
            .remove_watch(child.clone())
            .expect("carve out child");
        event_loop
            .add_watch(WatchPath::new(&child).unwrap(), non_recursive_watch())
            .expect("watch child non-recursively");
        event_loop
            .add_watch(
                WatchPath::from_parts(child.clone(), PathBuf::from("reported-child")),
                non_recursive_watch(),
            )
            .expect("rewatch child non-recursively");

        let child_watch = event_loop.watches.get(&child).expect("child watch");
        assert!(child_watch.metadata.is_user_watch);
        assert!(!event_loop.user_roots[child.as_path()].is_recursive);
        assert!(!child_watch.metadata.is_recursive);
        assert_eq!(
            child_watch.metadata.reported_path,
            PathBuf::from("reported-child")
        );
        assert!(!event_loop.watches.contains_key(&grandchild));
    }

    /// Runs manually.
    ///
    /// * Save actual value of the limit: `MAX_USER_WATCHES=$(sysctl -n fs.inotify.max_user_watches)`
    /// * Run the test.
    /// * Set the limit to 0: `sudo sysctl fs.inotify.max_user_watches=0` while test is running
    /// * Wait for the test to complete
    /// * Restore the limit `sudo sysctl fs.inotify.max_user_watches=$MAX_USER_WATCHES`
    #[test]
    #[ignore = "requires changing sysctl fs.inotify.max_user_watches while test is running"]
    fn recursive_watch_calls_handler_if_creating_a_file_raises_max_files_watch() {
        use std::time::Duration;

        let tmpdir = tempfile::tempdir().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let (proc_changed_tx, proc_changed_rx) = std::sync::mpsc::channel();
        let proc_path = Path::new("/proc/sys/fs/inotify/max_user_watches");
        let mut watcher = INotifyWatcher::new(
            move |result: Result<Event>| match result {
                Ok(event) => {
                    if event.paths.first().is_some_and(|path| path == proc_path) {
                        proc_changed_tx.send(()).unwrap();
                    }
                }
                Err(e) => tx.send(e).unwrap(),
            },
            Config::default(),
        )
        .unwrap();

        watcher
            .watch(tmpdir.path(), RecursiveMode::Recursive)
            .unwrap();
        watcher
            .watch(proc_path, RecursiveMode::NonRecursive)
            .unwrap();

        // give the time to set the limit
        proc_changed_rx
            .recv_timeout(Duration::from_secs(30))
            .unwrap();

        let child_dir = tmpdir.path().join("child");
        std::fs::create_dir(child_dir).unwrap();

        let result = rx.recv_timeout(Duration::from_millis(500));

        assert!(
            matches!(
                &result,
                Ok(Error {
                    kind: ErrorKind::MaxFilesWatch,
                    paths: _,
                })
            ),
            "expected {:?}, found: {:#?}",
            ErrorKind::MaxFilesWatch,
            result
        );
    }

    /// https://github.com/notify-rs/notify/issues/678
    #[test]
    fn race_condition_on_unwatch_and_pending_events_with_deleted_descriptor() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let (tx, rx) = mpsc::channel();
        // Use CORE to exclude access events - the parallel threads opening files
        // would otherwise flood the queue with OPEN events causing Rescan
        let mut inotify = INotifyWatcher::new(
            move |e: Result<Event>| {
                let e = match e {
                    Ok(e) if e.paths.is_empty() => e,
                    Ok(_) | Err(_) => return,
                };
                let _ = tx.send(e);
            },
            Config::default().with_event_kinds(EventKindMask::CORE),
        )
        .expect("inotify creation");

        let dir_path = tmpdir.path();
        let file_path = dir_path.join("foo");
        std::fs::File::create(&file_path).unwrap();

        let stop = Arc::new(AtomicBool::new(false));

        let handles: Vec<_> = (0..available_parallelism().unwrap().get().max(4))
            .map(|_| {
                let file_path = file_path.clone();
                let stop = stop.clone();
                thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let _ = std::fs::File::open(&file_path).unwrap();
                    }
                })
            })
            .collect();

        let non_recursive = RecursiveMode::NonRecursive;
        for _ in 0..(handles.len() * 4) {
            inotify.watch(dir_path, non_recursive).unwrap();
            inotify.unwatch(dir_path).unwrap();
        }

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        handles
            .into_iter()
            .for_each(|handle| handle.join().ok().unwrap_or_default());

        drop(inotify);

        let events: Vec<_> = rx.into_iter().map(|e| format!("{e:?}")).collect();

        const LOG_LEN: usize = 10;
        let events_len = events.len();
        assert!(
            events.is_empty(),
            "expected no events without path, but got {events_len}. first 10: {:#?}",
            &events[..LOG_LEN.min(events_len)]
        );
    }

    /// https://github.com/notify-rs/notify/issues/709
    #[test]
    fn remove_a_subdir_in_a_recursively_watched_parent() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let subdirectory_path_1 = tmpdir.path().join("subdir");
        let subdirectory_path_2 = subdirectory_path_1.join("nested");
        std::fs::create_dir(&subdirectory_path_1).expect("unable to create a subdir");
        std::fs::create_dir(&subdirectory_path_2).expect("unable to create a nested dir");

        let mut watcher =
            INotifyWatcher::new(|_| (), Config::default()).expect("unable to create watcher");
        watcher
            .watch(tmpdir.path(), RecursiveMode::Recursive)
            .expect("unable to watch");
        std::fs::remove_dir_all(&subdirectory_path_1).expect("unable to remove a subdir");
        let unwatch_result = watcher.unwatch(tmpdir.path());

        assert!(
            matches!(unwatch_result, Ok(())),
            "error: {unwatch_result:#?}"
        );
    }

    // FIXME: FreeBSD 15.1 does not generate IN_IGNORED unless IN_DELETE_SELF was requested.
    // Remove this ignore once CI uses a release containing the fix:
    // https://cgit.freebsd.org/src/commit/?id=242c9c86c8cad6aa29bc1af9161d4f0eec45f29b
    #[cfg_attr(
        target_os = "freebsd",
        ignore = "FreeBSD 15.1 does not generate IN_IGNORED unconditionally"
    )]
    #[test]
    fn ignored_event_removes_watch_when_remove_events_are_filtered_out() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let root = tmpdir.path().to_path_buf();
        let child = root.join("child");
        std::fs::create_dir(&child).expect("create child");

        // Recursive setup still installs a watch for `child`, but the parent does not receive a
        // DELETE event with this mask. IGNORED is therefore the only cleanup signal and must be
        // handled independently of the user-visible event filter.
        let config = Config::default().with_event_kinds(EventKindMask::MODIFY_DATA);
        let mut event_loop = test_event_loop_with_config(&config);
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .expect("watch recursively");

        let child_descriptor = event_loop
            .watches
            .get(&child)
            .expect("child watch")
            .watch_descriptor
            .clone();

        std::fs::remove_dir(&child).expect("remove child");
        event_loop.handle_inotify();

        assert!(event_loop.watches.contains_key(&root));
        assert!(
            !event_loop.watches.contains_key(&child),
            "IGNORED must remove the stale child watch"
        );
        assert!(
            !event_loop.paths.contains_key(&child_descriptor),
            "IGNORED must remove the stale descriptor-to-path mapping"
        );
    }

    #[test]
    fn duplicate_watch_removals_are_coalesced() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let path = tmpdir.path().to_path_buf();
        let mut event_loop = test_event_loop();
        event_loop
            .add_watch(WatchPath::new(&path).unwrap(), non_recursive_watch())
            .expect("add_watch");

        // DELETE may queue a normal removal before DELETE_SELF or IGNORED confirms that the
        // kernel already removed the same descriptor. Keep one entry with the stronger mode.
        let mut queued = std::collections::BTreeMap::new();
        for removal in [
            super::WatchRemoval::WithOsCall,
            super::WatchRemoval::DescriptorAlreadyRemoved,
        ] {
            super::queue_watch_removal(&path, None, &event_loop.watches, &mut queued, removal);
        }

        assert_eq!(
            queued.into_iter().collect::<Vec<_>>(),
            vec![(path, super::WatchRemoval::DescriptorAlreadyRemoved)]
        );
    }

    #[test]
    fn deleting_parent_still_removes_live_moved_out_descendant_descriptor() {
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let root = tmpdir.path().join("root");
        let child = root.join("child");
        let moved_child = tmpdir.path().join("moved-child");
        std::fs::create_dir_all(&child).expect("create watched tree");

        // Excluding rename/remove events deliberately leaves the moved child's old path in the
        // recursive bookkeeping until deleting the root triggers descriptor cleanup. Unlike the
        // deleted root descriptor, the descriptor follows the moved child and remains live.
        let config = Config::default().with_event_kinds(EventKindMask::MODIFY_DATA);
        let mut event_loop = test_event_loop_with_config(&config);
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .expect("watch recursively");

        let child_descriptor = event_loop
            .watches
            .get(&child)
            .expect("child watch")
            .watch_descriptor
            .clone();

        std::fs::rename(&child, &moved_child).expect("move child out of watched root");
        std::fs::remove_dir(&root).expect("remove watched root");
        event_loop.handle_inotify();

        assert!(event_loop.watches.is_empty());
        assert!(event_loop.paths.is_empty());

        // EINVAL here is expected because recursive cleanup should already have issued rm_watch
        // for the live moved-out descendant. Skipping every syscall for a deleted root would leak
        // that descriptor even though the local maps looked empty.
        let remove_result = event_loop
            .inotify
            .as_mut()
            .expect("inotify instance")
            .watches()
            .remove(child_descriptor);
        assert_eq!(
            remove_result.unwrap_err().raw_os_error(),
            Some(libc::EINVAL),
            "the moved-out descendant descriptor must already have been removed"
        );
    }

    #[test]
    fn unmount_event_maps_to_remove_other_with_unmount_info() {
        let path = PathBuf::from("/tmp/notify-unmount");
        let event = super::unmount_event(path.clone());

        assert_eq!(event.kind, EventKind::Remove(RemoveKind::Other));
        assert_eq!(event.paths, vec![path]);
        assert_eq!(event.info(), Some("unmount"));
    }

    #[test]
    fn descriptor_removed_cleanup_removes_internal_state() {
        let tmpdir = tempfile::tempdir().unwrap();
        let watched = tmpdir.path().join("watched");
        std::fs::create_dir(&watched).unwrap();

        let mut event_loop = test_event_loop();

        event_loop
            .add_watch(WatchPath::new(&watched).unwrap(), non_recursive_watch())
            .expect("add_watch");

        event_loop
            .remove_watch_without_root_os_call(watched.clone())
            .expect("remove_watch_without_root_os_call");

        let result = event_loop.remove_watch(watched.clone());
        assert!(
            matches!(
                result,
                Err(Error {
                    kind: ErrorKind::WatchNotFound,
                    ..
                })
            ),
            "expected WatchNotFound, got: {result:?}"
        );
    }

    #[test]
    fn create_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher_with_all_events();
        watcher.watch_recursively(&tmpdir);

        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("create");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&path).create_file(),
            expected(&path).access_open_any(),
            expected(&path).access_close_write(),
        ]);
    }

    #[test]
    fn write_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher_with_all_events();

        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("create");

        watcher.watch_recursively(&tmpdir);
        std::fs::write(&path, b"123").expect("write");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&path).access_open_any(),
            expected(&path).modify_data_any().multiple(),
            expected(&path).access_close_write(),
        ]);
    }

    #[test]
    fn chmod_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();

        let path = tmpdir.path().join("entry");
        let file = std::fs::File::create_new(&path).expect("create");
        let mut permissions = file.metadata().expect("metadata").permissions();
        permissions.set_readonly(true);

        watcher.watch_recursively(&tmpdir);
        file.set_permissions(permissions).expect("set_permissions");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([expected(&path).modify_meta_any()]);
    }

    #[test]
    fn rename_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();

        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("create");

        watcher.watch_recursively(&tmpdir);
        let new_path = tmpdir.path().join("renamed");

        std::fs::rename(&path, &new_path).expect("rename");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&path).rename_from(),
            expected(&new_path).rename_to(),
            expected([path, new_path]).rename_both(),
        ])
        .ensure_trackers_len(1);
    }

    #[test]
    fn delete_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();
        let file = tmpdir.path().join("file");
        std::fs::write(&file, "").expect("write");

        watcher.watch_nonrecursively(&tmpdir);

        std::fs::remove_file(&file).expect("remove");

        rx.wait_ordered_exact([expected(&file).remove_file()]);
    }

    #[test]
    fn delete_self_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();
        let file = tmpdir.path().join("file");
        std::fs::write(&file, "").expect("write");

        watcher.watch_nonrecursively(&file);

        std::fs::remove_file(&file).expect("remove");

        rx.wait_ordered_exact([
            expected(&file).modify_meta_any(),
            expected(&file).remove_file(),
        ]);
    }

    #[test]
    fn delete_self_dir() {
        let tmpdir = testdir();
        let dir = tmpdir.path().join("dir");
        std::fs::create_dir(&dir).expect("create");

        let (mut watcher, mut rx) = watcher();
        watcher.watch_nonrecursively(&dir);

        std::fs::remove_dir(&dir).expect("remove");

        rx.wait_unordered([expected(&dir).remove_folder()]);
    }

    #[test]
    fn non_recursive_directory_symlink_reports_target_events() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = channel_with_config::<INotifyWatcher>(
            ChannelConfig::default()
                .with_watcher_config(Config::default().with_follow_symlinks(false)),
        );
        let target = tmpdir.path().join("target");
        let link = tmpdir.path().join("link");
        std::fs::create_dir(&target).expect("create directory");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        watcher.watch_nonrecursively(&link);

        let child = target.join("child");
        let reported_child = link.join("child");
        std::fs::File::create_new(&child).expect("create child");
        rx.wait_ordered([expected(&reported_child).create_file()]);
        std::fs::remove_file(&child).expect("remove child");
        rx.wait_ordered([expected(&reported_child).remove_file()]);
        std::fs::remove_dir(&target).expect("remove directory");
        rx.wait_ordered([expected(&link).remove_folder()]);
    }

    #[test]
    fn non_recursive_file_symlink_reports_target_events() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = channel_with_config::<INotifyWatcher>(
            ChannelConfig::default()
                .with_watcher_config(Config::default().with_follow_symlinks(false)),
        );
        let target = tmpdir.path().join("target");
        let link = tmpdir.path().join("link");
        std::fs::write(&target, "").expect("create file");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        watcher.watch_nonrecursively(&link);

        std::fs::write(&target, "changed").expect("write file");
        rx.wait_ordered([expected(&link).modify_data_any()]);
        std::fs::remove_file(&target).expect("remove file");
        rx.wait_ordered([expected(&link).remove_file()]);
    }

    fn check_batch_with_bounded_event_handler(batch_size: usize) {
        let tmpdir = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmpdir.path().join("child")).unwrap();
        let path = tmpdir.path().to_path_buf();
        let (events_tx, events_rx) = mpsc::sync_channel(1);
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut watcher = INotifyWatcher::new(
                move |event| {
                    let _ = events_tx.send(event);
                },
                Config::default(),
            )
            .unwrap();
            let operations = (0..batch_size)
                .map(|_| crate::PathOp::watch_recursive(&path))
                .collect();
            finished_tx.send(watcher.update_paths(operations)).unwrap();
        });

        // The recursive scan produces access events without any concurrent file changes.
        // Wait for registration to finish before consuming events, as callers do at startup.
        let result = finished_rx.recv_timeout(Duration::from_secs(5));
        let event = events_rx.recv_timeout(Duration::from_secs(5));
        // Release a blocked handler before asserting, so a regression cannot hang the test.
        drop(events_rx);
        worker.join().unwrap();

        result
            .expect("batch must finish before events are consumed")
            .expect("watch paths");
        event
            .expect("deliver buffered event to the original handler")
            .expect("event without error");
    }

    #[test]
    fn batch_reply_precedes_bounded_event_delivery() {
        check_batch_with_bounded_event_handler(1);
    }

    #[test]
    fn large_batch_reply_precedes_bounded_event_delivery() {
        check_batch_with_bounded_event_handler(1025);
    }

    #[test]
    fn batch_reply_disconnect_does_not_report_unattempted_operations() {
        let poll = mio::Poll::new().expect("create poll");
        let (channel, requests) = mpsc::channel();
        let mut watcher = INotifyWatcher {
            channel,
            waker: Arc::new(
                mio::Waker::new(poll.registry(), super::MESSAGE).expect("create waker"),
            ),
        };
        let receiver = thread::spawn(move || {
            let Ok(super::EventLoopMsg::UpdatePaths(_, reply)) = requests.recv() else {
                panic!("expected batch request");
            };
            drop(reply);
            assert!(matches!(requests.recv(), Ok(super::EventLoopMsg::Shutdown)));
        });

        let result = watcher.update_paths(vec![
            crate::PathOp::watch_non_recursive("first"),
            crate::PathOp::watch_non_recursive("second"),
        ]);
        drop(watcher);
        receiver.join().expect("request receiver finished");

        let error = result.expect_err("batch reply was disconnected");
        assert!(error.origin.is_none());
        assert!(error.remaining.is_empty());
    }

    #[test]
    fn batch_watch_preserves_symlink_dereference_setting() {
        let tmpdir = testdir();
        let link = tmpdir.path().join("link");
        std::os::unix::fs::symlink(tmpdir.path().join("missing"), &link).expect("create symlink");
        let (mut watcher, mut rx) = watcher();

        let mut operations: Vec<_> = (0..2048)
            .map(|_| crate::PathOp::watch_non_recursive(tmpdir.path()))
            .collect();
        operations.push(crate::PathOp::Watch(
            link.clone(),
            non_recursive_watch().with_dereference_symlinks(false),
        ));
        watcher
            .watcher
            .update_paths(operations)
            .expect("watch dangling symlink without dereferencing it");
        std::fs::remove_file(&link).expect("remove symlink");
        rx.wait_ordered([expected(&link).remove_file()]);
    }

    #[test]
    fn create_write_overwrite() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher_with_all_events();
        let overwritten_file = tmpdir.path().join("overwritten_file");
        let overwriting_file = tmpdir.path().join("overwriting_file");
        std::fs::write(&overwritten_file, "123").expect("write1");

        watcher.watch_nonrecursively(&tmpdir);

        std::fs::File::create(&overwriting_file).expect("create");
        std::fs::write(&overwriting_file, "321").expect("write2");
        std::fs::rename(&overwriting_file, &overwritten_file).expect("rename");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&overwriting_file).create_file(),
            expected(&overwriting_file).access_open_any(),
            expected(&overwriting_file).access_close_write(),
            expected(&overwriting_file).access_open_any(),
            expected(&overwriting_file).modify_data_any().multiple(),
            expected(&overwriting_file).access_close_write(),
            expected(&overwriting_file).rename_from(),
            expected(&overwritten_file).rename_to(),
            expected([overwriting_file, overwritten_file]).rename_both(),
        ])
        .ensure_trackers_len(1);
    }

    #[test]
    fn create_dir() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();
        watcher.watch_recursively(&tmpdir);

        let path = tmpdir.path().join("entry");
        std::fs::create_dir(&path).expect("create");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([expected(&path).create_folder()]);
    }

    #[test]
    fn chmod_dir() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();

        let path = tmpdir.path().join("entry");
        std::fs::create_dir(&path).expect("create_dir");
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_readonly(true);

        watcher.watch_recursively(&tmpdir);
        std::fs::set_permissions(&path, permissions).expect("set_permissions");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&path).access_open_any().optional(),
            expected(&path).modify_meta_any(),
            expected(&path).modify_meta_any(),
        ]);
    }

    #[test]
    fn rename_dir() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();

        let path = tmpdir.path().join("entry");
        let new_path = tmpdir.path().join("new_path");
        std::fs::create_dir(&path).expect("create_dir");

        watcher.watch_recursively(&tmpdir);

        std::fs::rename(&path, &new_path).expect("rename");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&path).access_open_any().optional(),
            expected(&path).rename_from(),
            expected(&new_path).rename_to(),
            expected([path, new_path]).rename_both(),
        ])
        .ensure_trackers_len(1);
    }

    #[test]
    fn delete_dir() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();

        let path = tmpdir.path().join("entry");
        std::fs::create_dir(&path).expect("create_dir");

        watcher.watch_recursively(&tmpdir);
        std::fs::remove_dir(&path).expect("remove");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&path).access_open_any().optional(),
            expected(&path).remove_folder(),
        ]);
    }

    #[test]
    fn rename_dir_twice() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();

        let path = tmpdir.path().join("entry");
        let new_path = tmpdir.path().join("new_path");
        let new_path2 = tmpdir.path().join("new_path2");
        std::fs::create_dir(&path).expect("create_dir");

        watcher.watch_recursively(&tmpdir);
        std::fs::rename(&path, &new_path).expect("rename");
        std::fs::rename(&new_path, &new_path2).expect("rename2");

        // Use wait_ordered (not _exact) because we may get extra events
        // due to directory traversal/rescan on rename
        rx.wait_ordered([
            expected(&path).access_open_any().optional(),
            expected(&path).rename_from(),
            expected(&new_path).rename_to(),
            expected([&path, &new_path]).rename_both(),
            expected(&new_path).access_open_any().optional(),
            expected(&new_path).rename_from(),
            expected(&new_path2).rename_to(),
            expected([&new_path, &new_path2]).rename_both(),
        ])
        .ensure_trackers_len(2);
    }

    #[test]
    fn move_out_of_watched_dir() {
        let tmpdir = testdir();
        let subdir = tmpdir.path().join("subdir");
        let (mut watcher, mut rx) = watcher();

        let path = subdir.join("entry");
        std::fs::create_dir_all(&subdir).expect("create_dir_all");
        std::fs::File::create_new(&path).expect("create");

        watcher.watch_recursively(&subdir);
        let new_path = tmpdir.path().join("entry");

        std::fs::rename(&path, &new_path).expect("rename");

        // With ALL events, we may get Access events on the directory.
        // Skip Access events to find the rename event.
        let event = loop {
            let event = rx.recv();
            if !matches!(event.kind, EventKind::Access(_)) {
                break event;
            }
        };
        let tracker = event.attrs.tracker();
        assert_eq!(event, expected(&path).rename_from());
        assert!(tracker.is_some(), "tracker is none: {event:#?}");
    }

    #[test]
    fn create_write_write_rename_write_remove() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher_with_all_events();

        let file1 = tmpdir.path().join("entry");
        let file2 = tmpdir.path().join("entry2");
        std::fs::File::create_new(&file2).expect("create file2");
        let new_path = tmpdir.path().join("renamed");

        watcher.watch_recursively(&tmpdir);
        std::fs::write(&file1, "123").expect("write 1");
        std::fs::write(&file2, "321").expect("write 2");
        std::fs::rename(&file1, &new_path).expect("rename");
        std::fs::write(&new_path, b"1").expect("write 3");
        std::fs::remove_file(&new_path).expect("remove");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&file1).create_file(),
            expected(&file1).access_open_any(),
            expected(&file1).modify_data_any().multiple(),
            expected(&file1).access_close_write(),
            expected(&file2).access_open_any(),
            expected(&file2).modify_data_any().multiple(),
            expected(&file2).access_close_write(),
            expected(&file1).access_open_any().optional(),
            expected(&file1).rename_from(),
            expected(&new_path).rename_to(),
            expected([&file1, &new_path]).rename_both(),
            expected(&new_path).access_open_any(),
            expected(&new_path).modify_data_any().multiple(),
            expected(&new_path).access_close_write(),
            expected(&new_path).remove_file(),
        ]);
    }

    #[test]
    fn rename_twice() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();

        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("create");

        watcher.watch_recursively(&tmpdir);
        let new_path1 = tmpdir.path().join("renamed1");
        let new_path2 = tmpdir.path().join("renamed2");

        std::fs::rename(&path, &new_path1).expect("rename1");
        std::fs::rename(&new_path1, &new_path2).expect("rename2");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&path).access_open_any().optional(),
            expected(&path).rename_from(),
            expected(&new_path1).rename_to(),
            expected([&path, &new_path1]).rename_both(),
            expected(&new_path1).access_open_any().optional(),
            expected(&new_path1).rename_from(),
            expected(&new_path2).rename_to(),
            expected([&new_path1, &new_path2]).rename_both(),
        ])
        .ensure_trackers_len(2);
    }

    #[test]
    fn set_file_mtime() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();

        let path = tmpdir.path().join("entry");
        let file = std::fs::File::create_new(&path).expect("create");

        watcher.watch_recursively(&tmpdir);

        file.set_modified(
            std::time::SystemTime::now()
                .checked_sub(Duration::from_secs(60 * 60))
                .expect("time"),
        )
        .expect("set_time");

        // With ALL events, we may get Access events on the directory.
        // Skip Access events to find the modify event.
        let event = loop {
            let event = rx.recv();
            if !matches!(event.kind, EventKind::Access(_)) {
                break event;
            }
        };
        // Linux and FreeBSD classify this modification differently.
        assert_eq!(event, expected(&path).modify());
    }

    #[test]
    fn write_file_non_recursive_watch() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher_with_all_events();

        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("create");

        watcher.watch_nonrecursively(&path);

        std::fs::write(&path, b"123").expect("write");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&path).access_open_any(),
            expected(&path).modify_data_any().multiple(),
            expected(&path).access_close_write(),
        ]);
    }

    #[test]
    fn watch_recursively_then_unwatch_child_stops_events_from_child() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher_with_all_events();

        let subdir = tmpdir.path().join("subdir");
        let file = subdir.join("file");
        std::fs::create_dir(&subdir).expect("create");

        watcher.watch_recursively(&tmpdir);

        std::fs::File::create(&file).expect("create");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&subdir).access_open_any().optional(),
            expected(&file).create_file(),
            expected(&file).access_open_any(),
            expected(&file).access_close_write(),
        ]);

        watcher.watcher.unwatch(&subdir).expect("unwatch");

        std::fs::write(&file, b"123").expect("write");

        std::fs::remove_dir_all(&subdir).expect("remove_dir_all");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&subdir).access_open_any().optional(),
            expected(&subdir).remove_folder(),
        ]);
    }

    #[test]
    fn write_to_a_hardlink_pointed_to_the_watched_file_triggers_an_event() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher_with_all_events();

        let subdir = tmpdir.path().join("subdir");
        let file = subdir.join("file");
        let hardlink = tmpdir.path().join("hardlink");

        std::fs::create_dir(&subdir).expect("create");
        std::fs::write(&file, "").expect("file");
        std::fs::hard_link(&file, &hardlink).expect("hardlink");

        watcher.watch_nonrecursively(&file);

        std::fs::write(&hardlink, "123123").expect("write to the hard link");

        // Use wait_ordered (not _exact) because with ALL events we may get
        // directory access events that are timing-dependent
        rx.wait_ordered([
            expected(&file).access_open_any(),
            expected(&file).modify_data_any().multiple(),
            expected(&file).access_close_write(),
        ]);
    }

    // FreeBSD reports writes through any hard link to the watched inode.
    #[test]
    #[cfg(not(target_os = "freebsd"))]
    fn write_to_a_hardlink_pointed_to_the_file_in_the_watched_dir_doesnt_trigger_an_event() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();

        let subdir = tmpdir.path().join("subdir");
        let file = subdir.join("file");
        let hardlink = tmpdir.path().join("hardlink");

        std::fs::create_dir(&subdir).expect("create");
        std::fs::write(&file, "").expect("file");
        std::fs::hard_link(&file, &hardlink).expect("hardlink");

        watcher.watch_nonrecursively(&subdir);

        std::fs::write(&hardlink, "123123").expect("write to the hard link");

        // With ALL events, we may get Access events on the watched directory.
        // Filter those out - we only care about non-Access events on the file.
        let events: Vec<_> = rx
            .iter()
            .filter(|e| !matches!(e.kind, EventKind::Access(_)))
            .collect();
        assert!(events.is_empty(), "unexpected events: {events:#?}");
    }

    #[test]
    fn recursive_creation() {
        let tmpdir = testdir();
        let nested1 = tmpdir.path().join("1");
        let nested2 = tmpdir.path().join("1/2");
        let nested3 = tmpdir.path().join("1/2/3");
        let nested4 = tmpdir.path().join("1/2/3/4");
        let nested5 = tmpdir.path().join("1/2/3/4/5");
        let nested6 = tmpdir.path().join("1/2/3/4/5/6");
        let nested7 = tmpdir.path().join("1/2/3/4/5/6/7");
        let nested8 = tmpdir.path().join("1/2/3/4/5/6/7/8");
        let nested9 = tmpdir.path().join("1/2/3/4/5/6/7/8/9");

        let (mut watcher, mut rx) = watcher();

        watcher.watch_recursively(&tmpdir);

        std::fs::create_dir_all(&nested9).expect("create_dir_all");
        rx.wait_ordered([
            expected(&nested1).create_folder(),
            expected(&nested2).create_folder(),
            expected(&nested3).create_folder(),
            expected(&nested4).create_folder(),
            expected(&nested5).create_folder(),
            expected(&nested6).create_folder(),
            expected(&nested7).create_folder(),
            expected(&nested8).create_folder(),
            expected(&nested9).create_folder(),
        ]);
    }

    #[test]
    fn recursive_creation_before_event_processing() {
        let tmpdir = testdir();
        let root = tmpdir.path();
        let reported = PathBuf::from("reported-root");
        let deepest = root.join("1/2/3");
        let reported_deepest = reported.join("1/2/3");
        let file = deepest.join("file");

        let (tx, rx) = mpsc::channel();
        let inotify = super::inotify_sys::Inotify::init().unwrap();
        let mut event_loop = EventLoop::new(
            inotify,
            Box::new(move |event: Result<Event>| {
                if event.as_ref().is_ok_and(|event| {
                    event.kind == EventKind::Create(CreateKind::Folder)
                        && event.paths == [reported_deepest.clone()]
                }) {
                    // A handler can write into a directory as soon as its synthesized event arrives.
                    std::fs::write(&file, b"content").unwrap();
                }
                tx.send(event).unwrap();
            }),
            &Config::default(),
        )
        .unwrap();
        event_loop
            .add_watch(
                WatchPath::from_parts(root.to_path_buf(), reported.clone()),
                recursive_watch(),
            )
            .unwrap();

        // Finish creating the tree before handling the root's CREATE, so the descendants
        // have no native events. This also makes an exact count meaningful here.
        std::fs::create_dir_all(&deepest).unwrap();
        event_loop.handle_inotify();
        let created: Vec<_> = rx
            .try_iter()
            .map(Result::unwrap)
            .filter(|event| event.kind.is_create())
            .collect();
        assert_eq!(
            created,
            ["1", "1/2", "1/2/3"].map(|path| {
                Event::new(EventKind::Create(CreateKind::Folder)).add_path(reported.join(path))
            })
        );

        event_loop.handle_inotify();
        let created: Vec<_> = rx
            .try_iter()
            .map(Result::unwrap)
            .filter(|event| event.kind.is_create())
            .collect();
        assert_eq!(
            created,
            [
                Event::new(EventKind::Create(CreateKind::File))
                    .add_path(reported.join("1/2/3/file"))
            ]
        );
    }

    #[test]
    fn recursive_creation_and_move_in_same_batch() {
        for create_first in [true, false] {
            let tmpdir = testdir();
            let root = tmpdir.path().join("root");
            let staging = tmpdir.path().join("staging");
            let created = root.join("created");
            let moved = root.join("moved");
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir_all(staging.join("child/grandchild")).unwrap();

            let (mut event_loop, rx) = test_event_loop_with_events();
            event_loop
                .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
                .unwrap();
            let create = || std::fs::create_dir_all(created.join("child/grandchild")).unwrap();
            let move_in = || std::fs::rename(&staging, &moved).unwrap();
            if create_first {
                create();
                move_in();
            } else {
                move_in();
                create();
            }

            event_loop.handle_inotify();
            let events: Vec<_> = rx.try_iter().map(Result::unwrap).collect();
            let creations: Vec<_> = events
                .iter()
                .filter(|event| event.kind.is_create())
                .cloned()
                .collect();
            assert_eq!(
                creations,
                [
                    created.clone(),
                    created.join("child"),
                    created.join("child/grandchild")
                ]
                .map(|path| Event::new(EventKind::Create(CreateKind::Folder)).add_path(path))
            );
            assert!(events.iter().any(|event| {
                event.kind == EventKind::Modify(ModifyKind::Name(RenameMode::To))
                    && event.paths == [moved.clone()]
            }));
            for path in [&created, &moved] {
                assert!(
                    event_loop
                        .watches
                        .contains_key(&path.join("child/grandchild"))
                );
            }
        }
    }

    #[test]
    fn non_recursive_creation_does_not_report_descendants() {
        let tmpdir = testdir();
        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(
                WatchPath::new(tmpdir.path()).unwrap(),
                non_recursive_watch(),
            )
            .unwrap();

        std::fs::create_dir_all(tmpdir.path().join("1/2/3")).unwrap();
        event_loop.handle_inotify();
        let created: Vec<_> = rx
            .try_iter()
            .map(Result::unwrap)
            .filter(|event| event.kind.is_create())
            .collect();
        assert_eq!(
            created,
            [Event::new(EventKind::Create(CreateKind::Folder)).add_path(tmpdir.path().join("1"))]
        );
        assert_eq!(event_loop.watches.len(), 1);
    }

    // ============================================================
    // EventKindMask filtering tests
    // ============================================================

    /// Test that CORE config does not produce Access events.
    #[test]
    fn event_kind_mask_core_config_no_access_events() {
        let tmpdir = testdir();
        // Use explicit CORE mask to exclude access events
        let (mut watcher, mut rx) = channel_with_config::<INotifyWatcher>(
            ChannelConfig::default()
                .with_timeout(std::time::Duration::from_secs(1))
                .with_watcher_config(Config::default().with_event_kinds(EventKindMask::CORE)),
        );
        watcher.watch_recursively(&tmpdir);

        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("create");

        // With CORE config, we should only get create event, no access events
        rx.wait_ordered_exact([expected(&path).create_file()])
            .ensure_no_tail();
    }

    /// Test that EventKindMask::ALL config produces Access events.
    #[test]
    fn event_kind_mask_all_config_produces_access_events() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher_with_all_events();
        watcher.watch_recursively(&tmpdir);

        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("create");

        // With ALL config, we should get create + access events
        // Use wait_ordered (not _exact) because we may get directory access events too
        rx.wait_ordered([
            expected(&path).create_file(),
            expected(&path).access_open_any(),
            expected(&path).access_close_write(),
        ]);
    }

    /// Test that CREATE | REMOVE only mask filters out Modify events.
    #[test]
    fn event_kind_mask_create_remove_only_no_modify() {
        let tmpdir = testdir();
        let mask = EventKindMask::CREATE | EventKindMask::REMOVE;
        let (mut watcher, mut rx) = channel_with_config::<INotifyWatcher>(
            ChannelConfig::default()
                .with_timeout(std::time::Duration::from_secs(1))
                .with_watcher_config(Config::default().with_event_kinds(mask)),
        );
        watcher.watch_recursively(&tmpdir);

        let path = tmpdir.path().join("entry");
        std::fs::write(&path, b"123").expect("write");

        // With CREATE | REMOVE mask, we should only get create event, no modify events
        rx.wait_ordered_exact([expected(&path).create_file()])
            .ensure_no_tail();
    }

    /// Test unit tests for event_kind_mask_to_watch_mask helper function.
    #[test]
    fn event_kind_mask_to_watch_mask_core() {
        use super::event_kind_mask_to_watch_mask;

        let mask = EventKindMask::CORE;
        let watch_mask = event_kind_mask_to_watch_mask(mask, false);

        // CORE includes CREATE, REMOVE, MODIFY_DATA, MODIFY_META, MODIFY_NAME
        assert!(watch_mask.intersects(WatchMask::CREATE));
        assert!(watch_mask.intersects(WatchMask::MOVED_TO));
        assert!(watch_mask.intersects(WatchMask::DELETE));
        assert!(watch_mask.intersects(WatchMask::MOVED_FROM));
        assert!(watch_mask.intersects(WatchMask::MODIFY));
        assert!(watch_mask.intersects(WatchMask::ATTRIB));
        assert!(watch_mask.intersects(WatchMask::MOVE_SELF));

        // CORE does NOT include ACCESS (OPEN, CLOSE_WRITE, CLOSE_NOWRITE)
        // Note: CLOSE_WRITE generates Access events, not Modify events
        assert!(!watch_mask.intersects(WatchMask::OPEN));
        assert!(!watch_mask.intersects(WatchMask::CLOSE_WRITE));
        assert!(!watch_mask.intersects(WatchMask::CLOSE_NOWRITE));
    }

    #[test]
    fn event_kind_mask_to_watch_mask_all() {
        use super::event_kind_mask_to_watch_mask;

        let mask = EventKindMask::ALL;
        let watch_mask = event_kind_mask_to_watch_mask(mask, false);

        // ALL includes everything from CORE plus ACCESS
        assert!(watch_mask.intersects(WatchMask::OPEN));
        assert!(watch_mask.intersects(WatchMask::CLOSE_WRITE));
        assert!(watch_mask.intersects(WatchMask::CLOSE_NOWRITE));
    }

    #[test]
    fn event_kind_mask_to_watch_mask_empty() {
        use super::event_kind_mask_to_watch_mask;

        let mask = EventKindMask::empty();
        let watch_mask = event_kind_mask_to_watch_mask(mask, false);

        // Empty mask should produce empty watch mask
        assert!(watch_mask.is_empty());
    }

    #[test]
    fn event_kind_mask_to_watch_mask_access_only() {
        use super::event_kind_mask_to_watch_mask;

        // ACCESS_CLOSE only maps to CLOSE_WRITE (not CLOSE_NOWRITE)
        let mask = EventKindMask::ACCESS_OPEN | EventKindMask::ACCESS_CLOSE;
        let watch_mask = event_kind_mask_to_watch_mask(mask, false);

        assert!(watch_mask.intersects(WatchMask::OPEN));
        assert!(watch_mask.intersects(WatchMask::CLOSE_WRITE));
        assert!(!watch_mask.intersects(WatchMask::CLOSE_NOWRITE));

        // Should NOT have create/modify/remove
        assert!(!watch_mask.intersects(WatchMask::CREATE));
        assert!(!watch_mask.intersects(WatchMask::DELETE));
        assert!(!watch_mask.intersects(WatchMask::MODIFY));
        assert!(!watch_mask.intersects(WatchMask::ATTRIB));
    }

    #[test]
    fn event_kind_mask_to_watch_mask_all_access() {
        use super::event_kind_mask_to_watch_mask;

        // ALL_ACCESS includes OPEN, CLOSE_WRITE, and CLOSE_NOWRITE
        let mask = EventKindMask::ALL_ACCESS;
        let watch_mask = event_kind_mask_to_watch_mask(mask, false);

        assert!(watch_mask.intersects(WatchMask::OPEN));
        assert!(watch_mask.intersects(WatchMask::CLOSE_WRITE));
        assert!(watch_mask.intersects(WatchMask::CLOSE_NOWRITE));
    }

    #[test]
    fn event_kind_mask_to_watch_mask_recursive_includes_create() {
        use super::event_kind_mask_to_watch_mask;

        // Recursive mode includes CREATE|MOVED_TO even without CREATE in mask
        let watch_mask = event_kind_mask_to_watch_mask(EventKindMask::MODIFY_DATA, true);
        assert!(watch_mask.intersects(WatchMask::CREATE));
        assert!(watch_mask.intersects(WatchMask::MOVED_TO));
        assert!(watch_mask.intersects(WatchMask::MODIFY));

        // Empty mask with recursive still includes CREATE|MOVED_TO
        let watch_mask = event_kind_mask_to_watch_mask(EventKindMask::empty(), true);
        assert!(watch_mask.intersects(WatchMask::CREATE));
        assert!(watch_mask.intersects(WatchMask::MOVED_TO));
        assert!(!watch_mask.intersects(WatchMask::MODIFY));

        // Non-recursive mode does not include CREATE when not requested
        let watch_mask = event_kind_mask_to_watch_mask(EventKindMask::MODIFY_DATA, false);
        assert!(!watch_mask.intersects(WatchMask::CREATE));
        assert!(!watch_mask.intersects(WatchMask::MOVED_TO));
        assert!(watch_mask.intersects(WatchMask::MODIFY));
    }

    /// Recursive watches with MODIFY-only mask still track new subdirectories.
    #[test]
    fn recursive_watch_tracks_subdirs_without_create_mask() {
        let tmpdir = testdir();
        let (tx, rx) = mpsc::channel();
        let inotify = super::inotify_sys::Inotify::init().unwrap();
        let mut event_loop = EventLoop::new(
            inotify,
            Box::new(tx),
            &Config::default().with_event_kinds(EventKindMask::MODIFY_DATA),
        )
        .unwrap();
        event_loop
            .add_watch(WatchPath::new(tmpdir.path()).unwrap(), recursive_watch())
            .unwrap();

        let subdir = tmpdir.path().join("1/2/3");
        std::fs::create_dir_all(&subdir).unwrap();
        event_loop.handle_inotify();
        assert!(
            rx.try_iter().next().is_none(),
            "CREATE events must be filtered"
        );

        let file = subdir.join("file.txt");
        std::fs::write(&file, b"hello").unwrap();
        event_loop.handle_inotify();
        let events: Vec<_> = rx.try_iter().map(Result::unwrap).collect();
        assert_eq!(
            events,
            [Event::new(EventKind::Modify(ModifyKind::Data(DataChange::Any))).add_path(file)]
        );
    }

    /// A recursive watch resolves the path it walks, so the flag cannot silence it.
    #[test]
    fn recursive_watch_of_a_symlinked_dir_without_dereference_still_walks() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher_with_data_events();
        let destination = tmpdir.path().join("destination");
        std::fs::create_dir(&destination).expect("create");
        let file = destination.join("file");
        std::fs::write(&file, "").expect("write");
        let link = tmpdir.path().join("link");
        std::os::unix::fs::symlink(&destination, &link).expect("symlink");

        watcher
            .watcher
            .watch_with(&link, recursive_watch().with_dereference_symlinks(false))
            .expect("watch link recursively");

        std::fs::write(&file, "123").expect("write");

        rx.wait_ordered([expected(link.join("file")).modify_data_any().multiple()]);
    }

    // Regression tests for https://github.com/notify-rs/notify/issues/255.
    #[test]
    fn watching_a_dangling_symlink_without_dereference() {
        let tmpdir = tempfile::tempdir().unwrap();
        let link = tmpdir.path().join("link");
        std::os::unix::fs::symlink(tmpdir.path().join("missing"), &link).unwrap();

        let inotify = super::inotify_sys::Inotify::init().unwrap();
        let mut event_loop = EventLoop::new(inotify, Box::new(|_| {}), &Config::default()).unwrap();

        event_loop
            .add_watch(
                WatchPath::new(&link).unwrap(),
                non_recursive_watch().with_dereference_symlinks(false),
            )
            .expect("watch dangling symlink");

        let watch = event_loop.watches.get(&link).expect("link watch");
        assert!(!watch.is_dir);
        assert!(!watch.dereference);
    }

    #[test]
    fn watching_a_dangling_symlink_with_dereference_is_not_found() {
        let tmpdir = tempfile::tempdir().unwrap();
        let link = tmpdir.path().join("link");
        std::os::unix::fs::symlink(tmpdir.path().join("missing"), &link).unwrap();

        let inotify = super::inotify_sys::Inotify::init().unwrap();
        let mut event_loop = EventLoop::new(inotify, Box::new(|_| {}), &Config::default()).unwrap();

        let result = event_loop.add_watch(WatchPath::new(&link).unwrap(), non_recursive_watch());

        assert!(matches!(
            result,
            Err(Error {
                paths: _,
                kind: ErrorKind::PathNotFound
            })
        ))
    }

    #[test]
    fn recursive_watch_of_a_symlink_to_a_file_still_follows_it() {
        let tmpdir = tempfile::tempdir().unwrap();
        let destination = tmpdir.path().join("destination");
        let link = tmpdir.path().join("link");
        std::fs::write(&destination, "").unwrap();
        std::os::unix::fs::symlink(&destination, &link).unwrap();

        let inotify = super::inotify_sys::Inotify::init().unwrap();
        let mut event_loop = EventLoop::new(inotify, Box::new(|_| {}), &Config::default()).unwrap();

        event_loop
            .add_watch(WatchPath::new(&link).unwrap(), recursive_watch())
            .expect("watch link recursively");

        let watch = event_loop.watches.get(&link).expect("link watch");
        assert!(watch.dereference);
    }

    #[test]
    fn a_recursive_walk_stops_at_an_explicit_non_dereferenced_link() {
        let tmpdir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = tmpdir.path().to_path_buf();
        let destination = outside.path().join("destination");
        let nested = destination.join("nested");
        let link = root.join("link");
        std::fs::create_dir_all(&nested).unwrap();
        std::os::unix::fs::symlink(&destination, &link).unwrap();

        let inotify = super::inotify_sys::Inotify::init().unwrap();
        let mut event_loop = EventLoop::new(inotify, Box::new(|_| {}), &Config::default()).unwrap();

        event_loop
            .add_watch(
                WatchPath::new(&link).unwrap(),
                non_recursive_watch().with_dereference_symlinks(false),
            )
            .expect("watch link");
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .expect("watch root recursively");

        let watch = event_loop.watches.get(&link).expect("link watch");
        assert!(!watch.dereference);
        assert!(watch.metadata.is_user_watch);
        assert!(
            !event_loop.watches.contains_key(&link.join("nested")),
            "the recursive walk crossed an explicit non-dereferenced link"
        );
    }

    #[test]
    fn unwatching_a_non_dereferenced_link_lets_the_recursive_watch_walk_it_again() {
        for link_first in [false, true] {
            let tmpdir = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            let root = tmpdir.path().to_path_buf();
            let destination = outside.path().join("destination");
            let nested = destination.join("nested");
            let link = root.join("link");
            std::fs::create_dir_all(&nested).unwrap();
            std::os::unix::fs::symlink(&destination, &link).unwrap();

            let (mut event_loop, rx) = test_event_loop_with_events();
            let link_watch = non_recursive_watch().with_dereference_symlinks(false);
            if link_first {
                event_loop
                    .add_watch(WatchPath::new(&link).unwrap(), link_watch.clone())
                    .unwrap();
            }
            event_loop
                .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
                .unwrap();
            if !link_first {
                event_loop
                    .add_watch(WatchPath::new(&link).unwrap(), link_watch.clone())
                    .unwrap();
            }
            event_loop.unwatch(link.clone()).unwrap();

            std::fs::write(nested.join("file"), b"content").unwrap();
            std::thread::sleep(Duration::from_millis(50));
            event_loop.handle_inotify();
            let paths: Vec<_> = rx
                .try_iter()
                .filter_map(Result::ok)
                .flat_map(|event| event.paths)
                .collect();
            assert!(
                paths.contains(&link.join("nested").join("file")),
                "link_first: {link_first}, {paths:?}"
            );
        }
    }

    /// Returns a directory `root` with a link `root/link` to a directory outside of it, and the
    /// directory `nested` in the target of the link.
    fn root_with_a_link_to_outside() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().join("root");
        let destination = tmpdir.path().join("destination");
        let nested = destination.join("nested");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&destination, &link).unwrap();
        (tmpdir, root, link, nested)
    }

    #[test]
    fn dereferencing_a_link_on_rewatch_lets_the_recursive_watch_walk_it_again() {
        let (_tmpdir, root, link, _nested) = root_with_a_link_to_outside();
        let mut event_loop = test_event_loop();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();
        event_loop
            .add_watch(
                WatchPath::new(&link).unwrap(),
                non_recursive_watch().with_dereference_symlinks(false),
            )
            .unwrap();
        assert!(!event_loop.watches.contains_key(&link.join("nested")));
        event_loop
            .add_watch(WatchPath::new(&link).unwrap(), non_recursive_watch())
            .unwrap();
        assert!(event_loop.watches.contains_key(&link.join("nested")));
    }

    #[test]
    fn unwatching_a_link_watch_does_not_walk_the_link_without_follow_symlinks() {
        let (_tmpdir, root, link, _nested) = root_with_a_link_to_outside();
        let mut event_loop =
            test_event_loop_with_config(&Config::default().with_follow_symlinks(false));
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();
        event_loop
            .add_watch(
                WatchPath::new(&link).unwrap(),
                non_recursive_watch().with_dereference_symlinks(false),
            )
            .unwrap();
        let with_separator = PathBuf::from(format!("{}/", link.display()));
        event_loop.unwatch(with_separator).unwrap();
        assert!(!event_loop.watches.contains_key(&link.join("nested")));
    }

    #[test]
    fn unwatching_a_link_watch_does_not_walk_a_link_loop() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().join("root");
        std::fs::create_dir_all(root.join("a")).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&root, &link).unwrap();

        let mut event_loop = test_event_loop();
        // The walk reports the link as a loop and does not walk it.
        let _ = event_loop.add_watch(WatchPath::new(&root).unwrap(), recursive_watch());
        event_loop
            .add_watch(
                WatchPath::new(&link).unwrap(),
                non_recursive_watch().with_dereference_symlinks(false),
            )
            .unwrap();
        event_loop.unwatch(link.clone()).unwrap();
        assert!(!event_loop.watches.contains_key(&link.join("a")));
    }

    #[test]
    fn unwatching_a_link_watch_does_not_walk_a_loop_below_the_link() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().join("root");
        let outside = tmpdir.path().join("outside");
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        std::os::unix::fs::symlink(&root, outside.join("back")).unwrap();

        let mut event_loop = test_event_loop();
        // The walk reports `link/back` as a loop and does not walk it.
        let _ = event_loop.add_watch(WatchPath::new(&root).unwrap(), recursive_watch());
        assert!(event_loop.watches.contains_key(&link));
        assert!(
            !event_loop
                .watches
                .contains_key(&link.join("back").join("a"))
        );
        event_loop
            .add_watch(
                WatchPath::new(&link).unwrap(),
                non_recursive_watch().with_dereference_symlinks(false),
            )
            .unwrap();
        event_loop.unwatch(link.clone()).unwrap();
        assert!(event_loop.watches.contains_key(&link));
        assert!(
            !event_loop
                .watches
                .contains_key(&link.join("back").join("a"))
        );
    }

    #[test]
    fn unwatching_a_link_watch_walks_the_link_for_a_nested_watch() {
        let tmpdir = tempfile::tempdir().unwrap();
        let outer = tmpdir.path().join("outer");
        let inner = outer.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        let link = inner.join("link");
        std::os::unix::fs::symlink(&outer, &link).unwrap();

        let mut event_loop = test_event_loop();
        // The walk of `outer` reports `inner/link` as a loop. The walk of `inner` follows the
        // link to `outer`, which it has not passed through.
        let _ = event_loop.add_watch(WatchPath::new(&outer).unwrap(), recursive_watch());
        let _ = event_loop.add_watch(WatchPath::new(&inner).unwrap(), recursive_watch());
        assert!(event_loop.watches.contains_key(&link.join("inner")));
        event_loop
            .add_watch(
                WatchPath::new(&link).unwrap(),
                non_recursive_watch().with_dereference_symlinks(false),
            )
            .unwrap();
        event_loop.unwatch(link.clone()).unwrap();
        assert!(event_loop.watches.contains_key(&link.join("inner")));
    }

    #[test]
    fn unwatching_a_watch_on_a_carved_out_directory_keeps_it_carved_out() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().to_path_buf();
        let child = root.join("child");
        std::fs::create_dir_all(child.join("sub")).unwrap();

        let mut event_loop = test_event_loop();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();
        event_loop.unwatch(child.clone()).unwrap();
        event_loop
            .add_watch(WatchPath::new(&child).unwrap(), non_recursive_watch())
            .unwrap();
        event_loop.unwatch(child.clone()).unwrap();
        assert!(!event_loop.watches.contains_key(&child.join("sub")));
    }

    #[test]
    fn recursive_watch_does_not_report_errors_for_an_explicit_non_dereferenced_link() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().to_path_buf();
        let link = root.join("loop");
        std::os::unix::fs::symlink(".", &link).unwrap();

        let (mut event_loop, rx) = test_event_loop_with_events();

        event_loop
            .add_watch(
                WatchPath::new(&link).unwrap(),
                non_recursive_watch().with_dereference_symlinks(false),
            )
            .expect("watch link itself");
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .expect("watch root recursively");

        assert!(event_loop.watches.contains_key(&root));
        let watch = event_loop.watches.get(&link).expect("link remains watched");
        assert!(!watch.dereference);

        // The walk reports errors synchronously from add_watch.
        let errors: Vec<_> = rx.try_iter().filter_map(Result::err).collect();
        assert!(
            errors.is_empty(),
            "the excluded link must not produce walk errors: {errors:?}"
        );
    }

    #[test]
    fn recursive_watch_only_reports_unreadable_links_that_are_not_excluded() {
        let tmpdir = tempfile::tempdir().unwrap();
        let root = tmpdir.path().join("root");
        let destination = tmpdir.path().join("unreadable");
        std::fs::create_dir(&root).unwrap();
        if !unwatchable_dir(&destination) {
            return;
        }
        let excluded = root.join("excluded");
        let included = root.join("included");
        std::os::unix::fs::symlink(&destination, &excluded).unwrap();
        std::os::unix::fs::symlink(&destination, &included).unwrap();

        let (mut event_loop, rx) = test_event_loop_with_events();
        event_loop
            .add_watch(
                WatchPath::new(&excluded).unwrap(),
                non_recursive_watch().with_dereference_symlinks(false),
            )
            .expect("watch excluded link itself");

        let result = event_loop.add_watch(WatchPath::new(&root).unwrap(), recursive_watch());
        make_readable(&destination);
        result.expect("watch root recursively");

        let errors: Vec<_> = rx.try_iter().filter_map(Result::err).collect();
        assert_eq!(errors.len(), 1, "unexpected walk errors: {errors:?}");
        assert_eq!(errors[0].paths, [included]);
        assert!(matches!(
            &errors[0].kind,
            ErrorKind::Io(err) if err.kind() == std::io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn recursive_watch_follows_only_root_symlink_when_follow_symlinks_is_disabled() {
        let tmpdir = tempfile::tempdir().unwrap();
        let destination = tmpdir.path().join("destination");
        std::fs::create_dir_all(destination.join("child")).unwrap();
        std::os::unix::fs::symlink("child", destination.join("alias")).unwrap();
        std::os::unix::fs::symlink(".", destination.join("loop")).unwrap();
        let root = tmpdir.path().join("root");
        std::os::unix::fs::symlink(&destination, &root).unwrap();

        let (tx, rx) = mpsc::channel::<Result<Event>>();
        let inotify = super::inotify_sys::Inotify::init().unwrap();
        let mut event_loop = EventLoop::new(
            inotify,
            Box::new(tx),
            &Config::default().with_follow_symlinks(false),
        )
        .unwrap();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .expect("watch root recursively");

        assert_eq!(event_loop.watches.len(), 2);
        assert!(event_loop.watches[&root].metadata.is_user_watch);
        assert!(event_loop.watches.contains_key(&root.join("child")));
        let errors: Vec<_> = rx.try_iter().filter_map(Result::err).collect();
        assert!(errors.is_empty(), "unexpected walk errors: {errors:?}");
    }

    #[test]
    fn watch_with_dereference_disabled_reports_the_link_not_its_destination() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher_with_data_events();
        let destination = tmpdir.path().join("destination");
        let link = tmpdir.path().join("link");
        std::fs::write(&destination, "").expect("write");
        std::os::unix::fs::symlink(&destination, &link).expect("symlink");

        watcher
            .watcher
            .watch_with(
                &link,
                non_recursive_watch().with_dereference_symlinks(false),
            )
            .expect("watch link");
        watcher.watch_nonrecursively(&destination);

        std::fs::write(&destination, "123").expect("write");

        rx.wait_ordered_exact([expected(&destination).modify_data_any().multiple()]);
    }

    /// Taking a watch off a link must not drop an ancestor's coverage of the destination.
    #[test]
    fn watching_a_link_itself_keeps_the_ancestors_recursive_coverage() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher_with_data_events();
        let destination = tmpdir.path().join("destination");
        std::fs::create_dir(&destination).expect("create");
        let file = destination.join("file");
        std::fs::write(&file, "").expect("write");
        let link = tmpdir.path().join("link");
        std::os::unix::fs::symlink(&destination, &link).expect("symlink");

        watcher.watch_nonrecursively(&link);
        watcher.watch_recursively(tmpdir.path());
        watcher
            .watcher
            .watch_with(
                &link,
                non_recursive_watch().with_dereference_symlinks(false),
            )
            .expect("watch the link itself");

        std::fs::write(&file, "123").expect("write");

        let reported: std::collections::HashSet<_> =
            rx.iter().flat_map(|event| event.paths).collect();
        assert_eq!(
            reported,
            std::collections::HashSet::from([file]),
            "the ancestor recursive watch must keep reporting the destination by its real path"
        );
    }

    /// It does drop it when the link is the only way the tree reaches the destination.
    #[test]
    fn watching_a_link_itself_drops_a_destination_reached_only_through_it() {
        let outside = testdir();
        let destination = outside.path().join("destination");
        let nested = destination.join("nested");
        std::fs::create_dir_all(&nested).expect("create");
        let file = nested.join("file");
        std::fs::write(&file, "").expect("write");

        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher_with_data_events();
        let link = tmpdir.path().join("link");
        std::os::unix::fs::symlink(&destination, &link).expect("symlink");

        watcher.watch_recursively(tmpdir.path());
        watcher
            .watcher
            .watch_with(
                &link,
                non_recursive_watch().with_dereference_symlinks(false),
            )
            .expect("watch the link itself");

        std::fs::write(&file, "123").expect("write");

        let reported: Vec<_> = rx.iter().flat_map(|event| event.paths).collect();
        assert!(
            reported.is_empty(),
            "the destination is still reported after the caller asked not to follow the link: \
             {reported:?}"
        );
    }

    #[test]
    fn unwatching_a_walked_directory_stops_the_outer_watch_below_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let child = root.join("child");
        std::fs::create_dir_all(child.join("grandchild")).unwrap();

        let mut event_loop = test_event_loop();
        event_loop
            .add_watch(WatchPath::new(&root).unwrap(), recursive_watch())
            .unwrap();
        event_loop.remove_watch(child.clone()).unwrap();

        let mut watched: Vec<_> = event_loop.watches.keys().cloned().collect();
        watched.sort();
        assert_eq!(watched, [root.clone()]);
        assert!(event_loop.user_roots.contains_key(root.as_path()));
    }

    #[test]
    fn a_new_directory_below_two_recursive_watches_is_walked_once() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let child = root.join("child");
        std::fs::create_dir_all(&child).unwrap();

        let (mut event_loop, rx) = test_event_loop_with_events();
        for path in [&root, &child] {
            event_loop
                .add_watch(WatchPath::new(path).unwrap(), recursive_watch())
                .unwrap();
        }

        let locked = child.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(50));
            event_loop.handle_inotify();
        }
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

        let errors: Vec<_> = rx.try_iter().filter_map(|event| event.err()).collect();
        assert_eq!(errors.len(), 1, "{errors:?}");
    }

    #[test]
    fn a_walk_root_that_is_no_longer_a_directory_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file");
        std::fs::write(&file, b"content").unwrap();

        // The user watch checked that its root is a directory before the walk starts.
        let barriers = std::collections::HashSet::new();
        let mut walk = super::walk_dirs(
            file.clone(),
            WatchPath::new(&file).unwrap(),
            true,
            &barriers,
            Vec::new(),
            None,
        );
        let err = walk.next().expect("an error for the root").unwrap_err();
        assert!(
            matches!(&err.kind, ErrorKind::Io(err) if err.kind() == std::io::ErrorKind::NotADirectory),
            "{err:?}"
        );
        assert!(walk.next().is_none());
    }

    #[test]
    fn unwatching_a_nested_watch_keeps_the_coverage_of_the_outer_watch() {
        let tmpdir = testdir();
        let child = tmpdir.path().join("child");
        let grandchild = child.join("grandchild");
        std::fs::create_dir_all(&grandchild).expect("create");

        let (mut watcher, mut rx) = watcher();
        watcher.watch_recursively(tmpdir.path());
        watcher.watch_nonrecursively(&child);
        watcher.watcher.unwatch(&child).expect("unwatch child");

        let file = grandchild.join("file");
        std::fs::write(&file, "x").expect("write");
        rx.wait_unordered([expected(&file).create_file()]);
    }
}
