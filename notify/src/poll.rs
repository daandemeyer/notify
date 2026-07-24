//! Generic Watcher implementation based on polling
//!
//! Checks the `watch`ed paths periodically to detect changes. This implementation only uses
//! Rust stdlib APIs and should work on all of the platforms it supports.

use crate::{
    Config, Error, EventHandler, Receiver, RecursiveMode, Sender, WatchFilter, WatchPathConfig,
    Watcher,
    paths::{WatchPath, absolute_path, check_root},
    unbounded,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

pub(crate) enum PollMessage {
    Poll,
    PollAndWait(Sender<crate::Result<()>>),
}

/// Event sent for registered handlers on initial directory scans
pub type ScanEvent = crate::Result<PathBuf>;

/// Handler trait for receivers of [`ScanEvent`].
/// Very much the same as [`EventHandler`], but including the Result.
///
/// See the full example for more information.
pub trait ScanEventHandler: Send + 'static {
    /// Handles an event.
    fn handle_event(&mut self, event: ScanEvent);
}

impl<F> ScanEventHandler for F
where
    F: FnMut(ScanEvent) + Send + 'static,
{
    fn handle_event(&mut self, event: ScanEvent) {
        (self)(event);
    }
}

#[cfg(feature = "crossbeam-channel")]
impl ScanEventHandler for crossbeam_channel::Sender<ScanEvent> {
    fn handle_event(&mut self, event: ScanEvent) {
        let _ = self.send(event);
    }
}

#[cfg(feature = "flume")]
impl ScanEventHandler for flume::Sender<ScanEvent> {
    fn handle_event(&mut self, event: ScanEvent) {
        let _ = self.send(event);
    }
}

impl ScanEventHandler for std::sync::mpsc::Sender<ScanEvent> {
    fn handle_event(&mut self, event: ScanEvent) {
        let _ = self.send(event);
    }
}

impl ScanEventHandler for () {
    fn handle_event(&mut self, _event: ScanEvent) {}
}

use data::{DataBuilder, WatchData};
mod data {
    use crate::{
        EventHandler, RecursiveMode,
        event::{CreateKind, DataChange, Event, EventKind, MetadataKind, ModifyKind, RemoveKind},
        paths::{WatchPath, prune_walk_entry, reported_path},
    };
    use notify_types::event::EventKindMask;
    use std::{
        cell::RefCell,
        collections::HashMap,
        fmt::{self, Debug},
        fs::{File, Metadata},
        io::{self, Read},
        path::{Path, PathBuf},
        time::Instant,
    };
    use walkdir::WalkDir;
    use xxhash_rust::xxh3::Xxh3Default;

    use super::ScanEventHandler;

    const NANOS_PER_SECOND: i128 = 1_000_000_000;

    fn system_time_to_nanos(time: std::time::SystemTime) -> i128 {
        match time.duration_since(std::time::SystemTime::UNIX_EPOCH) {
            Ok(d) => d.as_nanos() as i128,
            Err(e) => -(e.duration().as_nanos() as i128),
        }
    }

    /// Builder for [`WatchData`] & [`PathData`].
    pub(super) struct DataBuilder {
        emitter: EventEmitter,
        scan_emitter: Option<Box<RefCell<dyn ScanEventHandler>>>,
        compare_contents: bool,

        // current timestamp for building Data.
        now: Instant,
    }

    impl DataBuilder {
        pub(super) fn new<F, G>(
            event_handler: F,
            compare_content: bool,
            scan_emitter: Option<G>,
            event_kinds: EventKindMask,
        ) -> Self
        where
            F: EventHandler,
            G: ScanEventHandler,
        {
            let scan_emitter = match scan_emitter {
                None => None,
                Some(v) => {
                    // workaround for a weird type resolution bug when directly going to dyn Trait
                    let intermediate: Box<RefCell<dyn ScanEventHandler>> =
                        Box::new(RefCell::new(v));
                    Some(intermediate)
                }
            };
            Self {
                emitter: EventEmitter::new(event_handler, event_kinds),
                scan_emitter,
                compare_contents: compare_content,
                now: Instant::now(),
            }
        }

        /// Update internal timestamp.
        pub(super) fn update_timestamp(&mut self) {
            self.now = Instant::now();
        }

        /// Create [`WatchData`].
        pub(super) fn build_watch_data(
            &self,
            root: WatchPath,
            is_recursive: bool,
            follow_symlinks: bool,
            watch_filter: crate::WatchFilter,
        ) -> WatchData {
            WatchData::new(self, root, is_recursive, follow_symlinks, watch_filter)
        }

        /// Create [`PathData`].
        fn build_path_data(&self, meta_path: &MetaPath) -> PathData {
            PathData::new(self, meta_path)
        }
    }

    impl Debug for DataBuilder {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("DataBuilder")
                .field("compare_contents", &self.compare_contents)
                .field("now", &self.now)
                .finish()
        }
    }

    #[derive(Debug)]
    pub(super) struct WatchData {
        // config part, won't change.
        root: PathBuf,
        requested_root: PathBuf,
        is_recursive: bool,
        follow_symlinks: bool,
        watch_filter: crate::WatchFilter,

        // current status part.
        all_path_data: HashMap<PathBuf, PathData>,
    }

    impl WatchData {
        /// Scan filesystem and create a new `WatchData`.
        ///
        /// # Side effect
        ///
        /// This function may send event by `data_builder.emitter`.
        fn new(
            data_builder: &DataBuilder,
            root: WatchPath,
            is_recursive: bool,
            follow_symlinks: bool,
            watch_filter: crate::WatchFilter,
        ) -> Self {
            let all_path_data = Self::scan_all_path_data(
                data_builder,
                root.absolute.clone(),
                root.requested.clone(),
                is_recursive,
                follow_symlinks,
                watch_filter.clone(),
                true,
            )
            .collect();

            Self {
                root: root.absolute,
                requested_root: root.requested,
                is_recursive,
                follow_symlinks,
                watch_filter,
                all_path_data,
            }
        }

        /// Rescan filesystem and update this `WatchData`.
        ///
        /// # Side effect
        ///
        /// This function may emit event by `data_builder.emitter`.
        pub(super) fn rescan(&mut self, data_builder: &mut DataBuilder) {
            // scan current filesystem.
            for (path, new_path_data) in Self::scan_all_path_data(
                data_builder,
                self.root.clone(),
                self.requested_root.clone(),
                self.is_recursive,
                self.follow_symlinks,
                self.watch_filter.clone(),
                false,
            ) {
                let event_kind = if let Some(old_path_data) = self.all_path_data.get_mut(&path) {
                    let event_kind =
                        PathData::compare_to_kind(Some(&*old_path_data), Some(&new_path_data));
                    *old_path_data = new_path_data;
                    event_kind
                } else {
                    let event_kind = PathData::compare_to_kind(None, Some(&new_path_data));
                    self.all_path_data.insert(path.clone(), new_path_data);
                    event_kind
                };

                if let Some(event_kind) = event_kind {
                    let event = Event::new(event_kind).add_path(reported_path(
                        &self.root,
                        &self.requested_root,
                        &path,
                    ));
                    data_builder.emitter.emit_ok(event);
                }
            }

            // scan for disappeared paths.
            let mut disappeared_paths = Vec::new();
            for (path, path_data) in self.all_path_data.iter() {
                if path_data.last_check < data_builder.now {
                    disappeared_paths.push(path.clone());
                }
            }

            // remove disappeared paths
            for path in disappeared_paths {
                let old_path_data = self.all_path_data.remove(&path);

                if let Some(event_kind) = PathData::compare_to_kind(old_path_data.as_ref(), None) {
                    let event = Event::new(event_kind).add_path(reported_path(
                        &self.root,
                        &self.requested_root,
                        &path,
                    ));
                    data_builder.emitter.emit_ok(event);
                }
            }
        }

        /// Get all `PathData` by given configuration.
        ///
        /// # Side Effect
        ///
        /// This function may emit some IO Error events by `data_builder.emitter`.
        fn scan_all_path_data(
            data_builder: &'_ DataBuilder,
            root: PathBuf,
            requested_root: PathBuf,
            is_recursive: bool,
            follow_symlinks: bool,
            watch_filter: crate::WatchFilter,
            // whether this is an initial scan, used only for events
            is_initial: bool,
        ) -> impl Iterator<Item = (PathBuf, PathData)> + '_ {
            log::trace!("rescanning {root:?}");
            // WalkDir return only one entry if root is a file (not a folder),
            // so we can use single logic to do the both file & dir's jobs.
            //
            // See: https://docs.rs/walkdir/2.0.1/walkdir/struct.WalkDir.html#method.new
            let mut walk = WalkDir::new(root.clone())
                .follow_links(follow_symlinks)
                .max_depth(Self::dir_scan_depth(is_recursive))
                .into_iter();

            std::iter::from_fn(move || {
                while let Some(entry_res) = walk.next() {
                    let entry = match entry_res {
                        Ok(entry) => entry,
                        Err(err) => {
                            log::warn!("walkdir error scanning {err:?}");

                            if let Some(io_error) = err.io_error() {
                                // clone an io::Error, so we have to create a new one.
                                let new_io_error = io::Error::new(io_error.kind(), err.to_string());
                                data_builder.emitter.emit_io_err(new_io_error, err.path());
                            } else {
                                let crate_err =
                                    crate::Error::new(crate::ErrorKind::Generic(err.to_string()));
                                data_builder.emitter.emit(Err(crate_err));
                            }
                            continue;
                        }
                    };

                    // The scan records an excluded directory, so its creation and removal are
                    // reported as on the other backends, but it does not descend into it. This also
                    // applies to the walk root. `watch_filtered` refuses a root that the filter
                    // rejects, but the target of a symlinked root can change between scans.
                    // The scan does not enter a symlink that it does not follow below the walk
                    // root, so the filter is not called for such a symlink.
                    let excluded = (entry.file_type().is_dir() || entry.depth() == 0)
                        && prune_walk_entry(&mut walk, &watch_filter, &entry);
                    // A symlink that the scan does not follow is recorded with the metadata of the
                    // link, so a new target of the link is reported.
                    let pins_metadata = excluded && entry.file_type().is_dir();

                    let metadata = match entry.metadata() {
                        Ok(metadata) => metadata,
                        Err(e) => {
                            // emit event.
                            data_builder.emitter.emit_io_err(e, Some(entry.into_path()));
                            continue;
                        }
                    };

                    let path = entry.into_path();
                    if is_initial {
                        // emit initial scans
                        if let Some(ref emitter) = data_builder.scan_emitter {
                            emitter.borrow_mut().handle_event(Ok(reported_path(
                                &root,
                                &requested_root,
                                &path,
                            )));
                        }
                    }
                    let meta_path = MetaPath::from_parts_unchecked(path, metadata);
                    let mut data_path = data_builder.build_path_data(&meta_path);
                    if pins_metadata {
                        // Changes inside an excluded directory change its mtime. Comparing the
                        // mtime would report a Modify event for the excluded directory on every
                        // poll, so the scan records a fixed mtime. The hash is a marker value
                        // instead of `None`, so an excluded directory that replaces a file at the
                        // same path still differs from the recorded file and is reported.
                        data_path.mtime = 0;
                        data_path.hash = Some(Self::EXCLUDED_DIR_HASH);
                    }

                    return Some((meta_path.into_path(), data_path));
                }
                None
            })
        }

        /// Marker stored as the content hash of a filter-excluded directory. Excluded
        /// directories all compare equal to each other, so no event is produced while one
        /// stays excluded, but they differ from any real entry that previously held the path.
        const EXCLUDED_DIR_HASH: u64 = u64::MAX;

        fn dir_scan_depth(is_recursive: bool) -> usize {
            if is_recursive { usize::MAX } else { 1 }
        }

        pub(super) fn recursive_mode(&self) -> RecursiveMode {
            if self.is_recursive {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            }
        }

        pub(super) fn requested_root(&self) -> &Path {
            &self.requested_root
        }
    }

    /// Stored data for a one path locations.
    ///
    /// See [`WatchData`] for more detail.
    #[derive(Debug, Clone)]
    struct PathData {
        /// File updated time in nanoseconds since the Unix epoch.
        mtime: i128,

        /// Content's hash value, only available if user request compare file
        /// contents and read successful.
        hash: Option<u64>,

        /// Checked time.
        last_check: Instant,
    }

    impl PathData {
        /// Create a new `PathData`.
        fn new(data_builder: &DataBuilder, meta_path: &MetaPath) -> PathData {
            let metadata = meta_path.metadata();
            let compare_contents = data_builder.compare_contents && metadata.is_file();
            let mut mtime = metadata.modified().map_or(0, system_time_to_nanos);
            if metadata.is_dir() || compare_contents {
                // Child changes update directory mtimes. Preserve the existing second precision for
                // directories to avoid emitting a redundant directory event for every file event.
                // Files with content comparison also retain second precision so changes keep their
                // existing event classification.
                mtime = mtime / NANOS_PER_SECOND * NANOS_PER_SECOND;
            }

            PathData {
                mtime,
                hash: if compare_contents {
                    content_hash(meta_path.path()).ok()
                } else {
                    None
                },

                last_check: data_builder.now,
            }
        }

        fn compare_to_kind(old: Option<&PathData>, new: Option<&PathData>) -> Option<EventKind> {
            match (old, new) {
                (Some(old), Some(new)) => {
                    if new.mtime > old.mtime {
                        Some(EventKind::Modify(ModifyKind::Metadata(
                            MetadataKind::WriteTime,
                        )))
                    } else if new.hash != old.hash {
                        Some(EventKind::Modify(ModifyKind::Data(DataChange::Any)))
                    } else {
                        None
                    }
                }
                (None, Some(_new)) => Some(EventKind::Create(CreateKind::Any)),
                (Some(_old), None) => Some(EventKind::Remove(RemoveKind::Any)),
                (None, None) => None,
            }
        }
    }

    /// Get hash value for the data content in given file `path`.
    pub(super) fn content_hash(path: &Path) -> io::Result<u64> {
        let mut hasher = Xxh3Default::new();
        let mut file = File::open(path)?;
        let mut buf = [0u8; 8 * 1024];

        loop {
            let n = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(len) => len,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };

            hasher.update(&buf[..n]);
        }

        Ok(hasher.digest())
    }

    /// Compose path and its metadata.
    ///
    /// This data structure designed for make sure path and its metadata can be
    /// transferred in consistent way, and may avoid some duplicated
    /// `fs::metadata()` function call in some situations.
    #[derive(Debug)]
    pub(super) struct MetaPath {
        path: PathBuf,
        metadata: Metadata,
    }

    impl MetaPath {
        /// Create `MetaPath` by given parts.
        ///
        /// # Invariant
        ///
        /// User must make sure the input `metadata` are associated with `path`.
        fn from_parts_unchecked(path: PathBuf, metadata: Metadata) -> Self {
            Self { path, metadata }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn metadata(&self) -> &Metadata {
            &self.metadata
        }

        fn into_path(self) -> PathBuf {
            self.path
        }
    }

    /// Thin wrapper for outer event handler, for easy to use.
    struct EventEmitter {
        // Use `RefCell` to make sure `emit()` only need shared borrow of self (&self).
        // Use `Box` to make sure EventEmitter is Sized.
        handler: Box<RefCell<dyn EventHandler>>,
        /// Event kind filter - only events matching this mask are emitted.
        event_kinds: EventKindMask,
    }

    impl EventEmitter {
        fn new<F: EventHandler>(event_handler: F, event_kinds: EventKindMask) -> Self {
            Self {
                handler: Box::new(RefCell::new(event_handler)),
                event_kinds,
            }
        }

        /// Emit single event (errors always pass through).
        fn emit(&self, event: crate::Result<Event>) {
            self.handler.borrow_mut().handle_event(event);
        }

        /// Emit event, filtered by event_kinds mask.
        fn emit_ok(&self, event: Event) {
            // Only emit if the event kind matches the configured mask
            if self.event_kinds.matches(&event.kind) {
                self.emit(Ok(event))
            }
        }

        /// Emit io error event.
        fn emit_io_err<E, P>(&self, err: E, path: Option<P>)
        where
            E: Into<io::Error>,
            P: Into<PathBuf>,
        {
            let e = crate::Error::io(err.into());
            if let Some(path) = path {
                self.emit(Err(e.add_path(path.into())));
            } else {
                self.emit(Err(e));
            }
        }
    }
}

/// Polling based `Watcher` implementation.
///
/// By default scans through all files and checks for changed entries based on their change date.
/// Can also be changed to perform file content change checks.
///
/// See [Config] for more details.
#[derive(Debug)]
pub struct PollWatcher {
    watches: Arc<Mutex<HashMap<PathBuf, WatchData>>>,
    data_builder: Arc<Mutex<DataBuilder>>,
    want_to_stop: Arc<AtomicBool>,
    /// channel to the poll loop
    /// currently used only for manual polling
    message_channel: Sender<PollMessage>,
    delay: Option<Duration>,
    follow_sylinks: bool,
}

impl PollWatcher {
    /// Create a new [`PollWatcher`], configured as needed.
    pub fn new<F: EventHandler>(event_handler: F, config: Config) -> crate::Result<PollWatcher> {
        Self::with_opt::<_, ()>(event_handler, config, None)
    }

    /// Actively poll for changes. Can be combined with a timeout of 0 to perform only manual polling.
    pub fn poll(&self) -> crate::Result<()> {
        self.message_channel
            .send(PollMessage::Poll)
            .map_err(|_| Error::generic("failed to send poll message"))?;
        Ok(())
    }

    /// Actively poll for changes and block until the poll cycle has completed.
    ///
    /// This is primarily useful together with [`Config::with_manual_polling`].
    pub fn poll_blocking(&self) -> crate::Result<()> {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        self.message_channel
            .send(PollMessage::PollAndWait(done_tx))
            .map_err(|_| Error::generic("failed to send poll message"))?;
        done_rx
            .recv()
            .map_err(|_| Error::generic("poll thread disconnected"))?
    }

    /// Returns a sender to initiate changes detection.
    #[cfg(test)]
    pub(crate) fn poll_sender(&self) -> Sender<PollMessage> {
        self.message_channel.clone()
    }

    /// Create a new [`PollWatcher`] with an scan event handler.
    ///
    /// `scan_fallback` is called on the initial scan with all files seen by the pollwatcher.
    pub fn with_initial_scan<F: EventHandler, G: ScanEventHandler>(
        event_handler: F,
        config: Config,
        scan_callback: G,
    ) -> crate::Result<PollWatcher> {
        Self::with_opt(event_handler, config, Some(scan_callback))
    }

    /// create a new [`PollWatcher`] with all options.
    fn with_opt<F: EventHandler, G: ScanEventHandler>(
        event_handler: F,
        config: Config,
        scan_callback: Option<G>,
    ) -> crate::Result<PollWatcher> {
        let data_builder = DataBuilder::new(
            event_handler,
            config.compare_contents(),
            scan_callback,
            config.event_kinds(),
        );

        let (tx, rx) = unbounded::<PollMessage>();

        let poll_watcher = PollWatcher {
            watches: Default::default(),
            data_builder: Arc::new(Mutex::new(data_builder)),
            want_to_stop: Arc::new(AtomicBool::new(false)),
            delay: config.poll_interval(),
            follow_sylinks: config.follow_symlinks(),
            message_channel: tx,
        };

        poll_watcher.run(rx);

        Ok(poll_watcher)
    }

    fn run(&self, rx: Receiver<PollMessage>) {
        let watches = Arc::clone(&self.watches);
        let data_builder = Arc::clone(&self.data_builder);
        let want_to_stop = Arc::clone(&self.want_to_stop);
        let delay = self.delay;

        let _ = thread::Builder::new()
            .name("notify-rs poll loop".to_string())
            .spawn(move || {
                // do an immediate first scan, then sleep `delay` between subsequent scans.
                let mut first_auto_scan = true;

                loop {
                    if want_to_stop.load(Ordering::SeqCst) {
                        break;
                    }

                    let msg = match delay {
                        Some(_delay) if first_auto_scan => {
                            first_auto_scan = false;
                            None
                        }
                        Some(delay) => match rx.recv_timeout(delay) {
                            Ok(msg) => Some(msg),
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        },
                        None => match rx.recv() {
                            Ok(msg) => Some(msg),
                            Err(_) => break,
                        },
                    };

                    // HINT: Make sure always lock in the same order to avoid deadlock.
                    let scan_res = {
                        let mut watches = watches.lock().unwrap_or_else(|e| e.into_inner());
                        let mut data_builder =
                            data_builder.lock().unwrap_or_else(|e| e.into_inner());

                        data_builder.update_timestamp();

                        let vals = watches.values_mut();
                        for watch_data in vals {
                            watch_data.rescan(&mut data_builder);
                        }

                        Ok(())
                    };

                    // Acknowledge poll requests after a poll cycle has finished.
                    if let Some(PollMessage::PollAndWait(done)) = msg {
                        let _ = done.send(scan_res);
                    }
                }
            });
    }

    /// Watch a path location.
    ///
    /// Return `Err(_)` if the path cannot be watched, e.g. because it does not
    /// exist or its metadata cannot be read.
    fn watch_inner(
        &mut self,
        path: &Path,
        recursive_mode: RecursiveMode,
        watch_filter: WatchFilter,
    ) -> crate::Result<()> {
        let watch_path = WatchPath::new(path)?;

        // HINT: Make sure always lock in the same order to avoid deadlock.
        let mut watches = self.watches.lock().unwrap_or_else(|e| e.into_inner());
        let mut data_builder = self.data_builder.lock().unwrap_or_else(|e| e.into_inner());

        // Creating a watch on a path that cannot be stat-ed (e.g. because it
        // does not exist) fails the `poll_watcher.watch(root, ..)` call, so
        // the error is reported to the caller instead of silently skipping
        // the path. `Error::io_watch` maps `io::ErrorKind::NotFound` to
        // `ErrorKind::PathNotFound`, matching the other backends.
        //
        // This is intentionally different from *POLLING* a watch: when a
        // watched path disappears, the existing watch is kept and io errors
        // encountered while scanning are emitted as events instead.
        let path_is_dir = std::fs::metadata(&watch_path.absolute)
            .map_err(|e| Error::io_watch(e).add_path(watch_path.requested.clone()))?
            .is_dir();
        check_root(
            &watch_filter,
            path_is_dir,
            &watch_path.absolute,
            &watch_path.requested,
        )?;

        data_builder.update_timestamp();

        let watch_data = data_builder.build_watch_data(
            watch_path.clone(),
            recursive_mode.is_recursive(),
            self.follow_sylinks,
            watch_filter,
        );

        watches.insert(watch_path.absolute, watch_data);

        Ok(())
    }

    /// Unwatch a path.
    ///
    /// Return `Err(_)` if given path has't be monitored.
    fn unwatch_inner(&mut self, path: &Path) -> crate::Result<()> {
        let path = absolute_path(path)?;

        self.watches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&path)
            .map(|_| ())
            .ok_or_else(crate::Error::watch_not_found)
    }
}

impl Watcher for PollWatcher {
    /// Create a new [`PollWatcher`].
    fn new<F: EventHandler>(event_handler: F, config: Config) -> crate::Result<Self> {
        Self::new(event_handler, config)
    }

    fn watch(&mut self, path: &Path, recursive_mode: RecursiveMode) -> crate::Result<()> {
        self.watch_inner(path, recursive_mode, WatchFilter::accept_all())
    }

    fn watch_with(&mut self, path: &Path, config: WatchPathConfig) -> crate::Result<()> {
        self.watch_inner(path, config.recursive_mode(), config.watch_filter().clone())
    }

    fn unwatch(&mut self, path: &Path) -> crate::Result<()> {
        self.unwatch_inner(path)
    }

    fn watched_paths(&self) -> crate::Result<Vec<(PathBuf, RecursiveMode)>> {
        let watches = self.watches.lock().unwrap_or_else(|e| e.into_inner());
        Ok(watches
            .values()
            .map(|watch| (watch.requested_root().to_path_buf(), watch.recursive_mode()))
            .collect())
    }

    fn kind() -> crate::WatcherKind {
        crate::WatcherKind::PollWatcher
    }
}

impl Drop for PollWatcher {
    fn drop(&mut self) {
        self.want_to_stop.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::PollWatcher;
    use crate::{Config, RecursiveMode, Watcher, test::*};

    fn watcher() -> (TestWatcher<PollWatcher>, Receiver) {
        poll_watcher_channel()
    }

    fn manual_watcher() -> (
        PollWatcher,
        std::sync::mpsc::Receiver<crate::Result<notify_types::event::Event>>,
    ) {
        let (tx, rx) = std::sync::mpsc::channel();
        let watcher =
            PollWatcher::new(tx, Config::default().with_manual_polling()).expect("create watcher");
        (watcher, rx)
    }

    fn drain(
        rx: &std::sync::mpsc::Receiver<crate::Result<notify_types::event::Event>>,
    ) -> Vec<notify_types::event::Event> {
        rx.try_iter().filter_map(|r| r.ok()).collect()
    }

    /// Dates a path's write time an hour ahead. With `compare_contents`, `PathData::mtime` of a
    /// file has whole-second resolution and is compared before the content hash, so a change to
    /// an entry is reported as `Metadata(WriteTime)` unless its recorded write time is one that
    /// nothing happening afterwards can exceed.
    fn set_write_time_ahead(path: &std::path::Path) {
        let ahead = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open to set write time")
            .set_modified(ahead)
            .expect("set write time");
    }

    /// Blocks until the wall clock crosses into the next second. `PathData::mtime` of a
    /// directory has whole-second resolution, so a test that needs an mtime comparison of a
    /// directory to be able to fire must straddle a second boundary.
    fn wait_for_next_second() {
        let second = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_secs()
        };
        let start = second();
        while second() == start {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn poll_watcher_is_send_and_sync() {
        fn check<T: Send + Sync>() {}
        check::<PollWatcher>();
    }

    #[test]
    fn watch_nonexistent_path_returns_path_not_found() {
        let tmpdir = testdir();
        let path = tmpdir.path().join("does_not_exist");

        let mut watcher = PollWatcher::new(|_| {}, Config::default()).expect("create watcher");
        let err = watcher
            .watch(&path, RecursiveMode::Recursive)
            .expect_err("watching a nonexistent path must return an error");

        assert!(matches!(err.kind, crate::ErrorKind::PathNotFound));
        assert_eq!(err.paths, vec![path]);

        let watched = watcher.watched_paths().expect("list watched paths");
        assert!(
            watched.is_empty(),
            "a failed watch must not be registered, got {watched:?}"
        );
    }

    #[test]
    fn watch_existing_paths_succeed() {
        let tmpdir = testdir();
        let file = tmpdir.path().join("entry");
        std::fs::write(&file, "contents").expect("write file");

        let mut watcher = PollWatcher::new(|_| {}, Config::default()).expect("create watcher");
        watcher
            .watch(&file, RecursiveMode::NonRecursive)
            .expect("watch existing file");
        watcher
            .watch(tmpdir.path(), RecursiveMode::Recursive)
            .expect("watch existing directory");

        let watched = watcher.watched_paths().expect("list watched paths");
        assert_eq!(watched.len(), 2);
    }

    #[test]
    fn detects_subsecond_mtime_change_without_content_hashing() {
        use std::{
            fs,
            sync::mpsc,
            time::{Duration, SystemTime},
        };

        use crate::event::{EventKind, MetadataKind, ModifyKind};

        let tmpdir = testdir();
        let path = tmpdir.path().join("entry");
        fs::write(&path, "initial").expect("write initial contents");

        let current_second = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("current time must be after the Unix epoch")
            .as_secs();
        let initial_mtime = SystemTime::UNIX_EPOCH
            + Duration::from_secs(current_second)
            + Duration::from_millis(100);
        fs::File::options()
            .write(true)
            .open(&path)
            .expect("open file to set initial mtime")
            .set_modified(initial_mtime)
            .expect("set initial mtime");

        let (tx, rx) = mpsc::channel();
        let mut watcher =
            PollWatcher::new(tx, Config::default().with_manual_polling()).expect("create watcher");
        watcher
            .watch(tmpdir.path(), RecursiveMode::Recursive)
            .expect("watch directory");

        fs::write(&path, "updated").expect("write updated contents");
        fs::File::options()
            .write(true)
            .open(&path)
            .expect("open file to set updated mtime")
            .set_modified(initial_mtime + Duration::from_millis(100))
            .expect("set updated mtime");
        watcher.poll().expect("poll for changes");

        let event = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("receive subsecond mtime change")
            .expect("watch event must not be an error");
        assert_eq!(event.paths, vec![path]);
        assert_eq!(
            event.kind,
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime))
        );
    }

    #[cfg(unix)]
    #[test]
    fn detects_subsecond_symlink_mtime_changes() {
        use std::{os::unix::fs::symlink, sync::mpsc};

        use nix::{
            fcntl::AT_FDCWD,
            sys::{
                stat::{UtimensatFlags, utimensat},
                time::TimeSpec,
            },
        };

        use crate::event::{Event, EventKind, MetadataKind, ModifyKind};

        for compare_contents in [false, true] {
            let tmpdir = testdir();
            let path = tmpdir.path().join("link");
            symlink("missing", &path).expect("create dangling symlink");

            let set_mtime = |nanos| {
                utimensat(
                    AT_FDCWD,
                    &path,
                    &TimeSpec::UTIME_OMIT,
                    &TimeSpec::new(1_700_000_000, nanos),
                    UtimensatFlags::NoFollowSymlink,
                )
                .expect("set symlink mtime");
            };
            set_mtime(100_000_000);

            let (tx, rx) = mpsc::channel();
            let config = Config::default()
                .with_manual_polling()
                .with_follow_symlinks(false)
                .with_compare_contents(compare_contents);
            let mut watcher = PollWatcher::new(tx, config).expect("create watcher");
            watcher
                .watch(tmpdir.path(), RecursiveMode::Recursive)
                .expect("watch directory");

            for nanos in [200_000_000, 300_000_000] {
                set_mtime(nanos);
                watcher.poll_blocking().expect("poll for changes");

                let events = rx
                    .try_iter()
                    .collect::<crate::Result<Vec<_>>>()
                    .expect("watch events must not be errors");
                assert_eq!(
                    events,
                    vec![
                        Event::new(EventKind::Modify(ModifyKind::Metadata(
                            MetadataKind::WriteTime,
                        )))
                        .add_path(path.clone())
                    ],
                    "compare_contents={compare_contents}, nanos={nanos}"
                );
            }

            watcher.poll_blocking().expect("poll without changes");
            assert!(rx.try_recv().is_err(), "unchanged symlink emitted an event");
        }
    }

    #[test]
    fn watch_operations_recover_poisoned_mutexes() {
        use std::{path::Path, sync::Arc};

        let tmpdir = testdir();
        let mut watcher = PollWatcher::new(|_| {}, Config::default().with_manual_polling())
            .expect("create watcher");

        let watches = Arc::clone(&watcher.watches);
        let data_builder = Arc::clone(&watcher.data_builder);
        std::thread::spawn(move || {
            let _watches = watches.lock().expect("lock watches");
            let _data_builder = data_builder.lock().expect("lock data builder");
            panic!("poison polling mutexes for test");
        })
        .join()
        .expect_err("poisoning thread must panic");

        watcher
            .watch(tmpdir.path(), RecursiveMode::Recursive)
            .expect("watch after poisoning");
        assert_eq!(
            watcher.watched_paths().expect("list after poisoning"),
            vec![(tmpdir.path().to_path_buf(), RecursiveMode::Recursive)]
        );
        watcher.poll_blocking().expect("poll after poisoning");
        watcher
            .unwatch(tmpdir.path())
            .expect("unwatch after poisoning");
        assert!(watcher.watched_paths().unwrap().is_empty());

        // Recovering a poisoned mutex still reports missing watches as errors.
        let result = watcher.unwatch_inner(Path::new("/path/that/is/not/watched"));
        assert!(result.is_err());
    }

    #[test]
    fn watched_paths_reflect_watch_and_unwatch() {
        let tmpdir = testdir();
        let dir_a = tmpdir.path().join("a");
        let dir_b = tmpdir.path().join("b");
        std::fs::create_dir(&dir_a).expect("create dir a");
        std::fs::create_dir(&dir_b).expect("create dir b");

        let mut watcher = PollWatcher::new(|_| {}, Config::default()).expect("create watcher");

        watcher
            .watch(&dir_a, RecursiveMode::Recursive)
            .expect("watch dir a");
        watcher
            .watch(&dir_b, RecursiveMode::NonRecursive)
            .expect("watch dir b");

        let watched = watcher.watched_paths().expect("list watched paths");
        assert!(watched.contains(&(
            dir_a.canonicalize().expect("canonicalize dir a"),
            RecursiveMode::Recursive,
        )));
        assert!(watched.contains(&(
            dir_b.canonicalize().expect("canonicalize dir b"),
            RecursiveMode::NonRecursive,
        )));

        watcher.unwatch(&dir_a).expect("unwatch dir a");

        let watched = watcher
            .watched_paths()
            .expect("list watched paths after unwatch");
        assert!(!watched.contains(&(
            dir_a.canonicalize().expect("canonicalize dir a"),
            RecursiveMode::Recursive,
        )));
        assert!(watched.contains(&(
            dir_b.canonicalize().expect("canonicalize dir b"),
            RecursiveMode::NonRecursive,
        )));
    }

    #[test]
    fn rewatching_same_path_replaces_recursive_mode() {
        let tmpdir = testdir();
        let root = tmpdir.path().canonicalize().expect("canonicalize root");

        let mut watcher = PollWatcher::new(|_| {}, Config::default()).expect("create watcher");

        watcher
            .watch(tmpdir.path(), RecursiveMode::Recursive)
            .expect("watch recursively");
        watcher
            .watch(tmpdir.path(), RecursiveMode::NonRecursive)
            .expect("watch non-recursively");

        let watched = watcher.watched_paths().expect("list watched paths");
        assert!(watched.contains(&(root.clone(), RecursiveMode::NonRecursive)));
        assert!(!watched.contains(&(root.clone(), RecursiveMode::Recursive)));
        assert_eq!(
            watched.iter().filter(|(path, _mode)| path == &root).count(),
            1
        );

        watcher.unwatch(tmpdir.path()).expect("unwatch");
        let watched = watcher.watched_paths().expect("list watched paths");
        assert!(!watched.iter().any(|(path, _mode)| path == &root));
    }

    #[test]
    fn create_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();
        watcher.watch_recursively(&tmpdir);

        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("Unable to create");

        rx.sleep_until_parent_contains(&path);
        rx.sleep_until_exists(&path);
        rx.sleep_until_walkdir_returns_set(tmpdir.path(), [&path]);

        rx.wait_unordered_exact([
            expected(&path).create_any(),
            expected(tmpdir.path()).modify_meta_mtime().optional(),
        ]);
    }

    #[test]
    fn create_dir() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();
        watcher.watch_recursively(&tmpdir);

        let path = tmpdir.path().join("entry");
        std::fs::create_dir(&path).expect("Unable to create");

        rx.sleep_until_parent_contains(&path);
        rx.sleep_until_exists(&path);
        rx.sleep_until_walkdir_returns_set(tmpdir.path(), [&path]);

        rx.wait_unordered_exact([
            expected(&path).create_any(),
            expected(tmpdir.path()).modify_meta_mtime().optional(),
        ]);
    }

    #[test]
    fn modify_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();
        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("Unable to create");

        rx.sleep_until_parent_contains(&path);
        rx.sleep_until_exists(&path);
        rx.sleep_until_walkdir_returns_set(tmpdir.path(), [&path]);

        set_write_time_ahead(&path);
        watcher.watch_recursively(&tmpdir);

        std::fs::write(&path, b"123").expect("Unable to write");

        assert!(
            rx.sleep_until(|| std::fs::read_to_string(&path).is_ok_and(|content| content == "123")),
            "the file wasn't modified"
        );
        rx.wait_ordered_exact([expected(&path).modify_data_any()]);
    }

    #[test]
    fn remove_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();
        let path = tmpdir.path().join("entry");
        std::fs::File::create_new(&path).expect("Unable to create");

        rx.sleep_until_parent_contains(&path);
        rx.sleep_until_exists(&path);
        rx.sleep_until_walkdir_returns_set(tmpdir.path(), [&path]);

        watcher.watch_recursively(&tmpdir);

        std::fs::remove_file(&path).expect("Unable to remove");

        rx.sleep_while_exists(&path);
        rx.sleep_while_parent_contains(&path);
        rx.sleep_until_walkdir_returns_set::<&str>(tmpdir.path(), []);

        rx.wait_unordered_exact([
            expected(&path).remove_any(),
            expected(tmpdir.path()).modify_meta_mtime().optional(),
        ]);
    }

    #[test]
    fn rename_file() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();
        let path = tmpdir.path().join("entry");
        let new_path = tmpdir.path().join("new_entry");
        std::fs::File::create_new(&path).expect("Unable to create");

        rx.sleep_until_parent_contains(&path);
        rx.sleep_until_exists(&path);
        rx.sleep_until_walkdir_returns_set(tmpdir.path(), [&path]);

        watcher.watch_recursively(&tmpdir);

        std::fs::rename(&path, &new_path).expect("Unable to remove");

        rx.sleep_while_exists(&path);
        rx.sleep_until_exists(&new_path);

        rx.sleep_while_parent_contains(&path);
        rx.sleep_until_parent_contains(&new_path);

        rx.sleep_until_walkdir_returns_set(tmpdir.path(), [&new_path]);

        rx.wait_unordered_exact([
            expected(&path).remove_any(),
            expected(&new_path).create_any(),
            expected(tmpdir.path()).modify_meta_mtime().optional(),
        ]);
    }

    #[test]
    fn create_write_overwrite() {
        let tmpdir = testdir();
        let (mut watcher, mut rx) = watcher();
        let overwritten_file = tmpdir.path().join("overwritten_file");
        let overwriting_file = tmpdir.path().join("overwriting_file");
        std::fs::write(&overwritten_file, "123").expect("write1");

        rx.sleep_until_parent_contains(&overwritten_file);
        rx.sleep_until_exists(&overwritten_file);
        rx.sleep_until_walkdir_returns_set(tmpdir.path(), [overwritten_file.clone()]);

        set_write_time_ahead(&overwritten_file);

        watcher.watch_nonrecursively(&tmpdir);

        std::fs::File::create(&overwriting_file).expect("create");
        std::fs::write(&overwriting_file, "321").expect("write2");
        std::fs::rename(&overwriting_file, &overwritten_file).expect("rename");

        rx.sleep_while_exists(&overwriting_file);
        rx.sleep_while_parent_contains(&overwriting_file);
        rx.sleep_until_walkdir_returns_set(tmpdir.path(), [overwritten_file.clone()]);

        assert!(
            rx.sleep_until(
                || std::fs::read_to_string(&overwritten_file).is_ok_and(|cnt| cnt == "321")
            ),
            "file {overwritten_file:?} was not replaced"
        );

        rx.wait_unordered([expected(&overwritten_file).modify_data_any()]);
    }

    // `root` rejects `excluded`, and the nested watch reports the directory below it.
    #[test]
    fn a_watch_inside_an_excluded_directory_reports_its_events() {
        use crate::Watcher;

        let tmpdir = testdir();
        let root = tmpdir.path();
        let inner = root.join("excluded").join("inner");
        std::fs::create_dir_all(&inner).expect("create inner");

        let (mut watcher, rx) = manual_watcher();
        watcher
            .watch_filtered(
                root,
                crate::RecursiveMode::Recursive,
                reject_name("excluded"),
            )
            .expect("watch root");
        watcher
            .watch(&inner, crate::RecursiveMode::Recursive)
            .expect("watch inner");
        let _ = drain(&rx);

        let file = inner.join("file");
        let hidden = root.join("excluded").join("hidden");
        std::fs::write(&file, "data").expect("write file");
        std::fs::write(&hidden, "data").expect("write hidden");
        watcher.poll_blocking().expect("poll");

        let events = drain(&rx);
        assert!(events.iter().any(|e| e.paths.contains(&file)), "{events:?}");
        assert!(
            !events.iter().any(|e| e.paths.contains(&hidden)),
            "{events:?}"
        );
    }

    #[test]
    fn rejected_root_preserves_existing_watch() {
        use crate::{ErrorKind, WatchFilter, Watcher};

        let tmpdir = testdir();
        let root = tmpdir.path();

        let (mut watcher, _rx) = manual_watcher();
        watcher
            .watch(root, crate::RecursiveMode::Recursive)
            .expect("watch");
        let before = watcher.watched_paths().expect("watched");

        let rejecting = root.to_path_buf();
        let result = watcher.watch_filtered(
            root,
            crate::RecursiveMode::Recursive,
            WatchFilter::with_filter(move |p: &std::path::Path| p != rejecting.as_path()),
        );

        assert!(
            matches!(result, Err(ref e) if matches!(e.kind, ErrorKind::PathExcluded)),
            "watching a rejected root must fail with PathExcluded: {result:?}"
        );
        assert_eq!(
            watcher.watched_paths().expect("watched"),
            before,
            "a failed rewatch must leave existing watches unchanged"
        );
    }

    #[test]
    fn watch_filter_does_not_apply_to_files() {
        use crate::Watcher;

        let tmpdir = testdir();
        let root = tmpdir.path();
        // The file exists before the watch, so it is in the first scan. The assertion below then
        // tests the comparison of recorded state. A new file would be found by the scan, which
        // never applies the filter to files.
        let seen = root.join("seen.txt");
        std::fs::write(&seen, "data").expect("write file");

        // `compare_contents` detects the modification from the content hash. With
        // `compare_contents`, the mtime of a file has whole-second resolution, so a test that
        // relies on it fails under load when two steps happen in the same second.
        let (tx, rx) = std::sync::mpsc::channel();
        let config = Config::default()
            .with_manual_polling()
            .with_compare_contents(true);
        let mut watcher = PollWatcher::new(tx, config).expect("create watcher");
        watcher
            .watch_filtered(
                root,
                crate::RecursiveMode::Recursive,
                reject_name("seen.txt"),
            )
            .expect("watch filtered");
        let _ = drain(&rx);

        // The filter would reject this file if it were a directory. The scan has to keep
        // comparing the file, or later changes to it are not reported.
        std::fs::write(&seen, "changed").expect("modify file");
        watcher.poll_blocking().expect("poll");

        let events = drain(&rx);
        assert!(
            events.iter().any(|e| e.paths.contains(&seen)),
            "the filter gates directories only; file events must still be delivered: {events:?}"
        );

        // A file that the filter would reject is reported when it is created.
        let fresh = root.join("fresh-seen.txt");
        std::fs::write(&fresh, "data").expect("write fresh file");
        watcher.poll_blocking().expect("poll 2");
        let events = drain(&rx);
        assert!(
            events.iter().any(|e| e.paths.contains(&fresh)),
            "a newly created matching file must be reported: {events:?}"
        );
    }

    #[test]
    fn excluded_directory_own_events_are_reported() {
        use crate::Watcher;

        let tmpdir = testdir();
        let root = tmpdir.path();

        let (mut watcher, rx) = manual_watcher();
        watcher
            .watch_filtered(
                root,
                crate::RecursiveMode::Recursive,
                reject_name("excluded"),
            )
            .expect("watch filtered");

        let excluded = root.join("excluded");
        std::fs::create_dir(&excluded).expect("create excluded");
        std::fs::write(excluded.join("inside.txt"), "data").expect("write inside excluded");
        watcher.poll_blocking().expect("poll");

        let events = drain(&rx);
        assert!(
            events
                .iter()
                .any(|e| e.kind.is_create() && e.paths.contains(&excluded)),
            "the excluded directory's own creation must be reported: {events:?}"
        );
        assert!(
            events.iter().all(|e| e
                .paths
                .iter()
                .all(|p| !p.starts_with(&excluded) || *p == excluded)),
            "events leaked from inside the excluded directory: {events:?}"
        );

        std::fs::remove_dir_all(&excluded).expect("remove excluded");
        watcher.poll_blocking().expect("poll 2");
        let events = drain(&rx);
        assert!(
            events
                .iter()
                .any(|e| e.kind.is_remove() && e.paths.contains(&excluded)),
            "the excluded directory's own removal must be reported: {events:?}"
        );
    }

    // The scan does not enter a symlink that it does not follow, so the filter is not called for
    // the symlink. walkdir only keeps a listing for an entry that it enters. Skipping the contents
    // of the symlink would drop the listing of the parent instead, together with the siblings that
    // the scan has not reached yet.
    #[cfg(unix)]
    #[test]
    fn an_unfollowed_symlink_is_not_filtered() {
        use crate::Watcher;

        let tmpdir = testdir();
        let root = tmpdir.path();
        let excluded = root.join("excluded");
        std::fs::create_dir(&excluded).expect("create excluded");
        // The scan does not sort, so the position of any one link in readdir order is
        // arbitrary. Interleave the creations: whether the filesystem reports entries in
        // creation order or reverse creation order, a link then precedes a sibling that has
        // not been yielded yet, and discarding the parent's listing drops it from the scan.
        let siblings: Vec<_> = (0..32)
            .map(|i| root.join(format!("sib{i:02}.txt")))
            .collect();
        for (i, sibling) in siblings.iter().enumerate() {
            std::os::unix::fs::symlink(&excluded, root.join(format!("link{i:02}")))
                .expect("symlink");
            std::fs::write(sibling, "data").expect("write sibling");
        }

        let filtered_links = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let filter = crate::WatchFilter::with_filter({
            let filtered_links = filtered_links.clone();
            move |path: &std::path::Path| {
                if path.is_symlink() {
                    filtered_links.lock().unwrap().push(path.to_path_buf());
                }
                path.file_name() != Some(std::ffi::OsStr::new("excluded"))
            }
        });
        let (tx, rx) = std::sync::mpsc::channel();
        let config = Config::default()
            .with_manual_polling()
            .with_follow_symlinks(false)
            .with_compare_contents(true);
        let mut watcher = PollWatcher::new(tx, config).expect("create watcher");
        watcher
            .watch_filtered(root, crate::RecursiveMode::Recursive, filter)
            .expect("watch filtered");
        let _ = drain(&rx);

        for sibling in &siblings {
            std::fs::write(sibling, "changed").expect("modify sibling");
        }
        watcher.poll_blocking().expect("poll");

        let events = drain(&rx);
        let reported: Vec<_> = siblings
            .iter()
            .filter(|s| events.iter().any(|e| e.paths.contains(s)))
            .collect();
        assert_eq!(
            reported.len(),
            siblings.len(),
            "pruning the symlink dropped siblings from the scan; reported {reported:?} of \
             {siblings:?}"
        );
        assert!(filtered_links.lock().unwrap().is_empty());
    }

    // An unfollowed symlink to an excluded directory is not a directory to the scan, so its
    // own metadata is compared. A new target changes that metadata.
    #[cfg(unix)]
    #[test]
    fn retargeting_an_unfollowed_link_to_an_excluded_directory_is_reported() {
        use crate::Watcher;

        let tmpdir = testdir();
        let root = tmpdir.path();
        std::fs::create_dir(root.join("excluded1")).expect("create excluded1");
        std::fs::create_dir(root.join("excluded2")).expect("create excluded2");
        let link = root.join("link");
        std::os::unix::fs::symlink(root.join("excluded1"), &link).expect("symlink");

        let (tx, rx) = std::sync::mpsc::channel();
        let config = Config::default()
            .with_manual_polling()
            .with_follow_symlinks(false);
        let mut watcher = PollWatcher::new(tx, config).expect("create watcher");
        watcher
            .watch_filtered(
                root,
                crate::RecursiveMode::Recursive,
                crate::WatchFilter::with_filter(|path: &std::path::Path| {
                    !path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with("excluded"))
                }),
            )
            .expect("watch filtered");
        let _ = drain(&rx);

        wait_for_next_second();
        std::fs::remove_file(&link).expect("remove link");
        std::os::unix::fs::symlink(root.join("excluded2"), &link).expect("retarget link");
        watcher.poll_blocking().expect("poll");

        let events = drain(&rx);
        assert!(
            events.iter().any(|event| event.paths.contains(&link)),
            "a new target of the link must be reported: {events:?}"
        );
    }

    // The walk root itself is descended into even when it is an unfollowed symlink, because
    // walkdir follows root links by default. Pruning must therefore still skip at depth 0, or
    // the excluded target is scanned under the link's name.
    #[cfg(unix)]
    #[test]
    fn symlink_root_repointed_to_an_excluded_directory_is_pruned() {
        use crate::Watcher;

        let tmpdir = testdir();
        let root = tmpdir.path();
        let allowed = root.join("allowed");
        let excluded = root.join("excluded");
        std::fs::create_dir(&allowed).expect("create allowed");
        std::fs::create_dir(&excluded).expect("create excluded");
        let link = root.join("link");
        std::os::unix::fs::symlink(&allowed, &link).expect("symlink");

        let (tx, rx) = std::sync::mpsc::channel();
        let config = Config::default()
            .with_manual_polling()
            .with_follow_symlinks(false);
        let mut watcher = PollWatcher::new(tx, config).expect("create watcher");
        // Watching through the link is allowed: it resolves to a directory the filter accepts.
        watcher
            .watch_filtered(
                &link,
                crate::RecursiveMode::Recursive,
                reject_name("excluded"),
            )
            .expect("watch filtered");
        let _ = drain(&rx);

        // Point the link at the excluded directory. The next scan must exclude the walk root.
        std::fs::remove_file(&link).expect("remove link");
        std::os::unix::fs::symlink(&excluded, &link).expect("repoint symlink");
        std::fs::write(excluded.join("secret.txt"), "x").expect("write secret");
        watcher.poll_blocking().expect("poll");

        let events = drain(&rx);
        assert!(
            events
                .iter()
                .all(|e| !e.paths.iter().any(|p| p.starts_with(&link) && *p != link)),
            "the excluded target was scanned under the link's name: {events:?}"
        );
    }

    // A rewatch that fails says so, and leaves the previous watch and its filter in place.
    #[test]
    fn failed_rewatch_of_a_vanished_path_keeps_the_watch() {
        use crate::Watcher;

        let tmpdir = testdir();
        let target = tmpdir.path().join("target");
        std::fs::create_dir(&target).expect("create target");

        let (mut watcher, _rx) = manual_watcher();
        watcher
            .watch(&target, crate::RecursiveMode::Recursive)
            .expect("watch");
        std::fs::remove_dir_all(&target).expect("remove target");

        let error = watcher
            .watch_filtered(
                &target,
                crate::RecursiveMode::Recursive,
                reject_name("excluded"),
            )
            .expect_err("the path is gone");
        assert!(matches!(error.kind, crate::ErrorKind::PathNotFound));
        assert_eq!(watcher.watched_paths().expect("watched").len(), 1);
    }

    // The creation of an excluded directory is reported when it replaces a file at the same
    // path. The recorded state of an excluded directory has to differ from that of the file.
    #[test]
    fn file_replaced_by_excluded_directory_is_reported() {
        use crate::Watcher;

        let tmpdir = testdir();
        let root = tmpdir.path();
        let path = root.join("excluded");
        std::fs::write(&path, "data").expect("write file");

        let (mut watcher, rx) = manual_watcher();
        watcher
            .watch_filtered(
                root,
                crate::RecursiveMode::Recursive,
                reject_name("excluded"),
            )
            .expect("watch filtered");
        let _ = drain(&rx);

        std::fs::remove_file(&path).expect("remove file");
        std::fs::create_dir(&path).expect("create excluded dir");
        watcher.poll_blocking().expect("poll");

        let events = drain(&rx);
        assert!(
            events.iter().any(|e| e.paths.contains(&path)),
            "replacing a file with an excluded directory must be reported: {events:?}"
        );
    }

    #[test]
    fn excluded_directory_mtime_changes_are_not_reported() {
        use crate::Watcher;

        let tmpdir = testdir();
        let root = tmpdir.path();
        let excluded = root.join("excluded");
        std::fs::create_dir(&excluded).expect("create excluded");

        let (mut watcher, rx) = manual_watcher();
        watcher
            .watch_filtered(
                root,
                crate::RecursiveMode::Recursive,
                reject_name("excluded"),
            )
            .expect("watch filtered");

        // poll compares the mtimes of directories with whole-second resolution. A write in the
        // same second as the first scan cannot cause a Modify event, and the test would pass
        // without the fixed mtime of excluded directories.
        wait_for_next_second();

        // A write inside the excluded directory changes its mtime. Only the creation and the
        // removal of the excluded directory may be reported, not a Modify event.
        std::fs::write(excluded.join("inside.txt"), "data").expect("write inside excluded");
        std::fs::write(root.join("seen.txt"), "data").expect("write included file");
        watcher.poll_blocking().expect("poll");

        let events = drain(&rx);
        assert!(
            events
                .iter()
                .all(|e| !e.kind.is_modify() || !e.paths.contains(&excluded)),
            "excluded-subtree activity leaked as a Modify on the excluded directory: {events:?}"
        );
        // The watch has to report the included file, or the assertion above passes without a
        // working watch.
        assert!(
            events
                .iter()
                .any(|e| e.paths.iter().any(|p| p.ends_with("seen.txt"))),
            "expected an event proving the watch is active, got: {events:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_root_to_excluded_directory_watches_nothing() {
        use crate::Watcher;

        let tmpdir = testdir();
        let root = tmpdir.path();
        let excluded = root.join("excluded");
        std::fs::create_dir(&excluded).expect("create excluded");
        std::fs::write(excluded.join("inside.txt"), "data").expect("write inside");
        let link = root.join("link");
        std::os::unix::fs::symlink(&excluded, &link).expect("symlink");

        let (mut watcher, rx) = manual_watcher();

        // The check of the watch root resolves a symlinked root, so a link to an excluded
        // directory is rejected, as on the walking backends. Otherwise the scan would cover the
        // excluded target under the name of the link.
        let result = watcher.watch_filtered(
            &link,
            crate::RecursiveMode::Recursive,
            reject_name("excluded"),
        );
        assert!(
            matches!(result, Err(ref e) if matches!(e.kind, crate::ErrorKind::PathExcluded)),
            "a symlink root resolving to an excluded directory must be rejected: {result:?}"
        );
        assert!(watcher.watched_paths().expect("watched").is_empty());

        std::fs::write(excluded.join("more.txt"), "data").expect("write more");
        watcher.poll_blocking().expect("poll");
        let events = drain(&rx);
        assert!(
            events.is_empty(),
            "nothing is watched, so nothing may be reported: {events:?}"
        );
    }

    #[test]
    fn file_roots_are_not_filtered() {
        use crate::{WatchFilter, Watcher};

        let tmpdir = testdir();
        let file = tmpdir.path().join("watched.txt");
        std::fs::write(&file, "data").expect("write file");

        let (tx, rx) = std::sync::mpsc::channel();
        // `compare_contents` detects the modification below from the content hash, also on a
        // file system that stores the mtime with a coarse resolution.
        let config = Config::default()
            .with_manual_polling()
            .with_compare_contents(true);
        let mut watcher = PollWatcher::new(tx, config).expect("create watcher");

        // The filter only applies to directories, so a filter that rejects this path must not
        // prevent a watch on the file.
        let rejecting = file.clone();
        watcher
            .watch_filtered(
                &file,
                crate::RecursiveMode::NonRecursive,
                WatchFilter::with_filter(move |p: &std::path::Path| p != rejecting),
            )
            .expect("watch file");

        std::fs::write(&file, "changed").expect("modify file");
        watcher.poll_blocking().expect("poll");

        let events = drain(&rx);
        assert!(
            events.iter().any(|e| e.paths.contains(&file)),
            "file watches must not be affected by the directory filter: {events:?}"
        );
    }

    #[test]
    fn poll_watcher_respects_event_kind_mask() {
        use crate::{Config, Watcher};
        use notify_types::event::EventKindMask;
        use std::time::Duration;

        let tmpdir = testdir();
        let (tx, rx) = std::sync::mpsc::channel();

        // Create watcher with CREATE-only mask (no MODIFY events)
        let config = Config::default()
            .with_event_kinds(EventKindMask::CREATE)
            .with_compare_contents(true)
            .with_manual_polling();

        let mut watcher = PollWatcher::new(tx, config).expect("create watcher");
        watcher
            .watch(tmpdir.path(), crate::RecursiveMode::Recursive)
            .expect("watch");

        let path = tmpdir.path().join("test_file");

        // Create a file - should generate CREATE event
        std::fs::write(&path, "initial").expect("write initial");
        watcher.poll().expect("poll 1");

        // Wait for CREATE event (use blocking recv with timeout)
        let event = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("should receive CREATE event")
            .expect("event should not be an error");
        assert!(
            event.kind.is_create(),
            "Expected CREATE event, got: {event:?}"
        );

        // Modify the file - should NOT generate event (filtered by mask)
        std::fs::write(&path, "modified content").expect("write modified");
        watcher.poll().expect("poll 2");

        // Give poll thread time to process, then verify no MODIFY events
        std::thread::sleep(Duration::from_millis(100));

        // Should have no more events (MODIFY was filtered out)
        let remaining: Vec<_> = rx.try_iter().filter_map(|r| r.ok()).collect();
        assert!(
            !remaining.iter().any(|e| e.kind.is_modify()),
            "Should not receive MODIFY events with CREATE-only mask, got: {remaining:?}"
        );
    }
}
