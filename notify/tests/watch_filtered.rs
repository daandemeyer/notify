//! Integration tests for `Watcher::watch_filtered` that only use the public API.
//!
//! The tests run `RecommendedWatcher`, which is inotify, FSEvents, kqueue or
//! ReadDirectoryChangesW depending on the target, and `PollWatcher`. Every backend has to drop
//! the events below a directory that the filter rejects and deliver the events below an
//! accepted sibling. The error for a rejected root comes from code that all backends share, so
//! every backend has to return it the same way.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use notify::{
    Config, ErrorKind, Event, PathOp, PollWatcher, RecursiveMode, Result, WatchFilter,
    WatchPathConfig, Watcher, recommended_watcher,
};

/// A temporary directory whose path is canonicalized, matching what the event-time backends
/// report (macOS resolves `/var` -> `/private/var`; Windows returns a verbatim `\\?\` path).
struct TestDir {
    _tmp: tempfile::TempDir,
    path: PathBuf,
}

impl TestDir {
    fn path(&self) -> &Path {
        &self.path
    }
}

fn testdir() -> TestDir {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let path = std::fs::canonicalize(tmp.path()).expect("canonicalize tempdir");
    TestDir { _tmp: tmp, path }
}

/// A filter that rejects directories named `name`.
fn reject_name(name: &'static str) -> WatchFilter {
    WatchFilter::with_filter(move |p: &Path| p.file_name() != Some(std::ffi::OsStr::new(name)))
}

fn drain(rx: &mpsc::Receiver<Result<Event>>) -> Vec<Event> {
    rx.try_iter()
        .map(|res| res.expect("watcher delivered an error"))
        .collect()
}

/// Receives events until one names `target` or a path below it, and fails on any event for a
/// path below `excluded`. Returns whether an event for `target` arrived before `deadline`.
///
/// kqueue does not report which entry of a watched directory changed, so the backend reports
/// one new entry for each write to the parent. A test that waits for the creation of each
/// sibling before it creates the next gives kqueue one write for each sibling.
fn wait_for_path(
    rx: &mpsc::Receiver<Result<Event>>,
    target: &Path,
    excluded: &Path,
    deadline: Instant,
) -> bool {
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(Ok(event)) => {
                assert!(
                    !event
                        .paths
                        .iter()
                        .any(|p| p.starts_with(excluded) && p.as_path() != excluded),
                    "event leaked from inside the excluded directory: {event:?}"
                );
                if event.paths.iter().any(|p| p.starts_with(target)) {
                    return true;
                }
            }
            Ok(Err(e)) => panic!("watcher delivered an error: {e:?}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!("watcher channel disconnected"),
        }
    }
    false
}

/// FSEvents can fail to start its stream under load, so the call makes up to five attempts.
fn watch_filtered_retrying(watcher: &mut impl Watcher, root: &Path, filter: WatchFilter) {
    for attempt in 0..5 {
        match watcher.watch_filtered(root, RecursiveMode::Recursive, filter.clone()) {
            Ok(()) => return,
            Err(e) if attempt < 4 => {
                eprintln!("watch_filtered attempt {attempt} failed: {e:?}; retrying");
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("watch_filtered failed: {e:?}"),
        }
    }
}

#[test]
fn rejected_root_returns_path_excluded_recommended() {
    let dir = testdir();
    let (tx, _rx) = mpsc::channel();
    let mut watcher = recommended_watcher(tx).expect("recommended watcher");

    let rejecting = dir.path().to_path_buf();
    let result = watcher.watch_filtered(
        dir.path(),
        RecursiveMode::Recursive,
        WatchFilter::with_filter(move |p: &Path| p != rejecting.as_path()),
    );
    assert!(
        matches!(result, Err(ref e) if matches!(e.kind, ErrorKind::PathExcluded)),
        "watching a filter-rejected root must fail with PathExcluded: {result:?}"
    );
}

#[test]
fn a_watch_inside_an_excluded_directory_reports_its_events_recommended() {
    let dir = testdir();
    let root = dir.path();
    let (tx, rx) = mpsc::channel();
    let mut watcher = recommended_watcher(tx).expect("recommended watcher");
    let excluded = root.join("excluded");
    let inner = excluded.join("inner");
    std::fs::create_dir_all(&inner).expect("create inner");

    watch_filtered_retrying(&mut watcher, root, reject_name("excluded"));
    watch_filtered_retrying(&mut watcher, &inner, reject_name("other"));
    let _ = drain(&rx);

    let file = inner.join("file");
    let hidden = excluded.join("hidden");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = false;
    while !seen && Instant::now() < deadline {
        std::fs::write(&hidden, "x").expect("write hidden");
        std::fs::write(&file, "x").expect("write file");
        while let Ok(event) = rx.recv_timeout(Duration::from_millis(100)) {
            let event = event.expect("watcher delivered an error");
            assert!(!event.paths.contains(&hidden), "{event:?}");
            seen |= event.paths.contains(&file);
        }
    }
    assert!(seen, "the watch of {inner:?} did not report {file:?}");
}

/// A rejected root must fail the whole batch and register nothing.
#[test]
fn update_paths_rejected_root_is_path_excluded() {
    let dir = testdir();
    let root = dir.path();
    let rejecting = root.to_path_buf();

    let (tx, _rx) = mpsc::channel();
    let mut watcher =
        PollWatcher::new(tx, Config::default().with_manual_polling()).expect("poll watcher");
    let result = watcher.update_paths(vec![PathOp::Watch(
        root.to_path_buf(),
        WatchPathConfig::new(RecursiveMode::Recursive).with_watch_filter(WatchFilter::with_filter(
            move |p: &Path| p != rejecting.as_path(),
        )),
    )]);

    assert!(
        matches!(result, Err(ref e) if matches!(e.source.kind, ErrorKind::PathExcluded)),
        "update_paths must surface PathExcluded for a rejected root: {result:?}"
    );
    assert!(watcher.watched_paths().expect("watched paths").is_empty());
}

/// `PollWatcher` drops the events below a rejected directory and delivers the events below an
/// included sibling. The test polls manually, so the result does not depend on timing. `watch`
/// adds the watch with the filter on the root.
fn assert_poll_watcher_filters(watch: impl FnOnce(&mut PollWatcher, &Path)) {
    let dir = testdir();
    let root = dir.path();
    let excluded = root.join("excluded");
    let included = root.join("included");
    std::fs::create_dir(&excluded).expect("create excluded");
    std::fs::create_dir(&included).expect("create included");

    let (tx, rx) = mpsc::channel();
    let mut watcher =
        PollWatcher::new(tx, Config::default().with_manual_polling()).expect("poll watcher");
    // The first scan records the state of the tree and skips the excluded directory.
    watch(&mut watcher, root);
    let _ = drain(&rx);

    std::fs::write(excluded.join("hidden.txt"), "x").expect("write hidden");
    std::fs::write(included.join("seen.txt"), "x").expect("write seen");
    watcher.poll_blocking().expect("poll");

    let events = drain(&rx);
    assert!(
        events
            .iter()
            .any(|e| e.paths.contains(&included.join("seen.txt"))),
        "expected an event for the file created under the included directory: {events:?}"
    );
    assert!(
        events.iter().all(|e| e
            .paths
            .iter()
            .all(|p| !p.starts_with(&excluded) || *p == excluded)),
        "no event may originate strictly inside the excluded directory: {events:?}"
    );
}

#[test]
fn poll_watcher_suppresses_events_inside_excluded_directory() {
    assert_poll_watcher_filters(|watcher, root| {
        watcher
            .watch_filtered(root, RecursiveMode::Recursive, reject_name("excluded"))
            .expect("watch filtered");
    });
}

/// `update_paths` has to pass the filter of each `PathOp` to the backend.
#[test]
fn update_paths_applies_the_watch_filter() {
    assert_poll_watcher_filters(|watcher, root| {
        watcher
            .update_paths(vec![PathOp::Watch(
                root.to_path_buf(),
                WatchPathConfig::new(RecursiveMode::Recursive)
                    .with_watch_filter(reject_name("excluded")),
            )])
            .expect("update_paths");
    });
}

/// The platform backend drops the events below a rejected directory and delivers the events below
/// an included sibling. The backend delivers events asynchronously, so the test keeps writing
/// until an event from the included directory arrives, and checks every event on the way.
#[test]
fn recommended_watcher_suppresses_events_inside_excluded_directory() {
    let dir = testdir();
    let root = dir.path();

    let (tx, rx) = mpsc::channel();
    let mut watcher = recommended_watcher(tx).expect("recommended watcher");
    watch_filtered_retrying(&mut watcher, root, reject_name("excluded"));

    let excluded = root.join("excluded");
    let included = root.join("included");

    let deadline = Instant::now() + Duration::from_secs(15);

    // Create the siblings one at a time and wait for each creation, so kqueue gets one write to
    // the parent for each sibling (see `wait_for_path`). The creation of `excluded` is
    // delivered, because only events below a rejected directory are dropped.
    std::fs::create_dir(&excluded).expect("create excluded");
    assert!(
        wait_for_path(&rx, &excluded, &excluded, deadline),
        "expected the excluded directory's own creation to be reported"
    );
    std::fs::create_dir(&included).expect("create included");
    assert!(
        wait_for_path(&rx, &included, &excluded, deadline),
        "expected the included directory's creation to be observed so it becomes watched"
    );

    let mut saw_included = false;
    while !saw_included && Instant::now() < deadline {
        std::fs::write(excluded.join("hidden.txt"), "x").expect("write hidden");
        std::fs::write(included.join("seen.txt"), "x").expect("write seen");

        let attempt_deadline = Instant::now() + Duration::from_millis(250);
        saw_included = wait_for_path(&rx, &included.join("seen.txt"), &excluded, attempt_deadline);
    }

    assert!(
        saw_included,
        "expected an event from inside the included directory within the deadline"
    );

    // The loop above stops at the first event from the included directory, and an event from
    // below `excluded` can arrive after it. Wait and drain the channel, so the check does not
    // depend on the order of delivery.
    std::thread::sleep(Duration::from_millis(500));
    for event in drain(&rx) {
        assert!(
            !event
                .paths
                .iter()
                .any(|p| p.starts_with(&excluded) && *p != excluded),
            "event leaked from inside the excluded directory: {event:?}"
        );
    }
}

/// The filter only applies to directories, so a watch on a file succeeds even when the filter
/// rejects the path of the file.
#[test]
fn file_root_is_not_filtered_recommended() {
    let dir = testdir();
    let file = dir.path().join("watched.txt");
    std::fs::write(&file, "init").expect("create file");
    let (tx, _rx) = mpsc::channel();
    let mut watcher = recommended_watcher(tx).expect("recommended watcher");

    let rejecting = file.clone();
    let result = watcher.watch_filtered(
        &file,
        RecursiveMode::Recursive,
        WatchFilter::with_filter(move |p: &Path| p != rejecting.as_path()),
    );
    assert!(
        result.is_ok(),
        "the filter only applies to directories, so a file root must still be watched: {result:?}"
    );
}

/// A rewatch of the same path with an accept-all filter replaces the filtered watch, so the events
/// below the excluded directory are delivered afterwards.
#[test]
fn rewatching_with_accept_all_lifts_the_filter() {
    let dir = testdir();
    let root = dir.path();
    let excluded = root.join("excluded");
    std::fs::create_dir(&excluded).expect("create excluded");

    let (tx, rx) = mpsc::channel();
    let mut watcher =
        PollWatcher::new(tx, Config::default().with_manual_polling()).expect("poll watcher");
    watcher
        .watch_filtered(root, RecursiveMode::Recursive, reject_name("excluded"))
        .expect("watch filtered");
    let _ = drain(&rx);

    // With the filter in place, activity inside `excluded` is suppressed.
    std::fs::write(excluded.join("first.txt"), "a").expect("write first");
    watcher.poll_blocking().expect("poll");
    let events = drain(&rx);
    assert!(
        events.iter().all(|e| e
            .paths
            .iter()
            .all(|p| !p.starts_with(&excluded) || *p == excluded)),
        "the filter should suppress excluded contents: {events:?}"
    );

    // A rewatch of the same path without a filter replaces the watch and removes the exclusion.
    watcher
        .watch(root, RecursiveMode::Recursive)
        .expect("rewatch accept-all");
    let _ = drain(&rx);

    std::fs::write(excluded.join("second.txt"), "b").expect("write second");
    watcher.poll_blocking().expect("poll");
    let events = drain(&rx);
    assert!(
        events
            .iter()
            .any(|e| e.paths.contains(&excluded.join("second.txt"))),
        "after re-watching without a filter, excluded contents must be reported: {events:?}"
    );
}
