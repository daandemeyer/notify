# fsevents-fd-repro

`FSEventStreamCreate` closes a file descriptor it does not own when given more
than about 4096 paths. Two C files, no dependencies beyond the system
frameworks. macOS only.

    cc -o probe trace/probe.c -framework CoreServices
    ./probe /tmp/probe scale

## The finding

Reproduced on macOS 14, 15 and 26 (arm64), identically:

| paths in one stream | result |
|---|---|
| 16 | clean |
| 4097 | fd 0 closed, once per `FSEventStreamCreate` |

It is deterministic, not a race. Concurrency, repetition and the CFURL
file-reference resolution are all irrelevant: 500 serial create/release cycles
at 16 paths, four concurrent threads, and threads racing a recursive delete were
all clean. Path count is the whole story. The create flags do not matter either;
all eight combinations of `FileEvents`, `NoDefer` and `WatchRoot` behave the
same.

The descriptor closed is fd 0, and fd 0 is open at the time, so FSEvents is not
closing something it opened. `close_trace.c` catches it with the caller on the
stack:

```
=== DOUBLE CLOSE ===
close(0) returned EBADF, so it was already closed

second closer (this call):
  FSEvents  _FSEventStreamDeallocate + 348
  FSEvents  _FSEventStreamCreate + 2160
  FSEvents  FSEventStreamCreate + 76

first closer (recorded earlier, this is the culprit):
  FSEvents  watch_path + 664
  FSEvents  _FSEventStreamCreate + 1228
```

## Why it matters far from the call site

Closing fd 0 takes the process's stdin. fd 0 is then the lowest free descriptor,
so the next `open` anywhere in the process lands on it, and the next oversized
`FSEventStreamCreate` closes that. The damage therefore surfaces nowhere near
FSEvents: in the Rust program where this was found it appeared as `EBADF` from
`closedir` inside `remove_dir_all`, and as an `IO Safety violation` abort.

## Modes

    ./probe <scratch-dir> <mode>

- `baseline` 16 paths, single threaded
- `cfurl` as baseline, paths resolved through file reference URLs first
- `scale` 4097 paths
- `threshold` 4000, 4095, 4096, 4097, 8194 paths, to pin the boundary
- `chunked` 8194 paths split across streams of 4000, testing the workaround

Exit status is 1 if a descriptor was closed.

## Attributing a close

`close_trace.c` interposes `close()` and prints a backtrace when a descriptor is
closed twice, naming the caller:

    cc -dynamiclib -o libclosetrace.dylib trace/close_trace.c
    DYLD_INSERT_LIBRARIES=$PWD/libclosetrace.dylib ./probe /tmp/probe scale

Two traps it documents, both hit the hard way: `dlsym(RTLD_NEXT, "close")`
returns the interposed function and recurses until the stack overflows, and
`syscall(2)` no longer resolves at load time on current macOS.

## Workaround

Keep each stream under the cap and use several streams. `chunked` tests exactly
that. Parking a sacrificial descriptor on fd 0 across the call does **not** work
and was measured not to: fd 0 stays free for the whole duration of
`FSEventStreamCreate`, which is long, so another thread simply takes it.
