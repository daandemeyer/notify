// Bisecting probe for the FSEvents descriptor bug.
//
//   cc -o probe probe.c -framework CoreServices
//   ./probe <scratch-dir> <mode>
//
// The full reproducer closes descriptors it does not own within ~15 seconds.
// The simplest possible thing -- create a stream, release it, check fd 0 -- does
// not, across 24 flag/path combinations and three macOS versions. So something
// between those two extremes is required, and each mode here adds exactly one
// ingredient so the run says which:
//
//   baseline   create and release, 16 paths, single threaded
//   cfurl      as baseline, but each path resolved through a file reference URL
//              first, the way notify does it
//   scale      as baseline, with 4097 paths
//   threshold  4000, 4095, 4096, 4097 and 8194 paths, to pin the boundary
//   chunked    8194 paths split across several streams of 4000, the proposed fix
//
// A first pass also tried 500 serial cycles, four concurrent threads, and
// threads racing a recursive delete. All three were clean, so concurrency and
// repetition are not ingredients and those modes are gone. Path count is the
// whole story, and the failure is deterministic: one close per stream created.
//
// Detection: park /dev/null on fd 0 and check whether it is still open. Nothing
// here ever closes fd 0, so a closed fd 0 is FSEvents closing a descriptor it
// does not own. After each detection fd 0 is re-parked so counting can continue.

#include <CoreServices/CoreServices.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NOTIFY_FLAGS                                                            \
    (kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer |      \
     kFSEventStreamCreateFlagWatchRoot)

static atomic_int g_hits;
static const char *g_root;

static int fd0_is_open(void) {
    return fcntl(0, F_GETFD) != -1;
}

static void plug_fd0(void) {
    int nul = open("/dev/null", O_RDWR);
    if (nul < 0) {
        return;
    }
    if (nul != 0) {
        dup2(nul, 0);
        close(nul);
    }
}

static void check(const char *where) {
    if (!fd0_is_open()) {
        int n = atomic_fetch_add(&g_hits, 1);
        if (n < 8) {
            printf("  fd 0 CLOSED after %s\n", where);
            fflush(stdout);
        }
        plug_fd0();
    }
}

static void noop_callback(ConstFSEventStreamRef stream, void *info, size_t num,
                          void *paths, const FSEventStreamEventFlags flags[],
                          const FSEventStreamEventId ids[]) {
    (void)stream;
    (void)info;
    (void)num;
    (void)paths;
    (void)flags;
    (void)ids;
}

// Mirror of notify's path_to_cfstring_ref: path -> URL -> absolute -> file
// reference URL -> file path URL -> path. This is where CoreFoundation does its
// own per-path filesystem work, and it is absent from the simple probe.
static CFStringRef cfurl_round_trip(const char *path) {
    CFStringRef s = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    if (!s) {
        return NULL;
    }
    CFURLRef url = CFURLCreateWithFileSystemPath(NULL, s, kCFURLPOSIXPathStyle, true);
    CFRelease(s);
    if (!url) {
        return NULL;
    }
    CFURLRef absolute = CFURLCopyAbsoluteURL(url);
    CFRelease(url);
    if (!absolute) {
        return NULL;
    }
    CFErrorRef err = NULL;
    CFURLRef reference = CFURLCreateFileReferenceURL(NULL, absolute, &err);
    CFRelease(absolute);
    if (!reference) {
        if (err) {
            CFRelease(err);
        }
        return NULL;
    }
    CFURLRef back = CFURLCreateFilePathURL(NULL, reference, &err);
    CFRelease(reference);
    if (!back) {
        if (err) {
            CFRelease(err);
        }
        return NULL;
    }
    CFStringRef out = CFURLCopyFileSystemPath(back, kCFURLPOSIXPathStyle);
    CFRelease(back);
    return out;
}

static CFArrayRef make_paths(const char *root, int count, int round_trip) {
    CFMutableArrayRef paths = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (int i = 0; i < count; i++) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s/dir_%d", root, i);
        mkdir(buf, 0755);
        CFStringRef s = round_trip ? cfurl_round_trip(buf)
                                   : CFStringCreateWithCString(NULL, buf, kCFStringEncodingUTF8);
        if (s) {
            CFArrayAppendValue(paths, s);
            CFRelease(s);
        }
    }
    return paths;
}

// One create / schedule / start / stop / invalidate / release cycle.
static void cycle(CFArrayRef paths, const char *label) {
    FSEventStreamRef stream = FSEventStreamCreate(NULL, noop_callback, NULL, paths,
                                                 kFSEventStreamEventIdSinceNow, 0.0, NOTIFY_FLAGS);
    check(label);
    if (!stream) {
        return;
    }
    FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    if (FSEventStreamStart(stream)) {
        FSEventStreamStop(stream);
    }
    FSEventStreamInvalidate(stream);
    FSEventStreamRelease(stream);
    check(label);
}

static void mode_simple(int count, int round_trip, int iterations) {
    char sub[1024];
    snprintf(sub, sizeof(sub), "%s/tree", g_root);
    mkdir(sub, 0755);
    CFArrayRef paths = make_paths(sub, count, round_trip);
    for (int i = 0; i < iterations; i++) {
        cycle(paths, "create/release");
    }
    CFRelease(paths);
}

// Paths [from, to) of one prebuilt tree, so chunking does not rebuild anything.
// `pad` lengthens each component, so that the same count of paths can be made to
// occupy very different numbers of bytes.
static CFArrayRef make_paths_range_padded(const char *root, int from, int to, int pad) {
    char padding[192];
    if (pad > (int)sizeof(padding) - 1) {
        pad = (int)sizeof(padding) - 1;
    }
    memset(padding, 'x', (size_t)pad);
    padding[pad < 0 ? 0 : pad] = '\0';

    CFMutableArrayRef paths = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (int i = from; i < to; i++) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s/dir_%d%s", root, i, padding);
        mkdir(buf, 0755);
        CFStringRef s = CFStringCreateWithCString(NULL, buf, kCFStringEncodingUTF8);
        if (s) {
            CFArrayAppendValue(paths, s);
            CFRelease(s);
        }
    }
    return paths;
}

static CFArrayRef make_paths_range(const char *root, int from, int to) {
    return make_paths_range_padded(root, from, to, 0);
}

// One trial: how many descriptors does a single stream of `count` paths close?
static int trial(const char *root, int count, int pad) {
    const int before = atomic_load(&g_hits);
    CFArrayRef paths = make_paths_range_padded(root, 0, count, pad);
    cycle(paths, "bisect");
    CFRelease(paths);
    return atomic_load(&g_hits) - before;
}

// The threshold matters: if it is a few hundred rather than a few thousand, this
// is not a pathological corner but something ordinary recursive watches hit.
static void mode_bisect(int pad) {
    char sub[1024];
    snprintf(sub, sizeof(sub), "%s/tree", g_root);
    mkdir(sub, 0755);

    const int sweep[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4000};
    int lo = 0;
    int hi = 0;
    printf("  coarse sweep (pad=%d):\n", pad);
    for (size_t i = 0; i < sizeof(sweep) / sizeof(sweep[0]); i++) {
        const int closes = trial(sub, sweep[i], pad);
        printf("    paths=%-5d closes=%d %s\n", sweep[i], closes, closes ? "BUG" : "ok");
        fflush(stdout);
        if (closes && !hi) {
            hi = sweep[i];
            break;
        }
        lo = sweep[i];
    }

    if (!hi) {
        printf("  no count in the sweep triggered it\n");
        return;
    }

    printf("  binary search in (%d, %d]:\n", lo, hi);
    while (hi - lo > 1) {
        const int mid = lo + (hi - lo) / 2;
        const int closes = trial(sub, mid, pad);
        printf("    paths=%-5d closes=%d %s\n", mid, closes, closes ? "BUG" : "ok");
        fflush(stdout);
        if (closes) {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    printf("  THRESHOLD(pad=%d): %d paths clean, %d paths closes a descriptor\n", pad, lo, hi);
}

// Where exactly is the edge? FSEvents is documented nowhere but widely reported
// to cap a stream at about 4096 paths.
static void mode_threshold(void) {
    const int counts[] = {4000, 4095, 4096, 4097, 8194};
    char sub[1024];
    snprintf(sub, sizeof(sub), "%s/tree", g_root);
    mkdir(sub, 0755);
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        const int before = atomic_load(&g_hits);
        CFArrayRef paths = make_paths_range(sub, 0, counts[i]);
        cycle(paths, "create/release");
        CFRelease(paths);
        const int closed = atomic_load(&g_hits) - before;
        printf("  paths=%-5d closes=%d %s\n", counts[i], closed, closed ? "BUG" : "ok");
        fflush(stdout);
    }
}

// The edge was found with one trial per point. Repeat it, because a bug report
// should not rest on a single observation either side of the boundary.
static void mode_boundary(void) {
    char sub[1024];
    snprintf(sub, sizeof(sub), "%s/tree", g_root);
    mkdir(sub, 0755);
    for (int round = 0; round < 5; round++) {
        const int a = trial(sub, 1024, 0);
        const int b = trial(sub, 1025, 0);
        printf("  round %d: 1024 -> %d closes, 1025 -> %d closes\n", round, a, b);
        fflush(stdout);
    }
}

// `chunked` releases each stream before creating the next, so it never has more
// than one chunk registered. A real watcher needs them all alive. If the
// fseventsd client budget is system wide, as "too many clients in system
// (limit 1024)" suggests, keeping them alive should reproduce even though
// releasing between them does not.
static void mode_live_chunks(int total, int per_stream) {
    char sub[1024];
    snprintf(sub, sizeof(sub), "%s/tree", g_root);
    mkdir(sub, 0755);

    const int n = (total + per_stream - 1) / per_stream;
    FSEventStreamRef *streams = calloc((size_t)n, sizeof(FSEventStreamRef));
    int held = 0;

    for (int from = 0; from < total; from += per_stream) {
        int to = from + per_stream;
        if (to > total) {
            to = total;
        }
        CFArrayRef paths = make_paths_range(sub, from, to);
        FSEventStreamRef stream =
            FSEventStreamCreate(NULL, noop_callback, NULL, paths, kFSEventStreamEventIdSinceNow,
                                0.0, NOTIFY_FLAGS);
        CFRelease(paths);
        check("create (kept alive)");
        if (stream) {
            FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
            const int started = FSEventStreamStart(stream);
            check("start (kept alive)");
            streams[held++] = stream;
            printf("  stream %d: paths %d..%d started=%d closes so far=%d\n", held, from, to,
                   started, atomic_load(&g_hits));
        } else {
            printf("  stream for %d..%d could not be created\n", from, to);
        }
        fflush(stdout);
    }

    for (int i = 0; i < held; i++) {
        FSEventStreamStop(streams[i]);
        FSEventStreamInvalidate(streams[i]);
        FSEventStreamRelease(streams[i]);
    }
    check("teardown");
    free(streams);
}

// Is the budget per stream or shared? Two live streams, each comfortably under
// the threshold on its own, but over it together.
static void mode_two_streams(void) {
    mode_live_chunks(1200, 600);
}

// The proposed fix: never hand a single stream more than the cap. If this stays
// clean at a total that reproduces in one stream, chunking is a real fix rather
// than a mitigation.
static void mode_chunked(int total, int per_stream) {
    char sub[1024];
    snprintf(sub, sizeof(sub), "%s/tree", g_root);
    mkdir(sub, 0755);
    for (int from = 0; from < total; from += per_stream) {
        int to = from + per_stream;
        if (to > total) {
            to = total;
        }
        CFArrayRef paths = make_paths_range(sub, from, to);
        cycle(paths, "create/release (chunk)");
        CFRelease(paths);
        printf("  chunk %d..%d closes so far=%d\n", from, to, atomic_load(&g_hits));
        fflush(stdout);
    }
}

int main(int argc, char **argv) {
    g_root = argc > 1 ? argv[1] : "/tmp/fsevents-probe";
    const char *mode = argc > 2 ? argv[2] : "baseline";
    mkdir(g_root, 0755);
    plug_fd0();

    printf("mode=%s root=%s\n", mode, g_root);
    if (!fd0_is_open()) {
        printf("could not park a descriptor on fd 0; results are meaningless\n");
        return 2;
    }

    if (strcmp(mode, "baseline") == 0) {
        mode_simple(16, 0, 4);
    } else if (strcmp(mode, "cfurl") == 0) {
        mode_simple(16, 1, 4);
    } else if (strcmp(mode, "scale") == 0) {
        mode_simple(4097, 0, 2);
    } else if (strcmp(mode, "threshold") == 0) {
        mode_threshold();
    } else if (strcmp(mode, "chunked") == 0) {
        mode_chunked(8194, 1024);
    } else if (strcmp(mode, "boundary") == 0) {
        mode_boundary();
    } else if (strcmp(mode, "live-chunks") == 0) {
        mode_live_chunks(8194, 1024);
    } else if (strcmp(mode, "two-streams") == 0) {
        mode_two_streams();
    } else if (strcmp(mode, "bisect") == 0) {
        mode_bisect(0);
    } else if (strcmp(mode, "bisect-long") == 0) {
        mode_bisect(160);
    } else {
        printf("unknown mode\n");
        return 2;
    }

    const int hits = atomic_load(&g_hits);
    printf("mode=%s closes=%d %s\n", mode, hits, hits ? "BUG PRESENT" : "clean");
    return hits ? 1 : 0;
}
