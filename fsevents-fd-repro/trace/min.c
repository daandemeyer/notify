// Cutting probe.c down to the smallest thing that still reproduces.
//
// probe.c's `boundary` mode reproduces 5/5 on macOS 14, 15 and 26. Hand-written
// minimisations kept failing to reproduce, and each time I guessed at why and
// was wrong. So this is the mechanical version: STEP 0 is a near verbatim
// extraction of the code path that works, and each higher STEP removes exactly
// one more thing. The lowest STEP that stops reproducing is the answer.
//
//   cc -DSTEP=0 -o min0 min.c -framework CoreServices && ./min0 <dir>
//
// The first pass made the STEPs cumulative, which was a mistake: STEP 1 removed
// the intermediate directory and broke reproduction, so every later STEP was
// clean for that reason and tested nothing. These cuts are independent. Each is
// the working baseline minus exactly one thing, so anything still reproducing
// identifies something that is NOT required.
//
// CUT 0  baseline, known to reproduce
// CUT 1  one round instead of five
// CUT 2  drop the 1024 trial, only run 1025
// CUT 3  never schedule or start the stream, just create and tear down
// CUT 4  never tear the stream down, just create and check
// CUT 5  kFSEventStreamCreateFlagNone instead of the three notify flags
// CUT 6  do not mkdir the directories, so the watched paths do not exist
// CUT 7  release the CFArray before scheduling
// CUT 8  no check straight after create, only after teardown
//
// The intermediate directory is required and is therefore in every variant.
//
// The path count is derived from RLIMIT_NOFILE rather than hardcoded, because
// the threshold scales with the limit. Hardcoding a number only works on a
// machine with the limit it was measured on, which is the trap that made
// several earlier attempts at this file appear not to reproduce.
//
// The threshold is around limit/10, but not exactly: the boundary also moves
// with how many descriptors the process already holds, and it drifts down as
// trials accumulate within one process. So rather than trying to sit on the
// edge, this uses limit/20 for the clean case and limit/5 for the failing one,
// both comfortably clear of it.

#ifndef CUT
#define CUT 0
#endif

#include <CoreServices/CoreServices.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NOTIFY_FLAGS                                                                               \
    (kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer |                        \
     kFSEventStreamCreateFlagWatchRoot)

static atomic_int g_hits;

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
        atomic_fetch_add(&g_hits, 1);
        printf("  fd 0 CLOSED after %s\n", where);
        fflush(stdout);
        plug_fd0();
    }
}

static void noop_callback(ConstFSEventStreamRef stream, void *info, size_t num, void *paths,
                          const FSEventStreamEventFlags flags[], const FSEventStreamEventId ids[]) {
    (void)stream;
    (void)info;
    (void)num;
    (void)paths;
    (void)flags;
    (void)ids;
}

static CFArrayRef make_paths(const char *root, int count) {
    CFMutableArrayRef paths = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (int i = 0; i < count; i++) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s/dir_%d", root, i);
#if CUT != 6
        mkdir(buf, 0755);
#endif
        CFStringRef s = CFStringCreateWithCString(NULL, buf, kCFStringEncodingUTF8);
        if (s) {
            CFArrayAppendValue(paths, s);
            CFRelease(s);
        }
    }
    return paths;
}

static int trial(const char *root, int count) {
    const int before = atomic_load(&g_hits);
    CFArrayRef paths = make_paths(root, count);

#if CUT == 5
    const FSEventStreamCreateFlags flags = kFSEventStreamCreateFlagNone;
#else
    const FSEventStreamCreateFlags flags = NOTIFY_FLAGS;
#endif

    FSEventStreamRef stream = FSEventStreamCreate(NULL, noop_callback, NULL, paths,
                                                 kFSEventStreamEventIdSinceNow, 0.0, flags);

#if CUT == 7
    CFRelease(paths);
#endif

#if CUT != 8
    check("create");
#endif

    if (stream) {
#if CUT != 3
        FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        if (FSEventStreamStart(stream)) {
            FSEventStreamStop(stream);
        }
#endif
#if CUT != 4
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
#endif
        check("teardown");
    }

#if CUT != 7
    CFRelease(paths);
#endif

    return atomic_load(&g_hits) - before;
}

int main(int argc, char **argv) {
    const char *root = argc > 1 ? argv[1] : "/tmp/fsevents-min";
    mkdir(root, 0755);
    plug_fd0();

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        printf("getrlimit failed\n");
        return 2;
    }
    const int limit = (int)rl.rlim_cur;
    const int safe = limit / 20;
    const int over = limit / 5;

    printf("CUT=%d root=%s fd0=%d\n", CUT, root, fd0_is_open());
    printf("RLIMIT_NOFILE=%d: %d paths is well under the threshold, %d is well over\n", limit,
           safe, over);

    // probe.c puts the watched directories one level down, and that is the only
    // thing my first "verbatim" extraction failed to copy.
    char tree[1024];
    snprintf(tree, sizeof(tree), "%s/tree", root);
    mkdir(tree, 0755);

#if CUT == 1
    const int rounds = 1;
#else
    const int rounds = 5;
#endif

    for (int r = 0; r < rounds; r++) {
#if CUT != 2
        const int a = trial(tree, safe);
#else
        const int a = -1;
#endif
        const int b = trial(tree, over);
        printf("  round %d: %d paths -> %d closes, %d paths -> %d closes\n", r, safe, a, over, b);
        fflush(stdout);
    }

    const int hits = atomic_load(&g_hits);
    printf("CUT=%d closes=%d %s\n", CUT, hits, hits ? "REPRODUCED" : "clean");
    return hits ? 1 : 0;
}
