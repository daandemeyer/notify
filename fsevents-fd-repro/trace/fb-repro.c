// FSEvents closes a file descriptor it does not own.
//
//   cc -o fb-repro fb-repro.c -framework CoreServices
//   ./fb-repro [scratch-dir]
//
// Creating an FSEventStream over more than roughly RLIMIT_NOFILE/10 paths and
// then releasing it closes file descriptor 0, which belongs to the caller and
// was never handed to FSEvents. In a normal process that descriptor is stdin.
//
// The path count is derived from RLIMIT_NOFILE because the threshold scales
// with it. With the default soft limit of 256 on a stock desktop the threshold
// is around 27 paths. The counts below are deliberately well clear of the edge,
// since the exact boundary also shifts with how many descriptors the process
// already holds.
//
// Each of these is required. Removing any one of them stops it reproducing:
//
//   - more than about RLIMIT_NOFILE/10 paths in one stream
//   - the three create flags below; kFSEventStreamCreateFlagNone is clean
//   - the stream must be invalidated and released, because the close happens
//     during teardown rather than during create
//   - the watched paths must sit below an intermediate directory
//
// These make no difference: scheduling on a run loop, starting the stream,
// whether the directories exist on disk, and repeating the sequence. Scheduling
// and starting are kept only because they are what a real client does.

#include <CoreServices/CoreServices.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static int fd0_is_open(void) {
    return fcntl(0, F_GETFD) != -1;
}

// Park a descriptor we own on fd 0, so anything closing it is unambiguously not
// the owner.
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

static void callback(ConstFSEventStreamRef stream, void *info, size_t num, void *paths,
                     const FSEventStreamEventFlags flags[], const FSEventStreamEventId ids[]) {
    (void)stream;
    (void)info;
    (void)num;
    (void)paths;
    (void)flags;
    (void)ids;
}

// Returns 1 if fd 0 was closed by the time the stream had been torn down.
static int watch_and_release(const char *dir, int count) {
    CFMutableArrayRef paths = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (int i = 0; i < count; i++) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s/dir_%d", dir, i);
        mkdir(buf, 0755);
        CFStringRef s = CFStringCreateWithCString(NULL, buf, kCFStringEncodingUTF8);
        if (s) {
            CFArrayAppendValue(paths, s);
            CFRelease(s);
        }
    }

    FSEventStreamRef stream = FSEventStreamCreate(
        NULL, callback, NULL, paths, kFSEventStreamEventIdSinceNow, 0.0,
        kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer |
            kFSEventStreamCreateFlagWatchRoot);

    if (stream) {
        FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        if (FSEventStreamStart(stream)) {
            FSEventStreamStop(stream);
        }
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
    }
    CFRelease(paths);

    const int closed = !fd0_is_open();
    if (closed) {
        plug_fd0();
    }
    return closed;
}

int main(int argc, char **argv) {
    const char *root = argc > 1 ? argv[1] : "/tmp/fsevents-fd-bug";
    mkdir(root, 0755);

    // The watched paths must be below an intermediate directory. Listing them
    // directly in the scratch root does not reproduce.
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/tree", root);
    mkdir(dir, 0755);

    plug_fd0();

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        printf("getrlimit failed\n");
        return 2;
    }
    const int limit = (int)rl.rlim_cur;
    const int under = limit / 20;
    const int over = limit / 5;

    printf("RLIMIT_NOFILE=%d\n", limit);
    printf("fd 0 open at start: %d\n", fd0_is_open());

    const int closed_under = watch_and_release(dir, under);
    printf("%5d paths (well under the threshold): fd 0 closed = %d\n", under, closed_under);

    const int closed_over = watch_and_release(dir, over);
    printf("%5d paths (well over the threshold):  fd 0 closed = %d\n", over, closed_over);

    if (closed_over) {
        printf("\nFAIL: FSEvents closed fd 0, which this program opened and never closed.\n");
        return 1;
    }
    printf("\nfd 0 survived.\n");
    return 0;
}
