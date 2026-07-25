// Interposes close() so that a descriptor closed by something that does not own
// it is caught at the moment it happens, with the caller still on the stack.
//
// Elimination arguments only get you "FSEvents is implicated". This gets you the
// actual call. Load it with DYLD_INSERT_LIBRARIES; it works for calls made from
// inside CoreFoundation and CoreServices, not just from the main program.
//
// The reproducer marks its canary descriptors with repro_watch_fd(fd, 1). Nothing
// else in the process is supposed to close those, so any close() of a marked
// descriptor is the bug.
//
// Two things this deliberately does NOT do, both learned the hard way:
//
//   * It does not resolve the real close() with dlsym(RTLD_NEXT). dyld applies
//     interposition to dlsym results too, so the "real" pointer comes straight
//     back here and the stack overflows. Calls made from inside the interposing
//     image are not themselves interposed, so the plain close() below is the
//     correct original.
//   * It does not use syscall(2), which macOS deprecated long ago and which may
//     no longer resolve at load time on current releases.

#include <errno.h>
#include <execinfo.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_FD 8192
#define BT_FRAMES 24

// The backtrace of whoever last closed each descriptor. When a later close of
// the same descriptor fails with EBADF we have both ends of the double close:
// the caller on the stack right now, and the one recorded here.
static void *last_bt[MAX_FD][BT_FRAMES];
static atomic_int last_n[MAX_FD];

static atomic_int watched[MAX_FD];
static atomic_int hits;
// Nothing is inspected until the constructor has run. close() is called during
// process startup, before this image is fully initialised.
static atomic_int ready;

__attribute__((constructor)) static void repro_trace_init(void) {
    atomic_store(&ready, 1);
    const char *banner = "close_trace: loaded, interposing close()\n";
    write(2, banner, strlen(banner));
}

// Called from Rust. `on` marks a descriptor as owned by the reproducer.
__attribute__((visibility("default"))) void repro_watch_fd(int fd, int on) {
    if (fd >= 0 && fd < MAX_FD) {
        atomic_store(&watched[fd], on);
    }
}

__attribute__((visibility("default"))) int repro_stray_close_count(void) {
    return atomic_load(&hits);
}

static void dump(const char *label, void *const *frames, int count) {
    write(2, label, strlen(label));
    backtrace_symbols_fd((void **)frames, count, 2);
}

static int repro_close(int fd) {
    const int track = atomic_load(&ready) && fd >= 0 && fd < MAX_FD;
    void *frames[BT_FRAMES];
    int count = 0;
    if (track) {
        count = backtrace(frames, BT_FRAMES);
    }

    const int marked = track && atomic_load(&watched[fd]);
    if (marked) {
        atomic_store(&watched[fd], 0);
        atomic_fetch_add(&hits, 1);
        char msg[192];
        int n = snprintf(msg, sizeof(msg),
                         "\n=== STRAY CLOSE ===\nfd %d belongs to the reproducer, "
                         "closed by thread %p\n",
                         fd, (void *)pthread_self());
        if (n > 0) {
            write(2, msg, (size_t)n);
        }
        dump("caller:\n", frames, count);
        write(2, "=== END ===\n", 12);
    }

    const int r = close(fd);
    const int saved = errno;

    if (track) {
        if (r == -1 && saved == EBADF) {
            // This is the money case: the descriptor was already closed, so
            // whoever closed it before did not own it.
            atomic_fetch_add(&hits, 1);
            char msg[192];
            int n = snprintf(msg, sizeof(msg),
                             "\n=== DOUBLE CLOSE ===\nclose(%d) returned EBADF on thread %p, "
                             "so it was already closed\n",
                             fd, (void *)pthread_self());
            if (n > 0) {
                write(2, msg, (size_t)n);
            }
            dump("second closer (this call):\n", frames, count);
            const int prev = atomic_load(&last_n[fd]);
            if (prev > 0) {
                dump("first closer (recorded earlier, this is the culprit):\n", last_bt[fd], prev);
            } else {
                write(2, "first closer: not recorded\n", 27);
            }
            write(2, "=== END DOUBLE CLOSE ===\n", 25);
        } else if (r == 0 && count > 0) {
            memcpy(last_bt[fd], frames, (size_t)count * sizeof(void *));
            atomic_store(&last_n[fd], count);
        }
    }

    errno = saved;
    return r;
}

#define DYLD_INTERPOSE(_replacement, _replacee)                                   \
    __attribute__((used)) static struct {                                         \
        const void *replacement;                                                  \
        const void *replacee;                                                     \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = {    \
        (const void *)(unsigned long)&_replacement,                               \
        (const void *)(unsigned long)&_replacee                                   \
    };

DYLD_INTERPOSE(repro_close, close)
