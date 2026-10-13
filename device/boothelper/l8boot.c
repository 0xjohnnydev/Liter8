/*
 * l8boot - per-boot setup that needs more than shell builtins.
 *
 * jbboot.sh runs it before it execs pfwatch. It sets up the SSH PATH links
 * synchronously, then forks: the parent returns at once, so the boot job is not
 * held up and no zombie is left under pfwatch, and the child, reparented to
 * launchd, does the waiting.
 *
 * 1. PATH for SSH commands. Dropbear (System, v2016.74) runs every remote
 *    command through /bin/sh with its compiled-in PATH
 *        /usr/bin:/bin:/tmp/bin:/tmp/usr/bin:/binpack/usr/bin:/binpack/bin
 *    and no bootstrap directory, so `ssh root@... dpkg -i` fails. /tmp is
 *    wiped at every boot, so the two writable slots are recreated here:
 *        /tmp/bin     -> /var/jb/usr/bin   (dpkg, apt, killall, ldid, ...)
 *        /tmp/usr/bin -> /var/jb/usr/sbin
 *    /var/jb/bin only duplicates usr/bin. /tmp is world-writable, so anything
 *    already at those paths that is not exactly our root-owned link is moved
 *    aside first: left there, it would sit in front of root's commands.
 *
 * 2. Optional lhook auto-enable, only while /var/jb/.lhook_autoenable exists,
 *    root-owned and not group/other writable. Waits until SpringBoard has been
 *    up for a while, publishes the session flag exactly as `lhookctl enable`
 *    does, then restarts SpringBoard once so its tweaks load. Enabling after the
 *    UI is up, never at early boot, is the rule in launchdhook/SESSION_GUARD.md.
 *
 * The links are checked again once SpringBoard is up, in case /tmp was cleaned
 * after this ran. Everything is logged to stdout, which jbboot appends to
 * /var/mobile/jbboot.log. Paths are macros so the host test can redirect them.
 */
#include "lhook_session.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef L8BOOT_TMP
#define L8BOOT_TMP "/private/var/tmp"
#endif
#ifndef L8BOOT_USR_BIN
#define L8BOOT_USR_BIN "/var/jb/usr/bin"
#endif
#ifndef L8BOOT_USR_SBIN
#define L8BOOT_USR_SBIN "/var/jb/usr/sbin"
#endif
#ifndef L8BOOT_AUTO_MARKER
#define L8BOOT_AUTO_MARKER "/var/jb/.lhook_autoenable"
#endif
#ifndef L8BOOT_SB_NAME
#define L8BOOT_SB_NAME "SpringBoard"
#endif
#ifndef L8BOOT_OWNER_UID
#define L8BOOT_OWNER_UID 0
#endif
/* 1 restarts SpringBoard after enabling; the host test builds with 0. */
#ifndef L8BOOT_RESPRING
#define L8BOOT_RESPRING 1
#endif

/* SpringBoard must have been running this long before injection is enabled. */
#define SB_SETTLE_SECONDS 20
/* Give up waiting for SpringBoard after this long; the boot is not healthy. */
#define SB_WAIT_LIMIT_SECONDS 600
#define POLL_SECONDS 2

/* Move whatever occupies path out of the way, keeping it for inspection. */
static int displace(const char *path) {
    char aside[1024];
    snprintf(aside, sizeof aside, "%s.liter8-displaced.%d", path, (int)getpid());
    if (rename(path, aside) != 0) {
        printf("l8boot: could not move %s aside: %s\n", path, strerror(errno));
        return 0;
    }
    printf("l8boot: moved an unexpected %s to %s\n", path, aside);
    return 1;
}

/* True when path is already a symlink to target owned by the expected uid. */
static int is_our_link(const char *path, const char *target) {
    struct stat st;
    char current[1024];
    if (lstat(path, &st) != 0 || !S_ISLNK(st.st_mode) || st.st_uid != L8BOOT_OWNER_UID) return 0;
    ssize_t n = readlink(path, current, sizeof current - 1);
    if (n < 0) return 0;
    current[n] = '\0';
    return strcmp(current, target) == 0;
}

/* Make path a symlink to target, replacing anything else found there. */
static int ensure_link(const char *path, const char *target) {
    for (int attempt = 0; attempt < 3; attempt++) {
        if (is_our_link(path, target)) return 1;
        struct stat st;
        if (lstat(path, &st) == 0 && !displace(path)) return 0;
        if (symlink(target, path) == 0) {
            printf("l8boot: linked %s -> %s\n", path, target);
            return 1;
        }
        // EEXIST means something reappeared between the two calls; go round.
        if (errno != EEXIST) {
            printf("l8boot: could not link %s: %s\n", path, strerror(errno));
            return 0;
        }
    }
    printf("l8boot: gave up linking %s, it keeps reappearing\n", path);
    return 0;
}

/* Make path a real directory owned by the expected uid that only it can write. */
static int ensure_private_dir(const char *path) {
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode) && st.st_uid == L8BOOT_OWNER_UID && !(st.st_mode & (S_IWGRP | S_IWOTH))) {
            return 1;
        }
        if (!displace(path)) return 0;
    }
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        printf("l8boot: could not create %s: %s\n", path, strerror(errno));
        return 0;
    }
    // EEXIST after displacing means someone raced us; re-check, never trust it.
    if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != L8BOOT_OWNER_UID ||
        (st.st_mode & (S_IWGRP | S_IWOTH))) {
        printf("l8boot: %s is not a private directory after creating it\n", path);
        return 0;
    }
    return 1;
}

static int ensure_path_links(void) {
    int ok = ensure_link(L8BOOT_TMP "/bin", L8BOOT_USR_BIN);
    if (!ensure_private_dir(L8BOOT_TMP "/usr")) return 0;
    return ensure_link(L8BOOT_TMP "/usr/bin", L8BOOT_USR_SBIN) && ok;
}

/* Same predicate every liter8 marker uses: a regular file, owned by the
 * expected uid, not writable by group or other. */
static int auto_enable_requested(void) {
    struct stat st;
    return lstat(L8BOOT_AUTO_MARKER, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_uid == L8BOOT_OWNER_UID && !(st.st_mode & (S_IWGRP | S_IWOTH));
}

/* The SpringBoard pid and how long it has been running, or 0 when absent. */
static pid_t springboard(long *uptime_seconds) {
    int mib[3] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    size_t size = 0;
    if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0 || size == 0) return 0;
    size += size / 4;
    struct kinfo_proc *procs = malloc(size);
    if (!procs) return 0;
    pid_t found = 0;
    if (sysctl(mib, 3, procs, &size, NULL, 0) == 0) {
        struct timeval now;
        gettimeofday(&now, NULL);
        for (size_t i = 0; i < size / sizeof *procs; i++) {
            if (strcmp(procs[i].kp_proc.p_comm, L8BOOT_SB_NAME) != 0) continue;
            found = procs[i].kp_proc.p_pid;
            *uptime_seconds = now.tv_sec - procs[i].kp_proc.p_starttime.tv_sec;
            break;
        }
    }
    free(procs);
    return found;
}

/* Wait until SpringBoard has been up SB_SETTLE_SECONDS; its pid, or 0 on timeout. */
static pid_t wait_for_settled_springboard(void) {
    for (int waited = 0; waited < SB_WAIT_LIMIT_SECONDS; waited += POLL_SECONDS) {
        long up = 0;
        pid_t pid = springboard(&up);
        if (pid && up >= SB_SETTLE_SECONDS) return pid;
        sleep(POLL_SECONDS);
    }
    return 0;
}

/* Publish the session flag the same way lhookctl enable does. */
static int publish_session_flag(void) {
    char boot[64] = {0};
    if (!lhook_boot_id(boot)) return 0;
    char temporary[1024];
    if (snprintf(temporary, sizeof temporary, "%s.XXXXXX", LHOOK_ENABLE_PATH) >= (int)sizeof temporary) return 0;
    int fd = mkstemp(temporary);
    if (fd < 0) return 0;
    int ok = fchmod(fd, 0644) == 0 && write(fd, boot, 36) == 36 && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (ok && rename(temporary, LHOOK_ENABLE_PATH) == 0) return 1;
    unlink(temporary);
    return 0;
}

static void auto_enable(void) {
    pid_t sb = wait_for_settled_springboard();
    if (!sb) {
        printf("l8boot: SpringBoard did not settle within %d s; nothing enabled\n", SB_WAIT_LIMIT_SECONDS);
        return;
    }
    // /tmp may have been cleaned after the boot job ran; the check is cheap.
    ensure_path_links();
    if (!auto_enable_requested()) return;
    if (lhook_session_enabled()) {
        printf("l8boot: injection was already enabled for this boot\n");
        return;
    }
    if (!publish_session_flag() || !lhook_session_enabled()) {
        printf("l8boot: could not enable injection for this boot\n");
        return;
    }
    printf("l8boot: injection enabled for this boot\n");
    if (!L8BOOT_RESPRING) return;
    // SpringBoard started before injection was on, so its tweaks need a fresh
    // process; launchd starts it again.
    if (kill(sb, SIGKILL) == 0) {
        printf("l8boot: restarted SpringBoard (pid %d) so its tweaks load\n", (int)sb);
    } else {
        printf("l8boot: could not restart SpringBoard: %s\n", strerror(errno));
    }
}

int main(int argc, char **argv) {
    // "links" is the host test's entry point: no fork, no waiting.
    int links_only = argc == 2 && strcmp(argv[1], "links") == 0;
    int wait_only = argc == 2 && strcmp(argv[1], "auto") == 0;
    if (argc > 2 || (argc == 2 && !links_only && !wait_only)) {
        fputs("usage: l8boot [links|auto]\n", stderr);
        return 2;
    }
    if (wait_only) {
        auto_enable();
        return 0;
    }
    int linked = ensure_path_links();
    if (links_only) return linked ? 0 : 1;

    fflush(stdout);
    pid_t child = fork();
    if (child < 0) {
        printf("l8boot: fork failed: %s\n", strerror(errno));
        return 1;
    }
    if (child > 0) return linked ? 0 : 1;
    setsid();
    auto_enable();
    return 0;
}
