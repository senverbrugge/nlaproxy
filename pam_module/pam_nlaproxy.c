/*
 * pam_nlaproxy.so — nlaproxy credential cache PAM module.
 *
 * Loaded into the PAM stack for sshd. The module participates in TWO PAM
 * phases:
 *
 *   1. `auth`:  pam_sm_authenticate() runs after the real authenticator
 *               (pam_unix / pam_sss / etc.) has put the typed password in
 *               PAM_AUTHTOK. We snapshot the password into a pam_set_data()
 *               slot before later modules (or sshd itself) wipe PAM_AUTHTOK.
 *               We return PAM_IGNORE so we never affect the auth verdict.
 *
 *   2. `session`: pam_sm_open_session() runs in the post-fork child after the
 *               user is authenticated and the session is being opened. We
 *               retrieve the password from the data slot stashed in step 1
 *               and send it to nlaproxy-cached via a Unix socket.
 *
 * Why two phases? Some PAM stacks (notably sshd on Debian/Ubuntu via
 * pam_keyinit and pam_unix's session module) call pam_set_item(PAM_AUTHTOK,
 * NULL) between auth and session. On those systems PAM_AUTHTOK is already gone
 * by the time we get to open_session, so we must capture it earlier and
 * preserve it ourselves.
 *
 * The data slot lives only for the lifetime of the pam_handle_t (one SSH
 * connection attempt) and is zeroized on free.
 *
 * Design constraints:
 *
 *   - Never fail an SSH login because of us. Every error path returns
 *     PAM_SUCCESS / PAM_IGNORE and emits a syslog warning at worst.
 *
 *   - No credentials in syslog. We log usernames at INFO level on success and
 *     never log passwords or hashes.
 *
 *   - No blocking. The daemon is on a local Unix socket so writes are
 *     effectively instant, but we still set a small per-syscall timeout.
 *
 * Module arguments (configured in /etc/pam.d/sshd):
 *
 *   socket=/run/nlaproxy/cached.sock      Path to the daemon socket
 *   silent                                Do not print warnings to syslog
 *   keys_too                              Also send STOREs when no PAM_AUTHTOK
 *                                         is present (default: skip if no
 *                                         password, e.g. SSH key-only auth)
 *
 * Build:
 *
 *   make -C pam_module
 *   sudo install -m 0755 -o root -g root pam_module/pam_nlaproxy.so /usr/lib/security/
 *
 * /etc/pam.d/sshd snippet - both lines required:
 *
 *   auth       optional    pam_nlaproxy.so
 *   session    optional    pam_nlaproxy.so
 *
 * The `auth` line must appear AFTER the real authenticator (so PAM_AUTHTOK is
 * already populated), e.g. on Debian/Ubuntu:
 *
 *   @include common-auth
 *   auth    optional    pam_nlaproxy.so      # <-- here
 *   ...
 *   @include common-session
 *   session optional    pam_nlaproxy.so      # <-- and here
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define DEFAULT_SOCKET "/run/nlaproxy/cached.sock"
#define WRITE_TIMEOUT_MS 1500
#define READ_TIMEOUT_MS 1500

/* Wire-protocol constants, must match cached/src/main.rs. */
#define TAG_STORE 0x01
#define STATUS_OK 0x00

#define MAX_USERNAME 256
#define MAX_PASSWORD 1024
#define MAX_FRAME 65536

/* pam_set_data slot name - the AUTHTOK we captured in pam_sm_authenticate so
 * that pam_sm_open_session can find it later even if some other module wiped
 * the real PAM_AUTHTOK. */
#define DATA_KEY_AUTHTOK "nlaproxy_authtok"

struct opts {
    const char *socket_path;
    int silent;
    int keys_too;
};

static void parse_opts(struct opts *opts, int argc, const char **argv)
{
    opts->socket_path = DEFAULT_SOCKET;
    opts->silent = 0;
    opts->keys_too = 0;

    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "socket=", 7) == 0) {
            opts->socket_path = argv[i] + 7;
        } else if (strcmp(argv[i], "silent") == 0) {
            opts->silent = 1;
        } else if (strcmp(argv[i], "keys_too") == 0) {
            opts->keys_too = 1;
        }
    }
}

static void mlog(const struct opts *opts, int prio, const char *fmt, ...)
{
    if (opts->silent && prio > LOG_WARNING)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsyslog(prio | LOG_AUTHPRIV, fmt, ap);
    va_end(ap);
}

/* Connect to the daemon socket. Returns >= 0 fd on success or -1 on error. */
static int connect_daemon(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un sa = {0};
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(sa.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);

    /* Apply send/recv timeouts. */
    struct timeval tv;
    tv.tv_sec = WRITE_TIMEOUT_MS / 1000;
    tv.tv_usec = (WRITE_TIMEOUT_MS % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    tv.tv_sec = READ_TIMEOUT_MS / 1000;
    tv.tv_usec = (READ_TIMEOUT_MS % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Write all `len` bytes from `buf` to `fd`. Returns 0 on success, -1 on error. */
static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

/* Read exactly `len` bytes into `buf`. */
static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

/* Send STORE request and read reply. Returns 0 on STATUS_OK, -1 otherwise. */
static int store_credentials(const struct opts *opts,
                             const char *user,
                             const char *pwd)
{
    int fd = connect_daemon(opts->socket_path);
    if (fd < 0) {
        mlog(opts, LOG_WARNING,
             "pam_nlaproxy: connect(%s) failed: %s",
             opts->socket_path, strerror(errno));
        return -1;
    }

    size_t ulen = strlen(user);
    size_t plen = strlen(pwd);
    if (ulen == 0 || ulen > MAX_USERNAME || plen == 0 || plen > MAX_PASSWORD) {
        mlog(opts, LOG_WARNING,
             "pam_nlaproxy: invalid length (user=%zu pwd=%zu)", ulen, plen);
        close(fd);
        return -1;
    }

    /* Frame: u32_be length | u8 tag | u16_be ulen | user | u16_be plen | pwd */
    size_t body_len = 1 /* tag */
                    + 2 + ulen
                    + 2 + plen;
    if (body_len > MAX_FRAME) {
        close(fd);
        return -1;
    }
    uint8_t *frame = malloc(4 + body_len);
    if (!frame) {
        close(fd);
        return -1;
    }

    /* u32 BE length */
    frame[0] = (uint8_t)((body_len >> 24) & 0xff);
    frame[1] = (uint8_t)((body_len >> 16) & 0xff);
    frame[2] = (uint8_t)((body_len >> 8)  & 0xff);
    frame[3] = (uint8_t)( body_len        & 0xff);
    /* tag */
    frame[4] = TAG_STORE;
    /* ulen + user */
    frame[5] = (uint8_t)((ulen >> 8) & 0xff);
    frame[6] = (uint8_t)( ulen       & 0xff);
    memcpy(frame + 7, user, ulen);
    /* plen + pwd */
    size_t off = 7 + ulen;
    frame[off++] = (uint8_t)((plen >> 8) & 0xff);
    frame[off++] = (uint8_t)( plen       & 0xff);
    memcpy(frame + off, pwd, plen);

    int rc = write_all(fd, frame, 4 + body_len);
    /* Zero the frame buffer before freeing - it contains the password. */
    memset(frame, 0, 4 + body_len);
    free(frame);

    if (rc < 0) {
        mlog(opts, LOG_WARNING,
             "pam_nlaproxy: send failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Read reply: u32_be length | u8 status */
    uint8_t lenbuf[4];
    if (read_all(fd, lenbuf, 4) < 0) {
        mlog(opts, LOG_WARNING,
             "pam_nlaproxy: read len failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    uint32_t rl = ((uint32_t)lenbuf[0] << 24)
                | ((uint32_t)lenbuf[1] << 16)
                | ((uint32_t)lenbuf[2] << 8)
                |  (uint32_t)lenbuf[3];
    if (rl == 0 || rl > MAX_FRAME) {
        mlog(opts, LOG_WARNING,
             "pam_nlaproxy: malformed reply length %u", rl);
        close(fd);
        return -1;
    }
    uint8_t status = 0;
    if (read_all(fd, &status, 1) < 0) {
        mlog(opts, LOG_WARNING,
             "pam_nlaproxy: read status failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    /* Drain any remaining bytes the daemon sent (none expected for STORE). */
    if (rl > 1) {
        uint8_t junk[64];
        size_t remaining = rl - 1;
        while (remaining > 0) {
            size_t chunk = remaining < sizeof(junk) ? remaining : sizeof(junk);
            if (read_all(fd, junk, chunk) < 0)
                break;
            remaining -= chunk;
        }
    }
    close(fd);

    if (status != STATUS_OK) {
        mlog(opts, LOG_WARNING,
             "pam_nlaproxy: daemon STORE returned status 0x%02x", status);
        return -1;
    }
    return 0;
}

/*
 * pam_set_data cleanup callback. Called when the pam_handle_t is destroyed
 * (i.e. at the end of the SSH connection attempt) or when the slot is
 * overwritten. We zero the buffer before freeing so that the password is not
 * left in process memory longer than necessary.
 */
static void authtok_cleanup(pam_handle_t *pamh, void *data, int error_status)
{
    (void)pamh;
    (void)error_status;
    if (!data)
        return;
    /* `data` was allocated by us as strdup(token); it is NUL-terminated. */
    char *p = (char *)data;
    size_t n = strlen(p);
    /* explicit_bzero is the right primitive but isn't available everywhere;
     * volatile + memset is the portable fallback. */
    volatile char *v = p;
    while (n--)
        *v++ = 0;
    free(p);
}

/*
 * Auth hook: invoked from sshd's `auth` PAM stack. Runs AFTER the real
 * authenticator has populated PAM_AUTHTOK with the password the user typed.
 * We snapshot it into a pam_set_data slot so that pam_sm_open_session() can
 * find it even if another module (or sshd itself) later scrubs PAM_AUTHTOK.
 *
 * We do NOT participate in the auth verdict (return PAM_IGNORE), so a stack
 * line of either `auth optional` or `auth required` is safe; PAM treats
 * PAM_IGNORE as "this module had no opinion".
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv)
{
    (void)flags;
    struct opts opts;
    parse_opts(&opts, argc, argv);

    openlog("pam_nlaproxy", LOG_PID, LOG_AUTHPRIV);

    const char *user = NULL;
    int rc = pam_get_item(pamh, PAM_USER, (const void **)&user);
    if (rc != PAM_SUCCESS || user == NULL || user[0] == '\0') {
        mlog(&opts, LOG_DEBUG,
             "pam_nlaproxy(auth): no PAM_USER yet, nothing to snapshot");
        closelog();
        return PAM_IGNORE;
    }

    const char *pwd = NULL;
    rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pwd);
    if (rc != PAM_SUCCESS || pwd == NULL || pwd[0] == '\0') {
        /* No password available - either this is key/Kerberos auth, or our
         * line was placed before the real authenticator. Nothing to do. */
        mlog(&opts, LOG_DEBUG,
             "pam_nlaproxy(auth): no PAM_AUTHTOK for user %s (key auth or wrong stack position)",
             user);
        closelog();
        return PAM_IGNORE;
    }

    size_t plen = strlen(pwd);
    if (plen == 0 || plen > MAX_PASSWORD) {
        mlog(&opts, LOG_WARNING,
             "pam_nlaproxy(auth): PAM_AUTHTOK has unusable length %zu", plen);
        closelog();
        return PAM_IGNORE;
    }

    char *copy = strdup(pwd);
    if (!copy) {
        mlog(&opts, LOG_WARNING, "pam_nlaproxy(auth): strdup failed");
        closelog();
        return PAM_IGNORE;
    }

    /* Stash on the pam handle. Replaces any previous slot, which is fine -
     * libpam will call our cleanup on the previous value first. */
    rc = pam_set_data(pamh, DATA_KEY_AUTHTOK, copy, authtok_cleanup);
    if (rc != PAM_SUCCESS) {
        mlog(&opts, LOG_WARNING,
             "pam_nlaproxy(auth): pam_set_data failed: %d (%s)",
             rc, pam_strerror(pamh, rc));
        /* pam_set_data did not take ownership; we must free `copy` ourselves. */
        authtok_cleanup(pamh, copy, 0);
        closelog();
        return PAM_IGNORE;
    }
    mlog(&opts, LOG_DEBUG,
         "pam_nlaproxy(auth): snapshotted PAM_AUTHTOK for user %s (%zu bytes)",
         user, plen);
    closelog();
    return PAM_IGNORE;
}

/*
 * Session hook: invoked when sshd opens the session for the authenticated
 * user. Most distributions wipe PAM_AUTHTOK between auth and session via
 * pam_keyinit / pam_unix's session module, so we look at our own data slot
 * first and only fall back to PAM_AUTHTOK as a courtesy.
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv)
{
    (void)flags;
    struct opts opts;
    parse_opts(&opts, argc, argv);

    openlog("pam_nlaproxy", LOG_PID, LOG_AUTHPRIV);

    const char *user = NULL;
    int rc = pam_get_item(pamh, PAM_USER, (const void **)&user);
    if (rc != PAM_SUCCESS || user == NULL || user[0] == '\0') {
        mlog(&opts, LOG_DEBUG, "pam_nlaproxy: no PAM_USER, skipping");
        closelog();
        return PAM_SUCCESS;
    }

    const char *pwd = NULL;
    const void *stashed = NULL;
    rc = pam_get_data(pamh, DATA_KEY_AUTHTOK, &stashed);
    if (rc == PAM_SUCCESS && stashed != NULL && ((const char *)stashed)[0] != '\0') {
        pwd = (const char *)stashed;
        mlog(&opts, LOG_DEBUG,
             "pam_nlaproxy: using PAM_AUTHTOK snapshot for user %s", user);
    } else {
        /* Fall back to live PAM_AUTHTOK - works on stacks that don't wipe it
         * and is also useful as a sanity check / migration path. */
        rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pwd);
        if (rc == PAM_SUCCESS && pwd != NULL && pwd[0] != '\0') {
            mlog(&opts, LOG_DEBUG,
                 "pam_nlaproxy: using live PAM_AUTHTOK for user %s "
                 "(no snapshot - is the `auth` line installed?)",
                 user);
        } else {
            pwd = NULL;
        }
    }

    if (pwd == NULL) {
        if (!opts.keys_too) {
            mlog(&opts, LOG_DEBUG,
                 "pam_nlaproxy: no password available for user %s, skipping "
                 "(key auth, or pam_nlaproxy.so missing from the `auth` stack)",
                 user);
        } else {
            mlog(&opts, LOG_DEBUG,
                 "pam_nlaproxy: no password available for user %s, skipping "
                 "(keys_too set, but nothing to cache)",
                 user);
        }
        closelog();
        return PAM_SUCCESS;
    }

    if (store_credentials(&opts, user, pwd) == 0) {
        mlog(&opts, LOG_INFO,
             "pam_nlaproxy: cached credentials for user %s", user);
    }
    /* Even on failure we return PAM_SUCCESS - we must never block SSH. */
    closelog();
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
                                    int flags,
                                    int argc,
                                    const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    /*
     * Intentionally do NOT evict on close: the user's SSH session might end
     * before they fire up the RDP/PAM-server connection. The daemon-side TTL
     * handles cleanup.
     */
    return PAM_SUCCESS;
}

/*
 * Stubs for hooks we don't implement. We deliberately return PAM_IGNORE so
 * that the module is safe to load on any sub-stack (account / password /
 * setcred) without affecting the policy decision.
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
