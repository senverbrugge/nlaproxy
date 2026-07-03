/*
 * proxy-nlaproxy-plugin.so — nlaproxy FreeRDP-proxy3 plugin.
 *
 * Hooks into freerdp-proxy3 (the FreeRDP RDP gateway) to bridge NLA-required
 * clients (Delinea Secret Server RDP proxy, CyberArk PSM, mstsc, etc.) onto
 * a non-NLA xrdp on the same host. The plugin provides four things:
 *
 *   1. ServerSessionInitialize: assign `peer->SspiNtlmHashCallback` to our
 *      callback. FreeRDP's NLA server-side code path picks that up
 *      (credssp_auth_setup_identity() reads `peer->SspiNtlmHashCallback` at
 *      line ~956 of libfreerdp/core/credssp_auth.c on 3.24.2) and gives us
 *      full control over NTOWFv2 derivation on every incoming NLA session.
 *
 *   2. NtlmHashCallback: WinPR calls this once per session with the
 *      (user, domain) the client presented. We query nlaproxy-cached over
 *      a Unix socket for the NT-hash of that user (cached from an earlier
 *      SSH login), then compute NTOWFv2 with the *exact* Domain the client
 *      sent - so MIC verification passes regardless of what domain string
 *      the client chose. No SAM file is used.
 *
 *   3. ServerPeerLogon: return TRUE. Auth already validated by the time we
 *      get here (WinPR only calls us via the callback if the user has a
 *      cached NT-hash), so accept.
 *
 *   4. ServerPostConnect: after CredSSP completed, look up the *plaintext*
 *      password from nlaproxy-cached by username, and inject it into the
 *      upstream `pClientContext` settings so xrdp can PAM-authenticate. This
 *      is the moment where plaintext briefly touches this process (it's on
 *      an anonymous heap buffer, zeroized after use).
 *
 *   5. ClientLoginFailure: best-effort EVICT so a stale/rotated password is
 *      not retried on the next attempt.
 *
 * Plugin configuration (via environment variables read at plugin load):
 *
 *   NLAPROXY_PLUGIN_SOCKET    Daemon socket path (default /run/nlaproxy/cached.sock)
 *   NLAPROXY_PLUGIN_REQUIRE   "1" = abort session if no cached creds (default 1)
 *
 * Build:
 *   make
 * Install:
 *   sudo install -m 0755 proxy-nlaproxy-plugin.so \
 *       /usr/lib/x86_64-linux-gnu/freerdp3/proxy/     # Debian/Ubuntu
 *   sudo install -m 0755 proxy-nlaproxy-plugin.so \
 *       /usr/lib/freerdp/server/proxy/plugins/         # Arch
 *
 * proxy.ini snippet:
 *   [Plugins]
 *   Modules=nlaproxy
 *   Required=nlaproxy
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <freerdp/api.h>
#include <freerdp/freerdp.h>
#include <freerdp/peer.h>
#include <freerdp/settings.h>
#include <freerdp/server/proxy/proxy_context.h>
#include <freerdp/server/proxy/proxy_log.h>
#include <freerdp/server/proxy/proxy_modules_api.h>

#include <winpr/crypto.h>   /* winpr_HMAC + WINPR_MD_MD5 - for NTOWFv2 */
#include <winpr/sspi.h>
#include <winpr/winpr.h>
#include <winpr/wlog.h>

#define TAG MODULE_TAG("nlaproxy")

#define PLUGIN_NAME "nlaproxy"
#define PLUGIN_DESC \
    "Bridge NLA-enforced RDP clients to xrdp by serving NTLM SspiNtlmHashCallback " \
    "from an nlaproxy-cached daemon (which harvests passwords from SSH logins)."

#define DEFAULT_SOCKET "/run/nlaproxy/cached.sock"
#define WRITE_TIMEOUT_MS 1500
#define READ_TIMEOUT_MS 1500

/* Wire protocol - must match cached/src/main.rs */
#define LOOKUP_TAG 0x02
#define EVICT_TAG  0x03
#define NTHASH_TAG 0x05
#define STATUS_REPLY_OK        0x00
#define STATUS_REPLY_NOT_FOUND 0x01

#define MAX_USERNAME 256
#define MAX_PASSWORD 1024
#define MAX_FRAME 65536

struct plugin_state {
    char *socket_path;
    int require_cache;
};

/*
 * Process-wide socket path used by our NTLM hash callback (see below). We
 * capture it here at plugin load so the callback - which receives only a
 * `freerdp_peer*` as context - can reach the daemon without wading through
 * proxyData/plugin state lookups from an SSPI callsite.
 */
static char *g_daemon_socket = NULL;

/*
 * Per-session `(freerdp_peer* -> username)` map.
 *
 * WHY THIS EXISTS:
 * During NLA, WinPR invokes our `SspiNtlmHashCallback` with the User field
 * from the client's AUTHENTICATE_MESSAGE (the ACTUAL Linux account the
 * client is authenticating as - e.g. `ngh-del-la-01`).
 *
 * Later, in `nla_decrypt_ts_credentials()` (FreeRDP core), the proxy decrypts
 * the TSPasswordCreds `authInfo` blob the client sent and OVERWRITES
 * `settings->{Username,Password,Domain}` with what's inside.
 *
 * For a direct NLA client that's harmless - it's the same identity. But for a
 * relaying RDP proxy like Delinea Secret Server's PSM, the client authenticates
 * to Delinea with the real vault account name, then Delinea forwards the RDP
 * stream to us but replaces the `authInfo` with its own one-time UUID/token.
 * By the time `ServerPostConnect` runs, `settings->Username` is that UUID,
 * not the account we want to log into on xrdp.
 *
 * So we stash the real username - the one WinPR saw during NLA - keyed by
 * `freerdp_peer*` (which is stable for the session), and retrieve it in
 * `ServerPostConnect`. If it's absent (e.g. NLA wasn't used), we fall back
 * to `FreeRDP_Username`.
 */
struct session_user {
    freerdp_peer *peer;
    char *user;
    struct session_user *next;
};
static struct session_user *g_sessions = NULL;
static pthread_mutex_t g_sessions_lock = PTHREAD_MUTEX_INITIALIZER;

static void session_remember(freerdp_peer *peer, const char *user)
{
    if (!peer || !user)
        return;
    pthread_mutex_lock(&g_sessions_lock);
    struct session_user *s;
    for (s = g_sessions; s; s = s->next) {
        if (s->peer == peer) {
            free(s->user);
            s->user = strdup(user);
            pthread_mutex_unlock(&g_sessions_lock);
            return;
        }
    }
    s = calloc(1, sizeof(*s));
    if (!s) {
        pthread_mutex_unlock(&g_sessions_lock);
        return;
    }
    s->peer = peer;
    s->user = strdup(user);
    s->next = g_sessions;
    g_sessions = s;
    pthread_mutex_unlock(&g_sessions_lock);
}

static char *session_take(freerdp_peer *peer)
{
    if (!peer)
        return NULL;
    pthread_mutex_lock(&g_sessions_lock);
    struct session_user **pp = &g_sessions;
    while (*pp) {
        if ((*pp)->peer == peer) {
            struct session_user *s = *pp;
            *pp = s->next;
            char *u = s->user;
            free(s);
            pthread_mutex_unlock(&g_sessions_lock);
            return u; /* caller owns */
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&g_sessions_lock);
    return NULL;
}

static void session_forget(freerdp_peer *peer)
{
    char *u = session_take(peer);
    if (u) {
        memset(u, 0, strlen(u));
        free(u);
    }
}

/* ------------------------------------------------------------------------- */
/* I/O helpers                                                                */
/* ------------------------------------------------------------------------- */

static int connect_daemon(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(sa.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);

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

/*
 * Look up the plaintext password for `user` from the cache daemon. On success
 * sets *pwd_out to a newly-allocated NUL-terminated string the caller must
 * `memset` then `free()`. Returns:
 *
 *   0 on STATUS_OK with password
 *   1 on STATUS_NOT_FOUND
 *  -1 on transport / protocol error
 */
static int lookup_password(const char *socket_path,
                           const char *user,
                           char **pwd_out)
{
    *pwd_out = NULL;
    int fd = connect_daemon(socket_path);
    if (fd < 0)
        return -1;

    size_t ulen = strlen(user);
    if (ulen == 0 || ulen > MAX_USERNAME) {
        close(fd);
        return -1;
    }

    /* Frame: u32_be length | u8 tag | u16_be ulen | user */
    size_t body_len = 1 + 2 + ulen;
    uint8_t frame[4 + 1 + 2 + MAX_USERNAME];
    frame[0] = (uint8_t)((body_len >> 24) & 0xff);
    frame[1] = (uint8_t)((body_len >> 16) & 0xff);
    frame[2] = (uint8_t)((body_len >> 8)  & 0xff);
    frame[3] = (uint8_t)( body_len        & 0xff);
    frame[4] = LOOKUP_TAG;
    frame[5] = (uint8_t)((ulen >> 8) & 0xff);
    frame[6] = (uint8_t)( ulen       & 0xff);
    memcpy(frame + 7, user, ulen);

    if (write_all(fd, frame, 4 + body_len) < 0) {
        close(fd);
        return -1;
    }

    /* Read reply length */
    uint8_t lenbuf[4];
    if (read_all(fd, lenbuf, 4) < 0) {
        close(fd);
        return -1;
    }
    uint32_t rl = ((uint32_t)lenbuf[0] << 24)
                | ((uint32_t)lenbuf[1] << 16)
                | ((uint32_t)lenbuf[2] << 8)
                |  (uint32_t)lenbuf[3];
    if (rl == 0 || rl > MAX_FRAME) {
        close(fd);
        return -1;
    }

    uint8_t status = 0;
    if (read_all(fd, &status, 1) < 0) {
        close(fd);
        return -1;
    }

    if (status == STATUS_REPLY_NOT_FOUND) {
        close(fd);
        return 1;
    }
    if (status != STATUS_REPLY_OK) {
        /* drain rest and bail */
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
        return -1;
    }
    /* OK reply body: u16_be plen | password */
    if (rl < 3) {
        close(fd);
        return -1;
    }
    uint8_t plenbuf[2];
    if (read_all(fd, plenbuf, 2) < 0) {
        close(fd);
        return -1;
    }
    uint16_t plen = ((uint16_t)plenbuf[0] << 8) | (uint16_t)plenbuf[1];
    if (plen == 0 || plen > MAX_PASSWORD || (size_t)(3u + plen) != rl) {
        close(fd);
        return -1;
    }
    char *password = calloc(1, (size_t)plen + 1);
    if (!password) {
        close(fd);
        return -1;
    }
    if (read_all(fd, password, plen) < 0) {
        memset(password, 0, plen);
        free(password);
        close(fd);
        return -1;
    }
    password[plen] = '\0';
    close(fd);
    *pwd_out = password;
    return 0;
}

/*
 * Ask the daemon for the raw NT-hash of `user`'s cached password.
 *
 * On success writes 16 bytes into `nthash_out`. Returns:
 *    0 on OK,
 *    1 on NOT_FOUND,
 *   -1 on transport/protocol error.
 *
 * The plaintext password never leaves the daemon in this path - only its
 * MD4(UTF-16LE(password)) does. That's still password-equivalent for NLA
 * verification, but is not directly useable for anything else.
 */
static int lookup_nt_hash(const char *socket_path, const char *user,
                          uint8_t nthash_out[16])
{
    int fd = connect_daemon(socket_path);
    if (fd < 0)
        return -1;

    size_t ulen = strlen(user);
    if (ulen == 0 || ulen > MAX_USERNAME) {
        close(fd);
        return -1;
    }

    size_t body_len = 1 + 2 + ulen;
    uint8_t frame[4 + 1 + 2 + MAX_USERNAME];
    frame[0] = (uint8_t)((body_len >> 24) & 0xff);
    frame[1] = (uint8_t)((body_len >> 16) & 0xff);
    frame[2] = (uint8_t)((body_len >> 8)  & 0xff);
    frame[3] = (uint8_t)( body_len        & 0xff);
    frame[4] = NTHASH_TAG;
    frame[5] = (uint8_t)((ulen >> 8) & 0xff);
    frame[6] = (uint8_t)( ulen       & 0xff);
    memcpy(frame + 7, user, ulen);

    if (write_all(fd, frame, 4 + body_len) < 0) {
        close(fd);
        return -1;
    }

    uint8_t lenbuf[4];
    if (read_all(fd, lenbuf, 4) < 0) {
        close(fd);
        return -1;
    }
    uint32_t rl = ((uint32_t)lenbuf[0] << 24)
                | ((uint32_t)lenbuf[1] << 16)
                | ((uint32_t)lenbuf[2] << 8)
                |  (uint32_t)lenbuf[3];
    if (rl == 0 || rl > MAX_FRAME) {
        close(fd);
        return -1;
    }

    uint8_t status = 0;
    if (read_all(fd, &status, 1) < 0) {
        close(fd);
        return -1;
    }
    if (status == STATUS_REPLY_NOT_FOUND) {
        close(fd);
        return 1;
    }
    if (status != STATUS_REPLY_OK) {
        close(fd);
        return -1;
    }
    if (rl != 1 + 16) {
        close(fd);
        return -1;
    }
    if (read_all(fd, nthash_out, 16) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/* Send EVICT for `user`. Best-effort, always returns void. */
static void evict_password(const char *socket_path, const char *user)
{
    int fd = connect_daemon(socket_path);
    if (fd < 0)
        return;
    size_t ulen = strlen(user);
    if (ulen == 0 || ulen > MAX_USERNAME) {
        close(fd);
        return;
    }
    size_t body_len = 1 + 2 + ulen;
    uint8_t frame[4 + 1 + 2 + MAX_USERNAME];
    frame[0] = (uint8_t)((body_len >> 24) & 0xff);
    frame[1] = (uint8_t)((body_len >> 16) & 0xff);
    frame[2] = (uint8_t)((body_len >> 8)  & 0xff);
    frame[3] = (uint8_t)( body_len        & 0xff);
    frame[4] = EVICT_TAG;
    frame[5] = (uint8_t)((ulen >> 8) & 0xff);
    frame[6] = (uint8_t)( ulen       & 0xff);
    memcpy(frame + 7, user, ulen);
    (void)write_all(fd, frame, 4 + body_len);
    /* We don't care about the reply but read it to be polite. */
    uint8_t lenbuf[4];
    if (read_all(fd, lenbuf, 4) == 0) {
        uint32_t rl = ((uint32_t)lenbuf[0] << 24)
                    | ((uint32_t)lenbuf[1] << 16)
                    | ((uint32_t)lenbuf[2] << 8)
                    |  (uint32_t)lenbuf[3];
        if (rl > 0 && rl <= 16) {
            uint8_t junk[16];
            (void)read_all(fd, junk, rl);
        }
    }
    close(fd);
}

/* ------------------------------------------------------------------------- */
/* Plugin hooks                                                              */
/* ------------------------------------------------------------------------- */

WINPR_ATTR_NODISCARD
static BOOL nlaproxy_plugin_unload(proxyPlugin *plugin)
{
    if (plugin && plugin->custom) {
        struct plugin_state *st = (struct plugin_state *)plugin->custom;
        free(st->socket_path);
        free(st);
        plugin->custom = NULL;
    }
    free(g_daemon_socket);
    g_daemon_socket = NULL;
    /* Free any leftover session map entries. */
    pthread_mutex_lock(&g_sessions_lock);
    while (g_sessions) {
        struct session_user *s = g_sessions;
        g_sessions = s->next;
        if (s->user) {
            memset(s->user, 0, strlen(s->user));
            free(s->user);
        }
        free(s);
    }
    pthread_mutex_unlock(&g_sessions_lock);
    return TRUE;
}

/*
 * Convert a UTF-16LE WCHAR buffer to a UTF-8 C string. Returns a newly
 * allocated NUL-terminated string, or NULL on failure. Length is in WCHARs.
 */
static char *utf16_to_utf8_alloc(const WCHAR *w, size_t wchars)
{
    if (!w || wchars == 0) {
        char *empty = calloc(1, 1);
        return empty;
    }
    /* Cheap ASCII-only conversion. This is fine for Linux account names
     * (which are ASCII 99.99% of the time). WinPR does full UTF-16 -> UTF-8
     * conversion in `ConvertWCharNToUtf8Alloc`, which would be more correct
     * for non-ASCII usernames, but for our target audience (Linux account
     * names harvested from sshd's PAM stack) this is more than enough. */
    char *out = calloc(wchars + 1, 1);
    if (!out) return NULL;
    for (size_t i = 0; i < wchars; i++) {
        uint16_t c = w[i];
        out[i] = (c < 0x80) ? (char)c : '?';
    }
    out[wchars] = 0;
    return out;
}

/*
 * psSspiNtlmHashCallback implementation. Called by WinPR's NTLM subsystem
 * during `ntlm_compute_ntlm_v2_hash()` if the credentials have neither a
 * plaintext password nor a pre-set NT hash - i.e. our path.
 *
 * Contract (from winpr/sspi.h):
 *   input:  authIdentity->{User,UserLength,Domain,DomainLength} - UTF-16LE,
 *           length in WCHARs (not bytes)
 *   output: 16-byte NTOWFv2 = HMAC-MD5(NT-hash, UTF-16LE(Uppercase(user)||domain))
 *
 * We use `NTOWFv2FromHashW` from libwinpr, which does the uppercase-user +
 * concat-domain + HMAC-MD5 correctly, so we only need to source the raw
 * NT-hash (MD4 of UTF-16LE(password)) from the daemon.
 *
 * Return SEC_E_OK on success. WinPR 3.24.0 fixed the return-code check
 * (previously it accepted 1 for success); we return SEC_E_OK unconditionally
 * on success to work on both.
 */
static SECURITY_STATUS nlaproxy_ntlm_hash_cb(void *client,
                                             const SEC_WINNT_AUTH_IDENTITY *authIdentity,
                                             const SecBuffer *ntproofvalue,
                                             const BYTE *randkey,
                                             const BYTE *mic,
                                             const SecBuffer *micvalue,
                                             BYTE *ntlmhash /* out, 16 bytes */)
{
    /* Unused - these are handed to us for advanced verification/relay scenarios
     * we don't need. See the doxygen for psSspiNtlmHashCallback. */
    (void)ntproofvalue;
    (void)randkey;
    (void)mic;
    (void)micvalue;

    /* `client` is what credssp_auth stored as `hashCallbackArg` - which is the
     * `freerdp_peer*` (see credssp_auth.c line 959). We use it as the session
     * key for our (peer -> username) stash so ServerPostConnect can retrieve
     * the same username later, bypassing anything Delinea's proxy may have
     * rewritten into `settings->Username` via the TSPasswordCreds forwarding. */
    freerdp_peer *peer = (freerdp_peer *)client;

    if (!authIdentity || !ntlmhash)
        return SEC_E_INVALID_PARAMETER;
    if (!g_daemon_socket) {
        WLog_ERR(TAG, "hash callback fired but daemon socket path is not set");
        return SEC_E_INTERNAL_ERROR;
    }

    /* SEC_WINNT_AUTH_IDENTITY on WinPR aliases to SEC_WINNT_AUTH_IDENTITY_W
     * for UTF-16LE builds. Lengths are in WCHARs. */
    const WCHAR *user_w    = (const WCHAR *)authIdentity->User;
    const ULONG  user_wchars = authIdentity->UserLength;
    const WCHAR *domain_w  = (const WCHAR *)authIdentity->Domain;
    const ULONG  domain_wchars = authIdentity->DomainLength;

    /* Convert User to UTF-8 for our daemon query. */
    char *user_utf8 = utf16_to_utf8_alloc(user_w, user_wchars);
    if (!user_utf8)
        return SEC_E_INSUFFICIENT_MEMORY;

    /* For logging only. */
    char *domain_utf8 = utf16_to_utf8_alloc(domain_w, domain_wchars);
    WLog_INFO(TAG,
              "NTLM hash callback: user='%s' domain='%s' (u_wc=%lu d_wc=%lu)",
              user_utf8, domain_utf8 ? domain_utf8 : "",
              (unsigned long)user_wchars, (unsigned long)domain_wchars);
    free(domain_utf8);

    /* Remember the real username for this session, so ServerPostConnect can
     * look up the plaintext password by the SAME identity WinPR just used to
     * derive the NTLMv2 hash - not the potentially-rewritten Username in
     * settings. */
    if (peer)
        session_remember(peer, user_utf8);

    /* Ask the daemon for the NT-hash of the cached password. */
    uint8_t nthash[16];
    int rc = lookup_nt_hash(g_daemon_socket, user_utf8, nthash);
    if (rc == 1) {
        WLog_WARN(TAG, "no cached NT-hash for user '%s' - "
                       "SSH-cache expired or user not in cache", user_utf8);
        free(user_utf8);
        return SEC_E_NO_CREDENTIALS;
    }
    if (rc < 0) {
        WLog_ERR(TAG, "NT-hash lookup failed for user '%s' (errno=%d %s)",
                 user_utf8, errno, strerror(errno));
        free(user_utf8);
        return SEC_E_INTERNAL_ERROR;
    }
    free(user_utf8);

    /* Compute NTOWFv2 from the raw NT-hash and the exact (user, domain) the
     * client sent. Doing it here (instead of in the daemon) means we're
     * matching whatever Domain string the client chose - no SAM synonym rows
     * needed. `NTOWFv2FromHashW` takes byte lengths, hence *2. */
    if (!NTOWFv2FromHashW(nthash,
                          (LPWSTR)user_w,   (UINT32)(user_wchars * 2),
                          (LPWSTR)domain_w, (UINT32)(domain_wchars * 2),
                          ntlmhash)) {
        memset(nthash, 0, sizeof(nthash));
        WLog_ERR(TAG, "NTOWFv2FromHashW failed");
        return SEC_E_INTERNAL_ERROR;
    }
    memset(nthash, 0, sizeof(nthash));
    return SEC_E_OK;
}

/*
 * ServerSessionInitialize: called immediately after the peer context is
 * initialized and BEFORE FreeRDP's NLA server bring-up (`client->Initialize`).
 * We do two things here:
 *
 *   (1) Install our NTLM hash callback on the peer - which is then copied
 *       into `ntlmSettings.hashCallback` by `credssp_auth_setup_identity()`
 *       and reaches WinPR's `AcquireCredentialsHandle` as part of the
 *       extended auth identity struct.
 *
 *   (2) Turn off a couple of optional post-NLA features that some RDP
 *       proxies (Delinea Secret Server's RDP proxy in particular) do not
 *       tolerate. Specifically:
 *
 *       - `FreeRDP_NetworkAutoDetect` = FALSE.
 *         Otherwise the proxy sends an auto-detect request PDU right after
 *         `SECURE_SETTINGS_EXCHANGE` (state `CONNECT_TIME_AUTO_DETECT_REQUEST`).
 *         Delinea's RDP proxy silently drops the connection here.
 *
 *       - `FreeRDP_SupportHeartbeatPdu` = FALSE.
 *         Same rationale; not all RDP proxies handle heartbeat PDUs and
 *         they add no value for our use case.
 *
 * `param` is a `freerdp_peer*`.
 */
WINPR_ATTR_NODISCARD
static BOOL nlaproxy_server_session_initialize(proxyPlugin *plugin,
                                               proxyData *pdata,
                                               void *param)
{
    (void)pdata;
    if (!plugin)
        return TRUE;

    freerdp_peer *peer = (freerdp_peer *)param;
    if (!peer) {
        WLog_WARN(TAG, "ServerSessionInitialize: no peer, cannot install NTLM callback");
        return TRUE;
    }

    peer->SspiNtlmHashCallback = nlaproxy_ntlm_hash_cb;
    WLog_DBG(TAG, "installed SspiNtlmHashCallback on peer");

    if (peer->context && peer->context->settings) {
        rdpSettings *s = peer->context->settings;
        /* We ignore failures - these are best-effort tweaks. */
        (void)freerdp_settings_set_bool(s, FreeRDP_NetworkAutoDetect, FALSE);
        (void)freerdp_settings_set_bool(s, FreeRDP_SupportHeartbeatPdu, FALSE);
        /*
         * Force fast-path output ON for the front-side session. Some upstream
         * RDP proxies (notably Delinea Secret Server's RDP relay) fail to
         * advertise the RNS_UD_CS_FASTPATH_OUTPUT bit in their Client Core
         * Data even though they can decode fast-path output PDUs just fine.
         * Without this override, FreeRDP's front server aborts as soon as
         * xrdp sends its first fast-path screen update, with:
         *
         *     [fastpath_send_update_pdu]: client does not support fast path
         *     output
         *
         * which kills the session ~2s after the desktop starts drawing.
         *
         * This is safe: if the client genuinely cannot decode fast-path
         * output, the wire will look malformed on their end and they'll
         * disconnect - identical failure to what we already see. In practice
         * every RDP client we've encountered handles fast-path output.
         */
        (void)freerdp_settings_set_bool(s, FreeRDP_FastPathOutput, TRUE);
        WLog_DBG(TAG,
                 "disabled NetworkAutoDetect + SupportHeartbeatPdu, "
                 "forced FastPathOutput=TRUE on peer settings");
    }
    return TRUE;
}

/*
 * ServerPeerLogon: invoked from `pf_server_logon` after CredSSP's NTLM
 * server-side verification has succeeded (the client's NTProofStr matched the
 * NT-OWF we have in the SAM file). We trust the SAM file as the gatekeeper and
 * always accept here.
 */
WINPR_ATTR_NODISCARD
static BOOL nlaproxy_server_peer_logon(proxyPlugin *plugin,
                                       proxyData *pdata,
                                       void *param)
{
    (void)plugin;
    (void)pdata;
    const proxyServerPeerLogon *info = (const proxyServerPeerLogon *)param;
    if (!info || !info->identity) {
        /* This shouldn't happen, but if it does, fail safely. */
        WLog_WARN(TAG, "ServerPeerLogon called without an identity");
        return FALSE;
    }
    WLog_DBG(TAG, "ServerPeerLogon ok (automatic=%d)", info->automatic);
    return TRUE;
}

/*
 * ServerPostConnect: after CredSSP and before the upstream RDP client thread
 * is started. We look up the plaintext password by the username CredSSP gave
 * us, and inject it into the upstream client settings.
 */
WINPR_ATTR_NODISCARD
static BOOL nlaproxy_server_post_connect(proxyPlugin *plugin,
                                         proxyData *pdata,
                                         void *param)
{
    if (!plugin || !plugin->custom || !pdata)
        return FALSE;

    struct plugin_state *st = (struct plugin_state *)plugin->custom;
    freerdp_peer *peer = (freerdp_peer *)param;

    /*
     * proxyData exposes pointers to the front/back contexts. The exact public
     * type of these fields varies across FreeRDP releases:
     *
     *   * FreeRDP <= 3.24:  proxy_data.ps is `pServerContext*`,
     *                       proxy_data.pc is `pClientContext*`
     *                       (concrete structs whose first member is `rdpContext context`)
     *   * FreeRDP >= 3.27:  proxy_data.ps and pc are `rdpContext*`
     *                       (concrete structs are opaque in the public header)
     *
     * Either way the underlying pointer always points at memory that starts
     * with an `rdpContext`. We launder it through `void*` so the cast works
     * regardless of which header version we're compiled against.
     */
    rdpContext *fctx = (rdpContext *)(void *)pdata->ps;
    rdpContext *bctx = (rdpContext *)(void *)pdata->pc;
    if (!fctx || !bctx) {
        WLog_ERR(TAG, "ServerPostConnect: missing front/back rdpContext");
        return FALSE;
    }

    rdpSettings *front = fctx->settings;
    rdpSettings *back = bctx->settings;
    if (!front || !back) {
        WLog_ERR(TAG, "ServerPostConnect: missing rdpSettings");
        return FALSE;
    }

    /*
     * Determine the real user we need to log into xrdp as.
     *
     * The naive approach - reading FreeRDP_Username from front settings -
     * is INCORRECT when the client's NLA is being forwarded through a
     * relaying RDP proxy (Delinea Secret Server, some PSM broker configs).
     * Those proxies validate the client's NLA against their own vault, then
     * rewrite the TSPasswordCreds `authInfo` blob with their own one-time
     * UUID/token before forwarding it to us. `nla_decrypt_ts_credentials()`
     * then overwrites settings->{Username,Password,Domain} with that garbage.
     *
     * The REAL identity the client authenticated as is what WinPR saw during
     * NLA - the User field of the NTLMv2 AUTHENTICATE_MESSAGE - which we
     * captured in the SspiNtlmHashCallback and stashed keyed on freerdp_peer*.
     */
    char *stashed = session_take(peer);
    const char *raw_user;
    if (stashed && stashed[0]) {
        raw_user = stashed;
        WLog_DBG(TAG,
                 "ServerPostConnect: using NLA-captured username '%s' (not settings->Username='%s')",
                 raw_user,
                 freerdp_settings_get_string(front, FreeRDP_Username));
    } else {
        raw_user = freerdp_settings_get_string(front, FreeRDP_Username);
        WLog_DBG(TAG,
                 "ServerPostConnect: no NLA capture, falling back to settings->Username='%s'",
                 raw_user ? raw_user : "(null)");
    }
    const char *raw_domain = freerdp_settings_get_string(front, FreeRDP_Domain);
    if (!raw_domain) raw_domain = "";

    if (!raw_user || raw_user[0] == '\0') {
        WLog_WARN(TAG, "ServerPostConnect: no username available; skipping");
        free(stashed);
        return st->require_cache ? FALSE : TRUE;
    }

    WLog_INFO(TAG,
              "ServerPostConnect: identity to log in as = user='%s' domain='%s'",
              raw_user, raw_domain);

    /*
     * Some NLA clients (older mstsc, some Java RDP libs, and certain PAM
     * brokers) put the domain-qualified username into the User field with an
     * empty Domain field, e.g.
     *     User='EXAMPLE\alice'  Domain=''
     *     User='alice@example.com'  Domain=''
     * Split those before caching-lookup so we key by the bare account name,
     * which is what the SSH-side pam_nlaproxy captured.
     */
    char user_buf[256];
    const char *user = raw_user;
    const char *bslash = strchr(raw_user, '\\');
    const char *at = strchr(raw_user, '@');
    if (bslash && bslash > raw_user) {
        /* DOMAIN\user - take the tail. */
        const char *tail = bslash + 1;
        strncpy(user_buf, tail, sizeof(user_buf) - 1);
        user_buf[sizeof(user_buf) - 1] = '\0';
        user = user_buf;
        WLog_DBG(TAG, "stripped DOMAIN\\ prefix: '%s' -> '%s'", raw_user, user);
    } else if (at && at > raw_user) {
        /* user@REALM - take the head. */
        size_t n = (size_t)(at - raw_user);
        if (n >= sizeof(user_buf)) n = sizeof(user_buf) - 1;
        memcpy(user_buf, raw_user, n);
        user_buf[n] = '\0';
        user = user_buf;
        WLog_DBG(TAG, "stripped @REALM suffix: '%s' -> '%s'", raw_user, user);
    }

    /* Domain forwarded to xrdp: empty by default (xrdp doesn't care) unless
     * the client sent one explicitly. */
    const char *domain = raw_domain;

    WLog_DBG(TAG, "ServerPostConnect: looking up cached password for user '%s'", user);

    char *password = NULL;
    int rc = lookup_password(st->socket_path, user, &password);
    if (rc == 1) {
        WLog_WARN(TAG,
                  "no cached credentials for user '%s' - "
                  "the user must SSH to this host first within the cache TTL "
                  "(sent by client as user='%s' domain='%s')",
                  user, raw_user, raw_domain);
        if (st->require_cache) {
            free(stashed);
            return FALSE;
        }
        free(stashed);
        return TRUE;
    } else if (rc < 0) {
        WLog_ERR(TAG, "cache lookup failed for user '%s' (errno=%d %s)",
                 user, errno, strerror(errno));
        free(stashed);
        if (st->require_cache)
            return FALSE;
        return TRUE;
    }

    /* We have the plaintext. Inject into the upstream settings. Forward the
     * bare (post-strip) username so xrdp receives the Linux account name in
     * the Client Info PDU. */
    BOOL ok = TRUE;
    if (!freerdp_settings_set_string(back, FreeRDP_Username, user))
        ok = FALSE;
    if (ok && !freerdp_settings_set_string(back, FreeRDP_Domain, domain))
        ok = FALSE;
    if (ok && !freerdp_settings_set_string(back, FreeRDP_Password, password))
        ok = FALSE;
    /*
     * CRITICAL: FreeRDP's outbound Client Info PDU only sets the
     * INFO_AUTOLOGON flag when settings->AutoLogonEnabled is TRUE (see
     * libfreerdp/core/info.c:rdp_write_info_packet). Without that flag
     * xrdp will treat the connection as "user connected but has not yet
     * submitted credentials" and display its login screen despite the
     * Password field being populated. Setting Username/Password alone is
     * NOT sufficient.
     */
    if (ok && !freerdp_settings_set_bool(back, FreeRDP_AutoLogonEnabled, TRUE))
        ok = FALSE;

    /*
     * Re-force FastPathOutput=TRUE on the FRONT settings. We already set
     * this in ServerSessionInitialize, but FreeRDP's capability parsing
     * (which happens after that hook but before this one) may have
     * overwritten it based on what the client's Confirm Active PDU
     * declared. Delinea sometimes forgets to set the fast-path output
     * capability bit even though it can decode fast-path output fine.
     * Without this, xrdp's first fast-path screen update triggers:
     *     [fastpath_send_update_pdu]: client does not support fast path
     *     output
     * and the session dies ~2s after login. See ServerSessionInitialize
     * for the full rationale.
     */
    if (ok && !freerdp_settings_set_bool(front, FreeRDP_FastPathOutput, TRUE))
        ok = FALSE;

    /* Sanity-log what we ended up setting (without printing the actual
     * password) - lets an operator verify the injection worked when xrdp
     * doesn't auto-login.
     *
     * IMPORTANT: `user` may alias into `stashed` (when no DOMAIN\ or @REALM
     * stripping happened), so we MUST snapshot every string we want to log
     * BEFORE we free() either `stashed` or `password`. Otherwise the WLog_INFO
     * call below prints freed memory and journald garbles or hides the line.
     */
    char log_user[256];
    char log_back_user[256];
    char log_back_dom[256];
    strncpy(log_user, user ? user : "(null)", sizeof(log_user) - 1);
    log_user[sizeof(log_user) - 1] = '\0';
    const char *back_user = freerdp_settings_get_string(back, FreeRDP_Username);
    const char *back_pw   = freerdp_settings_get_string(back, FreeRDP_Password);
    const char *back_dom  = freerdp_settings_get_string(back, FreeRDP_Domain);
    strncpy(log_back_user, back_user ? back_user : "(null)", sizeof(log_back_user) - 1);
    log_back_user[sizeof(log_back_user) - 1] = '\0';
    strncpy(log_back_dom, back_dom ? back_dom : "(null)", sizeof(log_back_dom) - 1);
    log_back_dom[sizeof(log_back_dom) - 1] = '\0';
    const size_t pw_len = password ? strlen(password) : 0;
    const size_t back_pw_len = back_pw ? strlen(back_pw) : 0;
    const BOOL back_autologon = freerdp_settings_get_bool(back, FreeRDP_AutoLogonEnabled);
    const BOOL front_fpo     = freerdp_settings_get_bool(front, FreeRDP_FastPathOutput);

    /* Zero the temporary copy of the password. The setting now owns its own
     * copy inside the rdpSettings struct; we don't try to wipe that one. */
    memset(password, 0, strlen(password));
    free(password);
    /* stashed username no longer needed - it was already consumed for the
     * lookup, and we've populated the back settings. */
    free(stashed);
    /* From here on `user`, `raw_user`, and `raw_domain` are dangling if they
     * aliased into stashed; use the log_* snapshots only. */

    if (!ok) {
        WLog_ERR(TAG, "failed to set upstream credentials for user '%s'", log_user);
        return FALSE;
    }
    WLog_INFO(TAG,
              "injected cached credentials for user '%s' into upstream connection "
              "(back settings: Username='%s' Domain='%s' Password.len=%zu AutoLogon=%d; "
              "front settings: FastPathOutput=%d; input pw_len=%zu)",
              log_user, log_back_user, log_back_dom, back_pw_len,
              back_autologon ? 1 : 0, front_fpo ? 1 : 0, pw_len);
    return TRUE;
}

/*
 * ClientLoginFailure: the upstream RDP (xrdp) rejected our credentials. Evict
 * them so the next attempt re-reads from a freshly-populated cache rather than
 * re-trying a stale password.
 */
WINPR_ATTR_NODISCARD
static BOOL nlaproxy_client_login_failure(proxyPlugin *plugin,
                                          proxyData *pdata,
                                          void *param)
{
    (void)param;
    if (!plugin || !plugin->custom || !pdata)
        return TRUE;

    struct plugin_state *st = (struct plugin_state *)plugin->custom;
    /* See ServerPostConnect for the rationale behind the void* laundering. */
    rdpContext *fctx = (rdpContext *)(void *)pdata->ps;
    if (fctx && fctx->settings) {
        const char *user = freerdp_settings_get_string(fctx->settings,
                                                       FreeRDP_Username);
        if (user && user[0]) {
            WLog_WARN(TAG, "upstream login failed for user '%s', evicting cached creds",
                      user);
            evict_password(st->socket_path, user);
        }
    }
    return TRUE;
}

/*
 * ServerSessionEnd: called when the session terminates (successfully or not).
 * We clean up our per-session stash entry to avoid a slow leak.
 *
 * `param` is a `freerdp_peer*`.
 */
WINPR_ATTR_NODISCARD
static BOOL nlaproxy_server_session_end(proxyPlugin *plugin,
                                        proxyData *pdata,
                                        void *param)
{
    (void)plugin; (void)pdata;
    freerdp_peer *peer = (freerdp_peer *)param;
    if (peer) {
        session_forget(peer);
    }
    return TRUE;
}

/* ------------------------------------------------------------------------- */
/* Module entry                                                              */
/* ------------------------------------------------------------------------- */

static char *xstrdup_env_or(const char *env, const char *fallback)
{
    const char *v = getenv(env);
    if (!v || !v[0])
        v = fallback;
    return strdup(v);
}

WINPR_ATTR_NODISCARD
FREERDP_API BOOL proxy_module_entry_point(proxyPluginsManager *plugins_manager,
                                          void *userdata);

BOOL proxy_module_entry_point(proxyPluginsManager *plugins_manager, void *userdata)
{
    if (!plugins_manager)
        return FALSE;

    struct plugin_state *st = calloc(1, sizeof(*st));
    if (!st)
        return FALSE;

    st->socket_path = xstrdup_env_or("NLAPROXY_PLUGIN_SOCKET", DEFAULT_SOCKET);
    if (!st->socket_path) {
        free(st);
        return FALSE;
    }

    /* Capture the socket path in a process-global so the NTLM hash callback
     * (which receives only `freerdp_peer*` as context) can reach the daemon.
     * The daemon socket doesn't change over the process lifetime. */
    g_daemon_socket = strdup(st->socket_path);
    if (!g_daemon_socket) {
        free(st->socket_path);
        free(st);
        return FALSE;
    }

    const char *req = getenv("NLAPROXY_PLUGIN_REQUIRE");
    st->require_cache = (req && (req[0] == '0')) ? 0 : 1;

    proxyPlugin plugin;
    memset(&plugin, 0, sizeof(plugin));
    plugin.name = PLUGIN_NAME;
    plugin.description = PLUGIN_DESC;
    plugin.PluginUnload = nlaproxy_plugin_unload;
    plugin.ServerSessionInitialize = nlaproxy_server_session_initialize;
    plugin.ServerPeerLogon = nlaproxy_server_peer_logon;
    plugin.ServerPostConnect = nlaproxy_server_post_connect;
    plugin.ClientLoginFailure = nlaproxy_client_login_failure;
    plugin.ServerSessionEnd = nlaproxy_server_session_end;
    plugin.userdata = userdata;
    plugin.custom = st;

    WLog_INFO(TAG,
              "nlaproxy plugin loaded (socket=%s require=%d)",
              st->socket_path, st->require_cache);

    if (!plugins_manager->RegisterPlugin(plugins_manager, &plugin)) {
        free(g_daemon_socket); g_daemon_socket = NULL;
        free(st->socket_path);
        free(st);
        return FALSE;
    }
    return TRUE;
}
