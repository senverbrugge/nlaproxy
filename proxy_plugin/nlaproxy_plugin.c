/*
 * proxy-nlaproxy-plugin.so — nlaproxy FreeRDP-proxy3 plugin.
 *
 * Hooks into freerdp-proxy3 (the FreeRDP RDP gateway) to provide the missing
 * piece needed for NLA→non-NLA bridging in front of xrdp:
 *
 *   1. ServerPeerLogon: always returns TRUE. The SAM file maintained by
 *      nlaproxy-cached already gates which users can authenticate via NLA, so
 *      by the time this hook fires the client's NTLM response has already been
 *      validated against a cached NT-OWF. We just need to accept the result.
 *
 *   2. ServerPostConnect: after CredSSP has completed and the proxy has parsed
 *      the target info from config, we look up the plaintext password from
 *      nlaproxy-cached (over a Unix socket) using the username CredSSP reported,
 *      and copy it into the upstream `pClientContext` settings. The proxy then
 *      starts a fresh outbound RDP connection to xrdp using those settings, and
 *      xrdp receives the credentials in the Client Info PDU and PAM-authenticates
 *      the user in the usual way.
 *
 *   3. ClientLoginFailure: best-effort EVICT of the cached credentials so that a
 *      stale or rotated password is not retried.
 *
 * Plugin configuration (passed via proxy.ini [Plugins] section as
 *   ModulesArguments=nlaproxy:socket=/run/nlaproxy/cached.sock,...
 * — but freerdp-proxy3 does not yet pass module arguments through, so we
 * configure via environment variables read at plugin load):
 *
 *   NLAPROXY_PLUGIN_SOCKET    Daemon socket path  (default /run/nlaproxy/cached.sock)
 *   NLAPROXY_PLUGIN_REQUIRE   If "1", abort the proxy session when no cached
 *                             credentials are found. Otherwise we leave the
 *                             upstream Username/Password fields untouched and
 *                             let the operator-configured TargetUser/TargetPassword
 *                             apply. Default: 1.
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
#include <freerdp/settings.h>
#include <freerdp/server/proxy/proxy_context.h>
#include <freerdp/server/proxy/proxy_log.h>
#include <freerdp/server/proxy/proxy_modules_api.h>

#include <winpr/winpr.h>
#include <winpr/wlog.h>

#define TAG MODULE_TAG("nlaproxy")

#define PLUGIN_NAME "nlaproxy"
#define PLUGIN_DESC \
    "Look up cleartext password from nlaproxy-cached by client username (after " \
    "CredSSP/NLA has authenticated against the cached NT-OWFs) and inject it " \
    "into the upstream RDP connection so xrdp can PAM-authenticate the user."

#define DEFAULT_SOCKET "/run/nlaproxy/cached.sock"
#define WRITE_TIMEOUT_MS 1500
#define READ_TIMEOUT_MS 1500

/* Wire protocol - must match cached/src/main.rs */
#define LOOKUP_TAG 0x02
#define EVICT_TAG  0x03
#define STATUS_REPLY_OK        0x00
#define STATUS_REPLY_NOT_FOUND 0x01

#define MAX_USERNAME 256
#define MAX_PASSWORD 1024
#define MAX_FRAME 65536

struct plugin_state {
    char *socket_path;
    char *sam_path;
    int require_cache;
};

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
        free(st->sam_path);
        free(st);
        plugin->custom = NULL;
    }
    return TRUE;
}

/*
 * ServerSessionInitialize: called from `pf_server_handle_peer` immediately
 * after the peer context is initialized and BEFORE NLA runs. This is our
 * chance to push per-connection settings that the pf_server itself doesn't
 * wire up.
 *
 * Purpose: on FreeRDP < 3.25 (Debian/Ubuntu 24.04 ships 3.24.2), the proxy
 * parses `SamFile=` from proxy.ini but never actually forwards it to
 * `FreeRDP_NtlmSamFile` on each peer. That means WinPR's NTLM verifier falls
 * back to `~/.config/winpr/SAM` and always fails to find the user. Setting
 * the property here fixes NLA on those older builds. On 3.25+ the proxy sets
 * this itself but our set is a harmless no-op (identical value).
 *
 * `param` is a `freerdp_peer*`.
 */
WINPR_ATTR_NODISCARD
static BOOL nlaproxy_server_session_initialize(proxyPlugin *plugin,
                                               proxyData *pdata,
                                               void *param)
{
    (void)pdata;
    if (!plugin || !plugin->custom)
        return TRUE;
    struct plugin_state *st = (struct plugin_state *)plugin->custom;
    if (!st->sam_path || !st->sam_path[0])
        return TRUE;

    freerdp_peer *peer = (freerdp_peer *)param;
    if (!peer || !peer->context || !peer->context->settings) {
        WLog_WARN(TAG, "ServerSessionInitialize: no peer/settings, skipping SAM path push");
        return TRUE;
    }

    /* Only set if unset - respects FreeRDP >= 3.25 that already wired the
     * config value in, and lets operators override via proxy.ini SamFile= on
     * newer builds. */
    const char *existing = freerdp_settings_get_string(peer->context->settings,
                                                        FreeRDP_NtlmSamFile);
    if (existing && existing[0]) {
        WLog_DBG(TAG, "NtlmSamFile already set to '%s', leaving it alone", existing);
        return TRUE;
    }
    if (!freerdp_settings_set_string(peer->context->settings,
                                     FreeRDP_NtlmSamFile, st->sam_path)) {
        WLog_ERR(TAG, "failed to set FreeRDP_NtlmSamFile to '%s'", st->sam_path);
        return FALSE;
    }
    WLog_INFO(TAG, "pushed NtlmSamFile='%s' onto peer settings", st->sam_path);
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
    (void)param; /* `param` is freerdp_peer*, but we get the front via pdata. */
    if (!plugin || !plugin->custom || !pdata)
        return FALSE;

    struct plugin_state *st = (struct plugin_state *)plugin->custom;

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
     * Username CredSSP authenticated. FreeRDP_Username is populated by the
     * NLA server from the AUTHENTICATE_MESSAGE. FreeRDP_Domain is what the
     * client's identity carried in the same message; it may be empty.
     */
    const char *raw_user = freerdp_settings_get_string(front, FreeRDP_Username);
    const char *raw_domain = freerdp_settings_get_string(front, FreeRDP_Domain);
    if (!raw_user || raw_user[0] == '\0') {
        WLog_WARN(TAG, "ServerPostConnect: no username on front settings; skipping");
        return st->require_cache ? FALSE : TRUE;
    }
    if (!raw_domain) raw_domain = "";

    WLog_INFO(TAG,
              "ServerPostConnect: CredSSP identity = user='%s' domain='%s'",
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
        if (st->require_cache)
            return FALSE;
        return TRUE;
    } else if (rc < 0) {
        WLog_ERR(TAG, "cache lookup failed for user '%s' (errno=%d %s)",
                 user, errno, strerror(errno));
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

    /* Zero the temporary copy of the password. The setting now owns its own
     * copy inside the rdpSettings struct; we don't try to wipe that one. */
    memset(password, 0, strlen(password));
    free(password);

    if (!ok) {
        WLog_ERR(TAG, "failed to set upstream credentials for user '%s'", user);
        return FALSE;
    }
    WLog_INFO(TAG, "injected cached credentials for user '%s' into upstream connection",
              user);
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

    /*
     * SAM file path. We push this onto each incoming peer's
     * FreeRDP_NtlmSamFile setting in ServerSessionInitialize because
     * `pf_server` on FreeRDP < 3.25 (Ubuntu 24.04 ships 3.24.2) parses
     * SamFile= from proxy.ini but never forwards it to the NLA server.
     *
     * The default `/run/nlaproxy/users.sam` matches what nlaproxy-cached
     * writes. Operators can override via the env var, and can disable this
     * pushdown entirely by setting it to the empty string, letting FreeRDP's
     * own `SamFile=` parsing take effect (on FreeRDP >= 3.25).
     */
    st->sam_path = xstrdup_env_or("NLAPROXY_PLUGIN_SAM", "/run/nlaproxy/users.sam");
    if (!st->sam_path) {
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
    plugin.userdata = userdata;
    plugin.custom = st;

    WLog_INFO(TAG,
              "nlaproxy plugin loaded (socket=%s sam=%s require=%d)",
              st->socket_path,
              st->sam_path[0] ? st->sam_path : "(unset)",
              st->require_cache);

    if (!plugins_manager->RegisterPlugin(plugins_manager, &plugin)) {
        free(st->socket_path);
        free(st->sam_path);
        free(st);
        return FALSE;
    }
    return TRUE;
}
