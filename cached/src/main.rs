//! nlaproxy credential cache daemon.
//!
//! Receives plaintext passwords from a custom PAM module (loaded into sshd's PAM
//! stack), keeps them in memory encrypted with an ephemeral ChaCha20-Poly1305 key
//! for a short TTL, and exposes a Unix-socket lookup API consumed by the FreeRDP
//! proxy plugin.
//!
//! In parallel it maintains the NTLM SAM file used by `freerdp-proxy3`'s NLA
//! verifier so that incoming NLA connections from the Privileged-Access-Management
//! server validate against the same set of credentials that were just seen on SSH.
//!
//! Threat model:
//!  * The daemon trusts only local-socket peers whose UID matches the configured
//!    allow-list (root for STORE; root or `nlaproxy_uid` for LOOKUP/EVICT).
//!  * Plaintext is never written to disk; only the derived NT hash lands in the
//!    SAM file (which is itself on a tmpfs).
//!  * On shutdown all secrets are zeroized.

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit,
    aead::{Aead, OsRng},
};
use md4::{Digest, Md4};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::{Gid, Uid, User, chown};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------
//
// Each request and reply is framed as:
//     u32_be length | payload
//
// Maximum frame length: 64 KiB.
//
// Request payload:
//     u8 tag | tag-specific body
//
//     STORE  (0x01): u16_be ulen | username | u16_be plen | password
//     LOOKUP (0x02): u16_be ulen | username
//     EVICT  (0x03): u16_be ulen | username
//     PING   (0x04): (empty)
//
// Reply payload:
//     u8 status | optional body
//
//     status 0x00 = OK
//     status 0x01 = NOT_FOUND
//     status 0x02 = BAD_REQUEST
//     status 0x03 = DENIED
//     status 0x04 = INTERNAL_ERROR
//
//     LOOKUP OK body: u16_be plen | password (UTF-8)

const MAX_FRAME: usize = 65_536;

const TAG_STORE: u8 = 0x01;
const TAG_LOOKUP: u8 = 0x02;
const TAG_EVICT: u8 = 0x03;
const TAG_PING: u8 = 0x04;

const STATUS_OK: u8 = 0x00;
const STATUS_NOT_FOUND: u8 = 0x01;
const STATUS_BAD_REQUEST: u8 = 0x02;
const STATUS_DENIED: u8 = 0x03;
const STATUS_INTERNAL: u8 = 0x04;

// ---------------------------------------------------------------------------
// Config (env-driven; daemon is configured by systemd unit, not a file)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Config {
    socket_path: PathBuf,
    sam_path: PathBuf,
    /// UID allowed to issue LOOKUP/EVICT in addition to root. Typically the
    /// account `freerdp-proxy3` runs under.
    consumer_uid: Option<Uid>,
    /// GID applied to the Unix socket. The PAM module on Linux runs as the
    /// authenticating process (sshd, which is root) so this matters only for
    /// the consumer.
    socket_gid: Option<Gid>,
    ttl: Duration,
}

impl Config {
    fn from_env() -> Result<Self> {
        let socket_path = std::env::var_os("NLAPROXY_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/run/nlaproxy/cached.sock"));

        let sam_path = std::env::var_os("NLAPROXY_SAM")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/run/nlaproxy/users.sam"));

        let consumer_uid = match std::env::var("NLAPROXY_CONSUMER_USER") {
            Ok(name) if !name.is_empty() => {
                // Explicit configuration: hard-fail if the user doesn't exist
                // so a typo in the unit file doesn't silently produce a daemon
                // that only root can talk to.
                let u = User::from_name(&name)
                    .context("look up NLAPROXY_CONSUMER_USER")?
                    .ok_or_else(|| {
                        anyhow!(
                            "NLAPROXY_CONSUMER_USER='{name}' is set but no such system user exists"
                        )
                    })?;
                Some(u.uid)
            }
            _ => match User::from_name("nlaproxy")
                .context("look up default consumer user 'nlaproxy'")?
            {
                Some(u) => Some(u.uid),
                None => {
                    // The default user is missing - usually because the install
                    // script wasn't run. Warn loudly so the operator notices,
                    // but don't fail: a root-only daemon is still useful for
                    // testing.
                    eprintln!(
                        "warning: no 'nlaproxy' system user exists; \
                         only root will be able to LOOKUP/EVICT. \
                         Set NLAPROXY_CONSUMER_USER= explicitly to silence this warning."
                    );
                    None
                }
            },
        };

        let socket_gid = match std::env::var("NLAPROXY_CONSUMER_GROUP") {
            Ok(name) if !name.is_empty() => {
                let g = nix::unistd::Group::from_name(&name)?
                    .ok_or_else(|| {
                        anyhow!(
                            "NLAPROXY_CONSUMER_GROUP='{name}' is set but no such system group exists"
                        )
                    })?;
                Some(g.gid)
            }
            _ => nix::unistd::Group::from_name("nlaproxy")?.map(|g| g.gid),
        };

        let ttl_secs: u64 = std::env::var("NLAPROXY_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300);

        Ok(Self {
            socket_path,
            sam_path,
            consumer_uid,
            socket_gid,
            ttl: Duration::from_secs(ttl_secs),
        })
    }
}

// ---------------------------------------------------------------------------
// Secret material
// ---------------------------------------------------------------------------

/// Wrapper that zeroes its contents on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Secret(Vec<u8>);

impl Secret {
    #[cfg(test)]
    fn from_str(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// In-memory entry stored under each username. The password is encrypted with a
/// per-process ephemeral key so that a memory disclosure exploit cannot trivially
/// recover all cached passwords from a single page.
struct Entry {
    /// (nonce, ciphertext) - decrypt with the master Cipher.
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    /// Pre-computed NT-OWF (MD4 of UTF-16LE password) - used to populate the SAM
    /// file. This is "password-equivalent" but cannot be reversed to plaintext
    /// without brute force, so it is stored unencrypted to avoid having to decrypt
    /// on every SAM rewrite.
    nt_hash: [u8; 16],
    expires_at: Instant,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
        self.nonce.zeroize();
        self.nt_hash.zeroize();
    }
}

/// Compute the NTOWFv1 (one-way function v1) of a password.
///
///     NTOWFv1(password) = MD4(UTF-16LE(password))
///
/// This is the hash that goes into the NLA SAM file. FreeRDP's NLA verifier
/// reads this NT hash from the SAM entry and derives the per-session NTLMv2
/// hash on the fly via `NTOWFv2FromHash(NtHash, user, domain)` =
/// HMAC-MD5(NtHash, UTF-16LE(Uppercase(user) || domain)). So we never need to
/// know the user/domain at hashing time.
fn nt_owf(password: &str) -> [u8; 16] {
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let mut hasher = Md4::new();
    hasher.update(&utf16);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

struct Cache {
    cipher: ChaCha20Poly1305,
    entries: HashMap<String, Entry>,
    sam_path: PathBuf,
    /// Group to chown the SAM file to after each rewrite. The freerdp-proxy3
    /// consumer must be in this group to open the file (perms are 0640).
    /// `None` means "leave the file's group alone" — useful in tests and
    /// when running as an unprivileged operator.
    sam_gid: Option<Gid>,
    ttl: Duration,
}

impl Cache {
    fn new(sam_path: PathBuf, sam_gid: Option<Gid>, ttl: Duration) -> Self {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);
        Self {
            cipher,
            entries: HashMap::new(),
            sam_path,
            sam_gid,
            ttl,
        }
    }

    fn store(&mut self, username: String, password: Secret) -> Result<()> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, password.as_bytes())
            .map_err(|e| anyhow!("encrypt failed: {e}"))?;
        let password_str = std::str::from_utf8(password.as_bytes())
            .context("password is not UTF-8")?;
        let nt_hash = nt_owf(password_str);

        let entry = Entry {
            ciphertext,
            nonce: nonce.into(),
            nt_hash,
            expires_at: Instant::now() + self.ttl,
        };
        self.entries.insert(username, entry);
        self.write_sam_file()?;
        Ok(())
    }

    fn lookup(&self, username: &str) -> Result<Option<Secret>> {
        let Some(entry) = self.entries.get(username) else {
            return Ok(None);
        };
        if entry.expires_at <= Instant::now() {
            return Ok(None);
        }
        let nonce = chacha20poly1305::Nonce::from_slice(&entry.nonce);
        let plaintext = self
            .cipher
            .decrypt(nonce, entry.ciphertext.as_ref())
            .map_err(|e| anyhow!("decrypt failed: {e}"))?;
        Ok(Some(Secret(plaintext)))
    }

    fn evict(&mut self, username: &str) -> Result<bool> {
        let was_present = self.entries.remove(username).is_some();
        if was_present {
            self.write_sam_file()?;
        }
        Ok(was_present)
    }

    /// Remove all expired entries. Returns the number of entries removed.
    fn purge_expired(&mut self) -> Result<usize> {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries.retain(|_, e| e.expires_at > now);
        let removed = before - self.entries.len();
        if removed > 0 {
            self.write_sam_file()?;
        }
        Ok(removed)
    }

    /// Rewrite the SAM file atomically. The file format expected by
    /// `freerdp-proxy3` (via WinPR's `SamLookupUserA`) is:
    ///
    ///     user:domain::NT_HASH_HEX:::
    ///
    /// where NT_HASH_HEX is the hex-encoded NTOWFv1 (`MD4(UTF-16LE(password))`).
    /// FreeRDP's `ntlm_fetch_ntlm_v2_hash` reads this raw NT-hash from the SAM
    /// entry and then derives the NTLMv2 hash on the fly using the user/domain
    /// from the incoming AUTHENTICATE_MESSAGE. We always write entries with an
    /// empty domain because mstsc-class clients normally send no AD domain when
    /// none is configured (and FreeRDP's `SamLookupUserW` falls back to a
    /// nullptr-domain lookup if the domain-aware match misses).
    fn write_sam_file(&self) -> Result<()> {
        let tmp = self.sam_path.with_extension("sam.tmp");
        let mut contents = String::with_capacity(self.entries.len() * 80);
        for (user, entry) in &self.entries {
            // Filter usernames that contain characters that would break the SAM
            // line format (`:` is the field separator). These should never make
            // it here from PAM but we are defensive.
            if user.bytes().any(|b| b == b':' || b == b'\n' || b == b'\r') {
                warn!(user, "skipping SAM entry with invalid characters");
                continue;
            }
            contents.push_str(user);
            // Empty domain.
            contents.push_str("::");
            // Empty LM hash.
            contents.push(':');
            contents.push_str(&hex::encode(entry.nt_hash));
            contents.push_str(":::\n");
        }

        // Write atomically with restrictive permissions.
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o640)
                .open(&tmp)
                .with_context(|| format!("open {}", tmp.display()))?;
            f.write_all(contents.as_bytes())?;
            f.sync_all()?;
        }
        // Chown the tmp file BEFORE the rename so the on-disk file is never
        // observed by the consumer with the wrong group. Failures here are
        // logged prominently because a wrong group means freerdp-proxy3
        // cannot open the file and NLA login silently fails.
        if let Some(g) = self.sam_gid {
            if let Err(e) = chown(&tmp, None, Some(g)) {
                warn!(
                    error = %e,
                    path = %tmp.display(),
                    gid = g.as_raw(),
                    "chown of SAM tmp file failed; freerdp-proxy3 may be unable to read it"
                );
            }
        }
        std::fs::rename(&tmp, &self.sam_path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), self.sam_path.display()))?;
        debug!(
            entries = self.entries.len(),
            path = %self.sam_path.display(),
            "wrote SAM file"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

struct Server {
    cache: Arc<Mutex<Cache>>,
    consumer_uid: Option<Uid>,
}

impl Server {
    async fn handle(&self, mut stream: UnixStream) -> Result<()> {
        let creds = peer_creds(&stream)?;
        debug!(uid = creds.uid(), pid = creds.pid(), "client connected");

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_FRAME {
            self.reply_status(&mut stream, STATUS_BAD_REQUEST).await?;
            return Ok(());
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        let tag = buf[0];
        let body = &buf[1..];

        let allowed = self.is_allowed(tag, &creds);
        if !allowed {
            warn!(
                uid = creds.uid(),
                tag, "denying request from non-privileged peer"
            );
            self.reply_status(&mut stream, STATUS_DENIED).await?;
            return Ok(());
        }

        match tag {
            TAG_PING => {
                self.reply_status(&mut stream, STATUS_OK).await?;
            }
            TAG_STORE => match parse_store(body) {
                Ok((user, password)) => match self.cache.lock().await.store(user.clone(), password)
                {
                    Ok(()) => {
                        info!(user, "credentials cached");
                        self.reply_status(&mut stream, STATUS_OK).await?;
                    }
                    Err(e) => {
                        error!(error = ?e, "store failed");
                        self.reply_status(&mut stream, STATUS_INTERNAL).await?;
                    }
                },
                Err(e) => {
                    warn!(error = ?e, "malformed STORE");
                    self.reply_status(&mut stream, STATUS_BAD_REQUEST).await?;
                }
            },
            TAG_LOOKUP => match parse_username(body) {
                Ok(user) => match self.cache.lock().await.lookup(&user) {
                    Ok(Some(password)) => {
                        debug!(user, "credentials returned to consumer");
                        let mut reply = Vec::with_capacity(3 + password.as_bytes().len());
                        reply.push(STATUS_OK);
                        let plen = u16::try_from(password.as_bytes().len())?;
                        reply.extend_from_slice(&plen.to_be_bytes());
                        reply.extend_from_slice(password.as_bytes());
                        self.reply_raw(&mut stream, &reply).await?;
                    }
                    Ok(None) => {
                        debug!(user, "no cached credentials");
                        self.reply_status(&mut stream, STATUS_NOT_FOUND).await?;
                    }
                    Err(e) => {
                        error!(error = ?e, "lookup failed");
                        self.reply_status(&mut stream, STATUS_INTERNAL).await?;
                    }
                },
                Err(e) => {
                    warn!(error = ?e, "malformed LOOKUP");
                    self.reply_status(&mut stream, STATUS_BAD_REQUEST).await?;
                }
            },
            TAG_EVICT => match parse_username(body) {
                Ok(user) => match self.cache.lock().await.evict(&user) {
                    Ok(_) => {
                        info!(user, "evicted");
                        self.reply_status(&mut stream, STATUS_OK).await?;
                    }
                    Err(e) => {
                        error!(error = ?e, "evict failed");
                        self.reply_status(&mut stream, STATUS_INTERNAL).await?;
                    }
                },
                Err(e) => {
                    warn!(error = ?e, "malformed EVICT");
                    self.reply_status(&mut stream, STATUS_BAD_REQUEST).await?;
                }
            },
            _ => {
                warn!(tag, "unknown tag");
                self.reply_status(&mut stream, STATUS_BAD_REQUEST).await?;
            }
        }

        Ok(())
    }

    fn is_allowed(&self, tag: u8, creds: &nix::sys::socket::UnixCredentials) -> bool {
        let uid = Uid::from_raw(creds.uid());
        if uid.is_root() {
            return true;
        }
        match tag {
            // Only the consumer (freerdp-proxy3) may lookup or evict.
            TAG_LOOKUP | TAG_EVICT | TAG_PING => self.consumer_uid == Some(uid),
            // STORE is reserved for root (the PAM module runs as sshd, i.e. root).
            TAG_STORE => false,
            _ => false,
        }
    }

    async fn reply_status(&self, stream: &mut UnixStream, status: u8) -> Result<()> {
        self.reply_raw(stream, &[status]).await
    }

    async fn reply_raw(&self, stream: &mut UnixStream, body: &[u8]) -> Result<()> {
        let len = u32::try_from(body.len())?.to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(body).await?;
        stream.flush().await?;
        Ok(())
    }
}

fn parse_store(body: &[u8]) -> Result<(String, Secret)> {
    if body.len() < 2 {
        bail!("short");
    }
    let ulen = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + ulen + 2 {
        bail!("short username");
    }
    let user = std::str::from_utf8(&body[2..2 + ulen])
        .context("username not UTF-8")?
        .to_owned();
    let off = 2 + ulen;
    let plen = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    if body.len() != off + 2 + plen {
        bail!("length mismatch");
    }
    let password = Secret(body[off + 2..].to_vec());
    if user.is_empty() {
        bail!("empty username");
    }
    Ok((user, password))
}

fn parse_username(body: &[u8]) -> Result<String> {
    if body.len() < 2 {
        bail!("short");
    }
    let ulen = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() != 2 + ulen {
        bail!("length mismatch");
    }
    let user = std::str::from_utf8(&body[2..])
        .context("username not UTF-8")?
        .to_owned();
    if user.is_empty() {
        bail!("empty");
    }
    Ok(user)
}

fn peer_creds(stream: &UnixStream) -> Result<nix::sys::socket::UnixCredentials> {
    let raw = stream.as_raw_fd();
    // SAFETY: the fd is borrowed for the duration of this call; nix's
    // BorrowedFd wrapper would be safer but we want to avoid the wrapper
    // overhead here.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw) };
    let creds = getsockopt(&borrowed, PeerCredentials)?;
    Ok(creds)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn install_logging() {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,nlaproxy_cached=info"));

    // Prefer journald if /run/systemd/journal/socket is present.
    let registry = tracing_subscriber::registry().with(filter);
    if std::path::Path::new("/run/systemd/journal/socket").exists() {
        if let Ok(layer) = tracing_journald::layer() {
            registry.with(layer).init();
            return;
        }
    }
    registry.with(tracing_subscriber::fmt::layer().with_ansi(false)).init();
}

fn ensure_socket_dir(socket_path: &std::path::Path, gid: Option<Gid>) -> Result<()> {
    if let Some(dir) = socket_path.parent() {
        let created = if !dir.exists() {
            std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
            true
        } else {
            false
        };
        // Only tighten permissions on a directory we just created. If the dir
        // pre-existed (e.g. /run shipped by the distro, or created by systemd's
        // RuntimeDirectory=) we leave the mode alone to avoid the "Operation
        // not permitted" we get on directories we do not own, and to respect
        // whatever mode systemd applied.
        if created {
            let mut perms = std::fs::metadata(dir)?.permissions();
            perms.set_mode(0o750);
            std::fs::set_permissions(dir, perms)?;
            if let Some(g) = gid {
                if let Err(e) = chown(dir, None, Some(g)) {
                    warn!(
                        error = %e,
                        path = %dir.display(),
                        gid = g.as_raw(),
                        "chown of runtime directory failed"
                    );
                }
            }
        }
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    install_logging();
    let cfg = Config::from_env()?;
    info!(
        socket = %cfg.socket_path.display(),
        sam = %cfg.sam_path.display(),
        consumer_uid = ?cfg.consumer_uid,
        ttl_secs = cfg.ttl.as_secs(),
        "starting nlaproxy-cached"
    );

    ensure_socket_dir(&cfg.socket_path, cfg.socket_gid)?;

    // Remove a stale socket from a previous run.
    if cfg.socket_path.exists() {
        std::fs::remove_file(&cfg.socket_path).ok();
    }
    let listener = UnixListener::bind(&cfg.socket_path)
        .with_context(|| format!("bind {}", cfg.socket_path.display()))?;

    // Tighten socket permissions: rw for owner, rw for the consumer group,
    // nothing for world. The actual access control is via SO_PEERCRED but
    // defence in depth doesn't hurt.
    {
        let mut perms = std::fs::metadata(&cfg.socket_path)?.permissions();
        perms.set_mode(0o660);
        std::fs::set_permissions(&cfg.socket_path, perms)?;
        if let Some(g) = cfg.socket_gid {
            if let Err(e) = chown(&cfg.socket_path, None, Some(g)) {
                warn!(
                    error = %e,
                    path = %cfg.socket_path.display(),
                    gid = g.as_raw(),
                    "chown of listening socket failed; the consumer may be unable to connect"
                );
            }
        }
    }

    let cache = Arc::new(Mutex::new(Cache::new(
        cfg.sam_path.clone(),
        cfg.socket_gid,
        cfg.ttl,
    )));
    // Write an empty SAM up front so freerdp-proxy3 has something to open.
    cache.lock().await.write_sam_file()?;

    let server = Arc::new(Server {
        cache: cache.clone(),
        consumer_uid: cfg.consumer_uid,
    });

    // Background task: purge expired entries every 30s.
    {
        let cache = cache.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(30));
            tick.tick().await; // skip the immediate first tick
            loop {
                tick.tick().await;
                let mut guard = cache.lock().await;
                match guard.purge_expired() {
                    Ok(0) => {}
                    Ok(n) => info!(removed = n, "purged expired credentials"),
                    Err(e) => error!(error = ?e, "purge failed"),
                }
            }
        });
    }

    // Graceful shutdown.
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let server = server.clone();
                        tokio::spawn(async move {
                            if let Err(e) = server.handle(stream).await {
                                debug!(error = ?e, "handler ended");
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = ?e, "accept failed");
                    }
                }
            }
            _ = sigterm.recv() => { info!("SIGTERM, shutting down"); break; }
            _ = sigint.recv() => { info!("SIGINT, shutting down"); break; }
        }
    }

    // Wipe the SAM file on the way out.
    {
        let mut guard = cache.lock().await;
        guard.entries.clear();
        guard.write_sam_file().ok();
    }
    std::fs::remove_file(&cfg.socket_path).ok();
    info!("nlaproxy-cached stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_owf_known_vector_password() {
        // NT-OWF("Password") = MD4(UTF-16LE("Password"))
        // verified against winpr-hash3 -u x -p Password -f sam -v 1
        let h = nt_owf("Password");
        assert_eq!(hex::encode(h), "a4f49c406510bdcab6824ee7c30fd852");
    }

    #[test]
    fn nt_owf_known_vector_secret() {
        // NT-OWF("secret") = MD4(UTF-16LE("secret"))
        // verified against winpr-hash3 -u alice -p secret -f sam -v 1
        let h = nt_owf("secret");
        assert_eq!(hex::encode(h), "878d8014606cda29677a44efa1353fc7");
    }

    #[test]
    fn parse_store_roundtrip() {
        let mut body = Vec::new();
        let u = b"alice";
        let p = b"hunter2";
        body.extend_from_slice(&u16::try_from(u.len()).unwrap().to_be_bytes());
        body.extend_from_slice(u);
        body.extend_from_slice(&u16::try_from(p.len()).unwrap().to_be_bytes());
        body.extend_from_slice(p);
        let (user, secret) = parse_store(&body).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(secret.as_bytes(), p);
    }

    #[test]
    fn cache_store_lookup_evict() {
        let tmp = tempfile_path("nlaproxy_test.sam");
        let mut cache = Cache::new(tmp.clone(), None, Duration::from_secs(60));
        cache
            .store("alice".to_owned(), Secret::from_str("hunter2"))
            .unwrap();
        let got = cache.lookup("alice").unwrap().expect("present");
        assert_eq!(got.as_bytes(), b"hunter2");
        let evicted = cache.evict("alice").unwrap();
        assert!(evicted);
        assert!(cache.lookup("alice").unwrap().is_none());
        std::fs::remove_file(tmp).ok();
    }

    #[test]
    fn cache_ttl_expires() {
        let tmp = tempfile_path("nlaproxy_test_ttl.sam");
        let mut cache = Cache::new(tmp.clone(), None, Duration::from_millis(50));
        cache
            .store("alice".to_owned(), Secret::from_str("hunter2"))
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(cache.lookup("alice").unwrap().is_none());
        std::fs::remove_file(tmp).ok();
    }

    fn tempfile_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "{}_{}",
            std::process::id(),
            name
        ));
        p
    }
}
