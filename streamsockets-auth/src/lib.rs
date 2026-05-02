//! Authentication: accounts.yml loader, atomic snapshot, lease tracker, hot reload.
//!
//! Mirrors `authentication-server/src/main/java/.../TokenAuthentication.java`.

#![warn(missing_docs)]
// Same pedantic-suppression rationale as `streamsockets-core/src/lib.rs`.
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::redundant_closure_for_method_calls,
    clippy::manual_let_else,
    clippy::items_after_statements,
    clippy::if_not_else,
    clippy::needless_continue,
    clippy::match_wild_err_arm,
    clippy::map_unwrap_or,
    clippy::should_implement_trait,
    clippy::duplicated_attributes,
    clippy::unnecessary_wraps,
    clippy::unreadable_literal,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::unnested_or_patterns,
    clippy::single_match_else,
    clippy::semicolon_if_nothing_returned,
    clippy::needless_pass_by_value,
    clippy::match_same_arms,
    clippy::ignored_unit_patterns,
    clippy::single_match,
    clippy::bool_to_int_with_if,
    clippy::needless_bool,
    clippy::ptr_as_ptr,
    clippy::ref_as_ptr,
    clippy::borrow_as_ptr,
    clippy::redundant_else,
    clippy::unnecessary_literal_bound,
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::large_stack_arrays,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn
)]

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use ipnet::IpNet;
use serde::Deserialize;
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Default per-account active-lease ceiling. Defends against a misbehaving
/// client opening unbounded `reuse=true` tunnels and exhausting server
/// resources before the global connection cap kicks in.
pub const DEFAULT_MAX_LEASES_PER_ACCOUNT: usize = 1024;

/// Maximum permitted size of `accounts.yml`. Caps memory amplification from
/// a YAML alias-bomb (`serde_yml` does not bound expansion). 4 MiB is far
/// larger than any realistic operator config (1k accounts × ~200 bytes).
pub const MAX_ACCOUNTS_FILE_BYTES: u64 = 4 * 1024 * 1024;

fn redact_yaml_location(e: &serde_yml::Error) -> String {
    e.location()
        .map(|loc| format!("line {} column {}", loc.line(), loc.column()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Errors raised while parsing or validating `accounts.yml`.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Filesystem error reading the YAML file (missing file, EACCES, etc.).
    #[error("io error reading {path}: {source}")]
    Io {
        /// Path that failed to read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// YAML parser rejected the contents. The location (line/column) is
    /// surfaced; the offending mapping value is *not* included, because
    /// `serde_yml::Error::Display` can otherwise echo a `token: ...` byte
    /// snippet into logs.
    #[error("yaml parse error in {path} at {location}")]
    Parse {
        /// Path whose contents failed to parse.
        path: PathBuf,
        /// Sanitized parser-error location (e.g. "line 3 column 7" or "unknown").
        location: String,
    },
    /// File exceeded the maximum permitted size.
    #[error("accounts file {path} too large: {size} bytes > limit {limit} bytes")]
    TooLarge {
        /// Path that exceeded the limit.
        path: PathBuf,
        /// Observed file size.
        size: u64,
        /// Configured maximum.
        limit: u64,
    },
    /// Two accounts share the same `token` — file is rejected. The error
    /// reports the offending account *name*, never the token itself.
    #[error("each account must have a unique token; duplicate on account `{0}`")]
    DuplicateToken(String),
    /// One of the `allowedIps` entries failed to parse as an IP or CIDR.
    #[error("invalid CIDR `{value}` in account `{account}`: {source}")]
    InvalidCidr {
        /// Account whose `allowedIps` entry failed.
        account: String,
        /// Offending raw value.
        value: String,
        /// Underlying parser error.
        #[source]
        source: ipnet::AddrParseError,
    },
}

/// Top-level YAML structure: matches Java `Accounts.java`.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountsFile {
    /// Account rows in declaration order.
    pub accounts: Vec<Account>,
}

/// One account row. Field names match Java field-camelCase exactly.
///
/// `Hash`/`Eq` derive on the *token* alone — two `Account`s referring to the
/// same identity (across reloads) are considered equal.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// Operator-facing label used in metrics and logs.
    pub name: String,
    /// Bearer token presented by clients in `X-Auth-Token`.
    pub token: String,
    /// If `false`, only one tunnel may hold this account at a time (409).
    #[serde(default)]
    pub reuse: bool,
    /// Allowed `host:port` upstream targets.
    pub routes: Vec<String>,
    /// Allowed source CIDRs / bare IPs (`"127.0.0.1"` ≡ `"127.0.0.1/32"`).
    pub allowed_ips: Vec<String>,
}

impl PartialEq for Account {
    fn eq(&self, other: &Self) -> bool {
        self.token == other.token
    }
}
impl Eq for Account {}
impl std::hash::Hash for Account {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.token.hash(state);
    }
}

/// Compute the BLAKE3 hash of a token. Used as the lookup-table key so the
/// HashMap probe never sees the original token bytes.
#[inline]
#[must_use]
pub fn token_hash(token: &[u8]) -> [u8; 32] {
    *blake3::hash(token).as_bytes()
}

/// Pre-computed lookup cache for one account (mirrors Java `AccountCache`).
#[derive(Debug)]
pub struct AccountCache {
    /// Backing account row. Shared so `LeaseTracker` keys remain valid.
    pub account: Arc<Account>,
    /// BLAKE3(account.token). Stable across reloads for the same token —
    /// re-used as the `LeaseTracker` key so reloads preserve outstanding leases.
    pub token_hash: [u8; 32],
    /// Pre-computed set of allowed routes for O(1) membership test.
    pub route_set: HashSet<String>,
    /// Parsed CIDRs from [`Account::allowed_ips`].
    pub allowed_cidrs: Vec<IpNet>,
}

/// Atomic snapshot of all accounts and lookup tables.
#[derive(Debug)]
pub struct AccountsSnapshot {
    /// `BLAKE3(token)` → account cache. The HashMap probe sees only the
    /// preimage-resistant hash, so an attacker timing the bucket walk learns
    /// nothing about the original token.
    pub by_token_hash: HashMap<[u8; 32], Arc<AccountCache>>,
    /// Union of every account's `routes` — useful for telemetry / startup checks.
    pub all_routes: HashSet<String>,
}

impl AccountsSnapshot {
    /// Build a snapshot from a parsed YAML file. Validates uniqueness of tokens
    /// and parses every `allowedIps` entry. Empty `allowedIps` is allowed
    /// (deny-all, matching Java behavior).
    pub fn build(file: AccountsFile) -> Result<Self, AuthError> {
        let mut by_token_hash: HashMap<[u8; 32], Arc<AccountCache>> = HashMap::new();
        let mut all_routes: HashSet<String> = HashSet::new();

        for mut account in file.accounts {
            let hash = token_hash(account.token.as_bytes());
            if by_token_hash.contains_key(&hash) {
                return Err(AuthError::DuplicateToken(account.name));
            }
            if account.allowed_ips.is_empty() {
                warn!(
                    account = %account.name,
                    "account has empty allowedIps; every connection will be rejected with 403"
                );
            }
            if account.routes.is_empty() {
                warn!(
                    account = %account.name,
                    "account has empty routes; every connection will be rejected with 403"
                );
            }
            let mut cidrs = Vec::with_capacity(account.allowed_ips.len());
            for raw in &account.allowed_ips {
                let parsed = parse_cidr_lenient(raw).map_err(|source| AuthError::InvalidCidr {
                    account: account.name.clone(),
                    value: raw.clone(),
                    source,
                })?;
                // Canonicalize: warn if the operator wrote `192.168.1.5/24`
                // expecting "this host" — the prefix match ignores host bits,
                // so it actually matches the entire `/24`. Trunc to the
                // network address so logs/metrics show the canonical form.
                let trunc = parsed.trunc();
                if trunc != parsed {
                    warn!(
                        account = %account.name,
                        value = %raw,
                        canonical = %trunc,
                        "CIDR has host bits set; treating as network prefix \
                         (the matcher ignores host bits)"
                    );
                }
                cidrs.push(trunc);
            }
            // Drain routes once (no clone-then-clone): build the per-account
            // set and copy each entry into the global set without re-cloning.
            let mut route_set: HashSet<String> = HashSet::with_capacity(account.routes.len());
            for r in account.routes.drain(..) {
                all_routes.insert(r.clone());
                route_set.insert(r);
            }
            let arc_account = Arc::new(account);
            let cache = Arc::new(AccountCache {
                account: arc_account,
                token_hash: hash,
                route_set,
                allowed_cidrs: cidrs,
            });
            by_token_hash.insert(hash, cache);
        }

        info!(
            "Built authentication cache for {} accounts",
            by_token_hash.len()
        );
        Ok(AccountsSnapshot {
            by_token_hash,
            all_routes,
        })
    }

    /// Authenticate `(token, route, client_ip)`. Returns the matched account or `None`.
    ///
    /// **Timing-safety:** the HashMap is keyed on `BLAKE3(token)`, so the
    /// bucket-probe leaks at most "this 32-byte preimage-resistant hash
    /// exists". Token comparison is then performed in constant time over both
    /// the length and the bytes — no early exit on length mismatch.
    pub fn authenticate(
        &self,
        token: &str,
        route: &str,
        client_ip: IpAddr,
    ) -> Option<Arc<AccountCache>> {
        let hash = token_hash(token.as_bytes());
        let cache = self.by_token_hash.get(&hash)?;

        // Defense-in-depth constant-time equality. Compare length and bytes
        // separately, both via subtle, then AND the Choice values so neither
        // side short-circuits.
        let stored = cache.account.token.as_bytes();
        let candidate = token.as_bytes();
        let len_eq: Choice = (stored.len() as u64).ct_eq(&(candidate.len() as u64));
        // ct_eq on slices of differing length returns a constant Choice(0)
        // without comparing bytes — the length check above is what guards
        // correctness, not performance.
        let bytes_eq: Choice = stored.ct_eq(candidate);
        if !bool::from(len_eq & bytes_eq) {
            return None;
        }

        if !cache.route_set.contains(route) {
            debug!(route, %client_ip, "route not allowed for token");
            return None;
        }
        // Normalize IPv4-mapped IPv6 (::ffff:1.2.3.4) to its v4 form before
        // CIDR membership. Without this, dual-stack listeners reject legitimate
        // IPv4 clients allow-listed under a v4 CIDR.
        let normalized_ip = match client_ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            IpAddr::V4(_) => client_ip,
        };
        for net in &cache.allowed_cidrs {
            if net.contains(&normalized_ip) {
                return Some(cache.clone());
            }
        }
        debug!(%client_ip, "client IP not in any allowed CIDR");
        None
    }

    /// O(1) membership: does any account allow `route`?
    #[must_use]
    pub fn contains_route(&self, route: &str) -> bool {
        self.all_routes.contains(route)
    }
}

fn parse_cidr_lenient(s: &str) -> Result<IpNet, ipnet::AddrParseError> {
    if s.contains('/') {
        IpNet::from_str(s)
    } else {
        match s.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => Ok(IpNet::V4(
                ipnet::Ipv4Net::new(v4, 32).expect("32 is a valid IPv4 prefix"),
            )),
            Ok(IpAddr::V6(v6)) => Ok(IpNet::V6(
                ipnet::Ipv6Net::new(v6, 128).expect("128 is a valid IPv6 prefix"),
            )),
            Err(_) => IpNet::from_str(s),
        }
    }
}

/// Lease tracker: counts active sessions per account and enforces `reuse=false`.
///
/// Per MIGRATION.md §8.4: tracker is keyed on the BLAKE3(token) so that across
/// reloads — which re-issue `Arc<Account>` instances with the same token — the
/// outstanding leases continue to map to the same slot.
#[derive(Debug)]
pub struct LeaseTracker {
    active: DashMap<[u8; 32], AtomicUsize>,
    max_per_account: usize,
}

impl Default for LeaseTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors raised by [`LeaseTracker::try_lease_arc`].
#[derive(Debug, Error)]
pub enum LeaseError {
    /// `reuse=false` and another tunnel already holds this account.
    #[error("account already in use")]
    Conflict,
    /// `reuse=true` and the per-account active-lease ceiling is reached.
    #[error("per-account lease ceiling exhausted")]
    Exhausted,
}

impl LeaseTracker {
    /// Construct an empty tracker with the default ceiling.
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: DashMap::new(),
            max_per_account: DEFAULT_MAX_LEASES_PER_ACCOUNT,
        }
    }

    /// Construct an empty tracker with a custom per-account ceiling.
    #[must_use]
    pub fn with_max_per_account(max_per_account: usize) -> Self {
        Self {
            active: DashMap::new(),
            max_per_account,
        }
    }

    /// Try to acquire a lease. Returns an `Arc`-backed guard with `'static`
    /// lifetime — the tracker pointer is shared so the guard outlives the
    /// original `Arc<TokenAuthentication>` reference safely.
    ///
    /// For `account.reuse == false`, uses `compare_exchange(0, 1)` to
    /// atomically guarantee at most one outstanding lease.
    /// For `account.reuse == true`, returns [`LeaseError::Exhausted`] when
    /// the per-account ceiling would be exceeded.
    pub fn try_lease_arc(
        self: &Arc<Self>,
        account: &Arc<Account>,
    ) -> Result<LeaseGuard, LeaseError> {
        let hash = token_hash(account.token.as_bytes());
        let entry = self
            .active
            .entry(hash)
            .or_insert_with(|| AtomicUsize::new(0));
        if !account.reuse {
            entry
                .value()
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .map_err(|_| LeaseError::Conflict)?;
        } else {
            // Bounded fetch_add: load → check ceiling → CAS, retry on race.
            let counter = entry.value();
            let max = self.max_per_account;
            loop {
                let current = counter.load(Ordering::SeqCst);
                if current >= max {
                    return Err(LeaseError::Exhausted);
                }
                if counter
                    .compare_exchange_weak(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    break;
                }
            }
        }
        Ok(LeaseGuard {
            tracker: Arc::clone(self),
            account: account.clone(),
            token_hash: hash,
            released: false,
        })
    }

    fn release(&self, hash: &[u8; 32]) {
        // Decrement; if the resulting count is zero, garbage-collect the
        // entry so reloads issuing fresh `Arc<Account>` values don't leak.
        if let Some(entry) = self.active.get(hash) {
            let _ = entry
                .value()
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                    if v == 0 {
                        None
                    } else {
                        Some(v - 1)
                    }
                });
        }
        // remove_if races the increment path: we only remove when count==0.
        // If a concurrent lease bumped the count back up between the
        // fetch_update above and the remove_if check, the closure returns
        // false and the entry stays.
        self.active
            .remove_if(hash, |_, v| v.load(Ordering::SeqCst) == 0);
    }

    /// Test helper: count of active leases for `account`.
    #[must_use]
    pub fn active_count(&self, account: &Arc<Account>) -> usize {
        let hash = token_hash(account.token.as_bytes());
        self.active
            .get(&hash)
            .map(|e| e.value().load(Ordering::SeqCst))
            .unwrap_or(0)
    }
}

/// RAII guard that releases the lease on drop.
///
/// Holds an `Arc<LeaseTracker>` and `Arc<Account>` so it is `'static`-safe to
/// send across `tokio::spawn` boundaries. Drop releases on every exit path
/// (panic, cancellation, error, normal close).
pub struct LeaseGuard {
    tracker: Arc<LeaseTracker>,
    account: Arc<Account>,
    token_hash: [u8; 32],
    released: bool,
}

impl LeaseGuard {
    /// Operator-facing account name — useful for tracing fields.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.account.name
    }

    /// Underlying account, e.g. for metric labels.
    #[must_use]
    pub fn account(&self) -> &Arc<Account> {
        &self.account
    }

    /// Explicit release; idempotent with [`Drop`].
    pub fn release(mut self) {
        if !self.released {
            self.released = true;
            self.tracker.release(&self.token_hash);
        }
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        if !self.released {
            self.tracker.release(&self.token_hash);
        }
    }
}

/// Top-level handle: an `Arc<ArcSwap<AccountsSnapshot>>` wrapper that exposes both
/// authentication queries and the file-reload trigger.
pub struct TokenAuthentication {
    snapshot: Arc<ArcSwap<AccountsSnapshot>>,
    leases: Arc<LeaseTracker>,
    config_path: Option<PathBuf>,
    reload_lock: tokio::sync::Mutex<()>,
}

impl TokenAuthentication {
    /// Construct from a YAML file path. Reads + parses immediately; subsequent reload
    /// failures preserve the original snapshot.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, AuthError> {
        let path = path.as_ref().to_path_buf();
        let file = load_yaml_blocking(&path)?;
        let snapshot = Arc::new(ArcSwap::from_pointee(AccountsSnapshot::build(file)?));
        Ok(Self {
            snapshot,
            leases: Arc::new(LeaseTracker::new()),
            config_path: Some(path),
            reload_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// In-process construction (tests).
    pub fn from_accounts(accounts: AccountsFile) -> Result<Self, AuthError> {
        let snapshot = Arc::new(ArcSwap::from_pointee(AccountsSnapshot::build(accounts)?));
        Ok(Self {
            snapshot,
            leases: Arc::new(LeaseTracker::new()),
            config_path: None,
            reload_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Borrowed view of the current snapshot. Cheap (one atomic load).
    #[must_use]
    pub fn snapshot(&self) -> arc_swap::Guard<Arc<AccountsSnapshot>> {
        self.snapshot.load()
    }

    /// Owned `Arc` view — appropriate for storing across an await point.
    #[must_use]
    pub fn snapshot_arc(&self) -> Arc<AccountsSnapshot> {
        self.snapshot.load_full()
    }

    /// Shared lease tracker. Clone the `Arc` to share with handshake handlers.
    #[must_use]
    pub fn leases(&self) -> &Arc<LeaseTracker> {
        &self.leases
    }

    /// Reload from the file path provided at construction. On any error, the
    /// existing snapshot is preserved and a `warn`-level log line is emitted —
    /// `error!` is reserved for unrecoverable conditions.
    pub async fn reload(&self) {
        let Some(path) = self.config_path.as_ref() else {
            warn!("no config file path; cannot reload");
            return;
        };
        let _g = self.reload_lock.lock().await;
        match load_yaml_async(path)
            .await
            .and_then(AccountsSnapshot::build)
        {
            Ok(new_snap) => {
                self.snapshot.store(Arc::new(new_snap));
                info!(path = %path.display(), "reloaded accounts");
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "reload failed; keeping previous snapshot");
            }
        }
    }

    /// Spawn an inotify watcher + timer fallback that calls [`reload`] on changes.
    pub fn spawn_reload_watcher(self: &Arc<Self>, interval: Duration) {
        self.spawn_reload_watcher_with_cancel(interval, None);
    }

    /// Same as [`spawn_reload_watcher`] but observes a cancellation token.
    pub fn spawn_reload_watcher_with_cancel(
        self: &Arc<Self>,
        interval: Duration,
        cancel: Option<tokio_util::sync::CancellationToken>,
    ) {
        if interval.is_zero() {
            return;
        }
        if self.config_path.is_none() {
            return;
        }
        let me = Arc::clone(self);
        let me_timer = Arc::clone(&me);
        let cancel_timer = cancel.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(interval);
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            iv.tick().await; // skip immediate fire
            loop {
                if let Some(c) = &cancel_timer {
                    tokio::select! {
                        biased;
                        _ = c.cancelled() => return,
                        _ = iv.tick() => {}
                    }
                } else {
                    iv.tick().await;
                }
                me_timer.reload().await;
            }
        });
        if let Some(path) = me.config_path.clone() {
            let me_inotify = Arc::clone(&me);
            tokio::spawn(async move {
                let fut = run_inotify(path, me_inotify);
                let outcome = if let Some(c) = cancel {
                    tokio::select! {
                        biased;
                        _ = c.cancelled() => return,
                        r = fut => r,
                    }
                } else {
                    fut.await
                };
                if let Err(e) = outcome {
                    warn!(error = %e, "inotify watcher exited; relying on timer fallback");
                }
            });
        }
    }
}

fn load_yaml_blocking(path: &Path) -> Result<AccountsFile, AuthError> {
    let meta = std::fs::metadata(path).map_err(|source| AuthError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if meta.len() > MAX_ACCOUNTS_FILE_BYTES {
        return Err(AuthError::TooLarge {
            path: path.to_path_buf(),
            size: meta.len(),
            limit: MAX_ACCOUNTS_FILE_BYTES,
        });
    }
    let bytes = std::fs::read(path).map_err(|source| AuthError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_yml::from_slice(&bytes).map_err(|e| AuthError::Parse {
        path: path.to_path_buf(),
        location: redact_yaml_location(&e),
    })
}

async fn load_yaml_async(path: &Path) -> Result<AccountsFile, AuthError> {
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|source| AuthError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if meta.len() > MAX_ACCOUNTS_FILE_BYTES {
        return Err(AuthError::TooLarge {
            path: path.to_path_buf(),
            size: meta.len(),
            limit: MAX_ACCOUNTS_FILE_BYTES,
        });
    }
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|source| AuthError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    serde_yml::from_slice(&bytes).map_err(|e| AuthError::Parse {
        path: path.to_path_buf(),
        location: redact_yaml_location(&e),
    })
}

const INOTIFY_QUIESCE: Duration = Duration::from_millis(100);
const INOTIFY_MAX_DEBOUNCE: Duration = Duration::from_secs(2);
const INOTIFY_CHANNEL_CAP: usize = 256;

async fn run_inotify(path: PathBuf, auth: Arc<TokenAuthentication>) -> Result<(), notify::Error> {
    use notify::{Event, EventKind, RecursiveMode, Watcher};

    // Bounded channel: producer drops on full and emits a debug — debounce
    // already merges duplicate events, so no signal is lost.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(INOTIFY_CHANNEL_CAP);
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(ev) => {
            if let Err(e) = tx.try_send(ev) {
                match e {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                        debug!("inotify channel full; dropping event (debounce will catch up)");
                    }
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {}
                }
            }
        }
        Err(e) => warn!("inotify error: {e}"),
    })?;

    let watch_target = path.parent().unwrap_or(Path::new("."));
    watcher.watch(watch_target, RecursiveMode::NonRecursive)?;

    // Capture the configured filename once; events whose filename differs are
    // ignored (parent-dir watch would otherwise wake us for any sibling write).
    let target_filename = path.file_name().map(std::ffi::OsString::from);

    let event_matches = |ev: &Event| -> bool {
        // Skip Remove entirely: the next Create/Modify will reload, and a
        // bare Remove just produces ENOENT spam in the warn log.
        if !matches!(ev.kind, EventKind::Modify(_) | EventKind::Create(_)) {
            return false;
        }
        let Some(want) = target_filename.as_deref() else {
            return true;
        };
        if ev.paths.is_empty() {
            return false;
        }
        ev.paths
            .iter()
            .any(|p| p.file_name().is_some_and(|n| n == want))
    };

    loop {
        // Block for the next interesting event.
        let first = loop {
            match rx.recv().await {
                Some(ev) if event_matches(&ev) => break ev,
                Some(_) => continue,
                None => {
                    // Watcher channel closed — typically the `Watcher` was
                    // dropped (e.g. inode replaced under the watch on a K8s
                    // ConfigMap symlink swap). Log loudly so an operator sees
                    // that we have fallen back to interval-only reload.
                    warn!(
                        path = %path.display(),
                        "inotify channel closed; reload now relies on the timer fallback"
                    );
                    return Ok(());
                }
            }
        };
        let _ = first;

        // Drain any further events within a quiescent window. Reset the
        // sleep on every matching event; cap the total wait at
        // INOTIFY_MAX_DEBOUNCE to avoid starvation if events keep streaming.
        let deadline = tokio::time::Instant::now() + INOTIFY_MAX_DEBOUNCE;
        loop {
            let quiesce_until = tokio::time::Instant::now() + INOTIFY_QUIESCE;
            let next_deadline = quiesce_until.min(deadline);
            tokio::select! {
                biased;
                ev = rx.recv() => {
                    match ev {
                        Some(ev) if event_matches(&ev) => continue,
                        Some(_) => continue,
                        None => break,
                    }
                }
                () = tokio::time::sleep_until(next_deadline) => {
                    break;
                }
            }
        }

        auth.reload().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_file() -> AccountsFile {
        AccountsFile {
            accounts: vec![
                Account {
                    name: "user1".into(),
                    token: "tok1".into(),
                    reuse: false,
                    routes: vec!["127.0.0.1:8888".into()],
                    allowed_ips: vec!["127.0.0.1".into(), "192.168.1.0/24".into()],
                },
                Account {
                    name: "user2".into(),
                    token: "tok2".into(),
                    reuse: true,
                    routes: vec!["example.com:5050".into()],
                    allowed_ips: vec!["10.0.0.0/8".into()],
                },
            ],
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn build_and_query() {
        let snap = AccountsSnapshot::build(sample_file()).unwrap();
        let m = snap.authenticate("tok1", "127.0.0.1:8888", ip("127.0.0.1"));
        assert!(m.is_some());
        assert_eq!(m.unwrap().account.name, "user1");
        assert!(snap
            .authenticate("tok1", "127.0.0.1:8888", ip("192.168.1.50"))
            .is_some());
        assert!(snap
            .authenticate("tok1", "127.0.0.1:8888", ip("10.0.0.1"))
            .is_none());
        assert!(snap
            .authenticate("badtoken", "127.0.0.1:8888", ip("127.0.0.1"))
            .is_none());
        assert!(snap
            .authenticate("tok1", "wrong.route:1", ip("127.0.0.1"))
            .is_none());
    }

    #[test]
    fn duplicate_token_rejected_reports_account_name_not_token() {
        let mut f = sample_file();
        f.accounts[1].token = "tok1".into();
        let r = AccountsSnapshot::build(f);
        match r {
            Err(AuthError::DuplicateToken(name)) => {
                assert_eq!(name, "user2");
                let displayed = format!("{}", AuthError::DuplicateToken(name));
                assert!(!displayed.contains("tok1"));
            }
            other => panic!("expected DuplicateToken, got {other:?}"),
        }
    }

    #[test]
    fn lease_no_reuse_conflicts() {
        let auth = TokenAuthentication::from_accounts(sample_file()).unwrap();
        let snap = auth.snapshot_arc();
        let hash = token_hash(b"tok1");
        let acc = snap.by_token_hash.get(&hash).unwrap().account.clone();
        let g1 = auth.leases().try_lease_arc(&acc).unwrap();
        let r2 = auth.leases().try_lease_arc(&acc);
        assert!(matches!(r2, Err(LeaseError::Conflict)));
        drop(g1);
        let _g3 = auth.leases().try_lease_arc(&acc).unwrap();
    }

    #[test]
    fn lease_reuse_true_allows_concurrent() {
        let auth = TokenAuthentication::from_accounts(sample_file()).unwrap();
        let snap = auth.snapshot_arc();
        let hash = token_hash(b"tok2");
        let acc = snap.by_token_hash.get(&hash).unwrap().account.clone();
        let g1 = auth.leases().try_lease_arc(&acc).unwrap();
        let g2 = auth.leases().try_lease_arc(&acc).unwrap();
        assert_eq!(auth.leases().active_count(&acc), 2);
        drop(g1);
        drop(g2);
        assert_eq!(auth.leases().active_count(&acc), 0);
    }

    #[test]
    fn lease_cas_serializes_concurrent_attempts() {
        use std::sync::atomic::AtomicUsize;
        let auth = Arc::new(TokenAuthentication::from_accounts(sample_file()).unwrap());
        let snap = auth.snapshot_arc();
        let hash = token_hash(b"tok1");
        let acc = snap.by_token_hash.get(&hash).unwrap().account.clone();

        let won = Arc::new(AtomicUsize::new(0));
        let conflict = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let leases = auth.leases().clone();
            let acc = acc.clone();
            let won = won.clone();
            let conflict = conflict.clone();
            handles.push(std::thread::spawn(move || {
                match leases.try_lease_arc(&acc) {
                    Ok(g) => {
                        won.fetch_add(1, Ordering::SeqCst);
                        drop(g);
                    }
                    Err(LeaseError::Conflict) => {
                        conflict.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(LeaseError::Exhausted) => {
                        panic!("unexpected Exhausted on reuse=false path");
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            won.load(Ordering::SeqCst) + conflict.load(Ordering::SeqCst),
            16
        );
        assert_eq!(auth.leases().active_count(&acc), 0);
    }

    #[test]
    fn lease_per_account_ceiling_enforced() {
        let leases = Arc::new(LeaseTracker::with_max_per_account(3));
        let acc = Arc::new(Account {
            name: "u".into(),
            token: "t".into(),
            reuse: true,
            routes: vec![],
            allowed_ips: vec![],
        });
        let g1 = leases.try_lease_arc(&acc).unwrap();
        let _g2 = leases.try_lease_arc(&acc).unwrap();
        let _g3 = leases.try_lease_arc(&acc).unwrap();
        let r = leases.try_lease_arc(&acc);
        assert!(matches!(r, Err(LeaseError::Exhausted)));
        assert_eq!(leases.active_count(&acc), 3);
        drop(g1);
        let _g4 = leases.try_lease_arc(&acc).unwrap();
        assert_eq!(leases.active_count(&acc), 3);
    }

    #[test]
    fn lease_release_garbage_collects_zero_entries() {
        let leases = Arc::new(LeaseTracker::new());
        let acc = Arc::new(Account {
            name: "u".into(),
            token: "tok-gc".into(),
            reuse: true,
            routes: vec![],
            allowed_ips: vec![],
        });
        let g = leases.try_lease_arc(&acc).unwrap();
        let h = token_hash(b"tok-gc");
        assert!(leases.active.contains_key(&h));
        drop(g);
        // After release, the entry should be GCed so reloads cannot leak.
        assert!(!leases.active.contains_key(&h));
    }

    #[test]
    fn lease_survives_reload_when_token_unchanged() {
        // Two snapshots issuing fresh Arc<Account> with the same token must
        // resolve to the same lease slot.
        let snap1 = AccountsSnapshot::build(sample_file()).unwrap();
        let snap2 = AccountsSnapshot::build(sample_file()).unwrap();
        let h = token_hash(b"tok2");
        let acc1 = snap1.by_token_hash.get(&h).unwrap().account.clone();
        let acc2 = snap2.by_token_hash.get(&h).unwrap().account.clone();
        // They are distinct Arc allocations:
        assert!(!Arc::ptr_eq(&acc1, &acc2));

        let leases = Arc::new(LeaseTracker::new());
        let g1 = leases.try_lease_arc(&acc1).unwrap();
        // Release-via-acc2 path: hash-keyed tracker must observe count==1
        // for either Arc identity.
        assert_eq!(leases.active_count(&acc1), 1);
        assert_eq!(leases.active_count(&acc2), 1);
        let g2 = leases.try_lease_arc(&acc2).unwrap();
        assert_eq!(leases.active_count(&acc1), 2);
        drop(g1);
        drop(g2);
        assert_eq!(leases.active_count(&acc1), 0);
    }

    /// Smoke test for timing-attack invariance on the HashMap probe.
    ///
    /// We don't claim ns-tight constant time — that would require disabling
    /// CPU frequency scaling, isolating cores, and a microbenchmarking
    /// harness. What we *do* claim: a random 32-byte input and a known-prefix
    /// input both hit the same code path (BLAKE3 hash → HashMap miss →
    /// return None) with no token-content-dependent branches before the miss.
    /// This test is a sanity check that the order-of-magnitude is comparable.
    #[test]
    fn authenticate_timing_smoke() {
        use std::time::Instant;
        let snap = AccountsSnapshot::build(sample_file()).unwrap();
        let ip4 = ip("127.0.0.1");

        // Warm up.
        for _ in 0..10_000 {
            let _ = snap.authenticate("tok-no-match", "r", ip4);
            let _ = snap.authenticate("tok1prefix-extended-bytes-x", "r", ip4);
        }

        let n = 50_000;
        let t0 = Instant::now();
        for _ in 0..n {
            // Token close to a real one: same length, different content.
            let _ = snap.authenticate("tok9", "r", ip4);
        }
        let near_miss = t0.elapsed();

        let t1 = Instant::now();
        for _ in 0..n {
            // Token nothing like a real one.
            let _ = snap.authenticate("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "r", ip4);
        }
        let random_miss = t1.elapsed();

        // Tolerate a 5x ratio either direction. Lower bounds aren't meaningful
        // here — we're guarding against an order-of-magnitude regression
        // (e.g. accidentally adding a strncmp short-circuit before the hash).
        let ratio = near_miss.as_nanos() as f64 / random_miss.as_nanos() as f64;
        assert!(
            (0.2..=5.0).contains(&ratio),
            "near_miss={near_miss:?} random_miss={random_miss:?} ratio={ratio}"
        );
    }

    #[tokio::test]
    async fn reload_swap_and_malformed_preserves_snapshot() {
        use std::io::Write;
        let mut tf = tempfile::NamedTempFile::new().unwrap();
        let yaml1 = r#"
accounts:
  - name: u1
    token: tok-old
    reuse: true
    routes: ["127.0.0.1:1"]
    allowedIps: ["127.0.0.1"]
"#;
        tf.write_all(yaml1.as_bytes()).unwrap();
        tf.flush().unwrap();

        let auth = TokenAuthentication::from_file(tf.path()).unwrap();
        let snap1 = auth.snapshot_arc();
        let h_old = token_hash(b"tok-old");
        let h_new = token_hash(b"tok-new");
        assert!(snap1.by_token_hash.contains_key(&h_old));
        assert!(!snap1.by_token_hash.contains_key(&h_new));

        let yaml2 = r#"
accounts:
  - name: u1
    token: tok-new
    reuse: true
    routes: ["127.0.0.1:1"]
    allowedIps: ["127.0.0.1"]
"#;
        std::fs::write(tf.path(), yaml2).unwrap();
        auth.reload().await;
        let snap2 = auth.snapshot_arc();
        assert!(snap2.by_token_hash.contains_key(&h_new));
        assert!(!snap2.by_token_hash.contains_key(&h_old));

        std::fs::write(tf.path(), b": : : not yaml").unwrap();
        auth.reload().await;
        let snap3 = auth.snapshot_arc();
        assert!(
            snap3.by_token_hash.contains_key(&h_new),
            "malformed reload must preserve previous snapshot"
        );

        let yaml_dup = r#"
accounts:
  - name: u1
    token: dup
    reuse: true
    routes: ["127.0.0.1:1"]
    allowedIps: ["127.0.0.1"]
  - name: u2
    token: dup
    reuse: true
    routes: ["127.0.0.1:1"]
    allowedIps: ["127.0.0.1"]
"#;
        std::fs::write(tf.path(), yaml_dup).unwrap();
        auth.reload().await;
        let snap4 = auth.snapshot_arc();
        assert!(
            snap4.by_token_hash.contains_key(&h_new),
            "duplicate-token reload must preserve previous snapshot"
        );
        assert!(!snap4.by_token_hash.contains_key(&token_hash(b"dup")));
    }
}
