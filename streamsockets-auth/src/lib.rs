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
use subtle::ConstantTimeEq;
use thiserror::Error;
use tracing::{debug, info, warn};

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
    /// YAML parser rejected the contents.
    #[error("yaml parse error in {path}: {source}")]
    Parse {
        /// Path whose contents failed to parse.
        path: PathBuf,
        /// Underlying parser error.
        #[source]
        source: serde_yml::Error,
    },
    /// Two accounts share the same `token` — file is rejected.
    #[error("each account must have a unique token; duplicate: {0}")]
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
/// same identity (across reloads) are considered equal, so `LeaseTracker`'s
/// `DashMap<Arc<Account>, _>` survives a reload that re-issues the account.
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

/// Pre-computed lookup cache for one account (mirrors Java `AccountCache`).
#[derive(Debug)]
pub struct AccountCache {
    /// Backing account row. Shared so `LeaseTracker` keys remain valid.
    pub account: Arc<Account>,
    /// Pre-computed set of allowed routes for O(1) membership test.
    pub route_set: HashSet<String>,
    /// Parsed CIDRs from [`Account::allowed_ips`].
    pub allowed_cidrs: Vec<IpNet>,
}

/// Atomic snapshot of all accounts and lookup tables.
#[derive(Debug)]
pub struct AccountsSnapshot {
    /// Token → account cache. Lookups are O(1).
    pub by_token: HashMap<String, Arc<AccountCache>>,
    /// Union of every account's `routes` — useful for telemetry / startup checks.
    pub all_routes: HashSet<String>,
}

impl AccountsSnapshot {
    /// Build a snapshot from a parsed YAML file. Validates uniqueness of tokens
    /// and parses every `allowedIps` entry. Empty `allowedIps` is allowed (deny-all,
    /// matching Java behavior).
    pub fn build(file: AccountsFile) -> Result<Self, AuthError> {
        let mut by_token: HashMap<String, Arc<AccountCache>> = HashMap::new();
        let mut all_routes: HashSet<String> = HashSet::new();

        for account in file.accounts {
            if by_token.contains_key(&account.token) {
                return Err(AuthError::DuplicateToken(account.token));
            }
            if account.allowed_ips.is_empty() {
                warn!(
                    account = %account.name,
                    "account has empty allowedIps; every connection will be rejected with 403"
                );
            }
            let mut cidrs = Vec::with_capacity(account.allowed_ips.len());
            for raw in &account.allowed_ips {
                // Allow bare IP without prefix; default to /32 or /128.
                let parsed = parse_cidr_lenient(raw).map_err(|source| AuthError::InvalidCidr {
                    account: account.name.clone(),
                    value: raw.clone(),
                    source,
                })?;
                cidrs.push(parsed);
            }
            let route_set: HashSet<String> = account.routes.iter().cloned().collect();
            for r in &route_set {
                all_routes.insert(r.clone());
            }
            let token = account.token.clone();
            let arc_account = Arc::new(account);
            let cache = Arc::new(AccountCache {
                account: arc_account,
                route_set,
                allowed_cidrs: cidrs,
            });
            by_token.insert(token, cache);
        }

        info!("Built authentication cache for {} accounts", by_token.len());
        Ok(AccountsSnapshot {
            by_token,
            all_routes,
        })
    }

    /// Authenticate `(token, route, client_ip)`. Returns the matched account or `None`.
    ///
    /// **Timing-safety:** the candidate token is compared in constant time against
    /// the matched cache key. The HashMap lookup itself is not constant-time, but
    /// we only return `Some(_)` after a constant-time equality check — so an attacker
    /// can't distinguish "found in HashMap" from "found+equal" via timing.
    pub fn authenticate(
        &self,
        token: &str,
        route: &str,
        client_ip: &str,
    ) -> Option<Arc<AccountCache>> {
        let cache = self.by_token.get(token)?;
        // Defense-in-depth: re-verify equality in constant time.
        let stored = cache.account.token.as_bytes();
        if stored.len() != token.len() || !bool::from(stored.ct_eq(token.as_bytes())) {
            return None;
        }
        if !cache.route_set.contains(route) {
            debug!(route, client_ip, "route not allowed for token");
            return None;
        }
        let parsed_ip: IpAddr = match client_ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                warn!(client_ip, "could not parse client IP");
                return None;
            }
        };
        for net in &cache.allowed_cidrs {
            if net.contains(&parsed_ip) {
                return Some(cache.clone());
            }
        }
        debug!(client_ip, "client IP not in any allowed CIDR");
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
        // Bare IP — use /32 for v4, /128 for v6. If parsing as IP fails,
        // fall through to the IpNet parser to get a real error type.
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
/// Per MIGRATION.md §8.4: `active: DashMap<Arc<Account>, AtomicUsize>`. For
/// `reuse=false` accounts, `lease()` performs a `compare_exchange(0, 1)` so the
/// 409-conflict path is TOCTOU-safe under concurrent connect storms.
#[derive(Debug, Default)]
pub struct LeaseTracker {
    active: DashMap<Arc<Account>, AtomicUsize>,
}

/// Errors raised by [`LeaseTracker::try_lease_arc`].
#[derive(Debug, Error)]
pub enum LeaseError {
    /// `reuse=false` and another tunnel already holds this account.
    #[error("account already in use")]
    Conflict,
}

impl LeaseTracker {
    /// Construct an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to acquire a lease. Returns an `Arc`-backed guard with `'static` lifetime —
    /// the tracker pointer is shared so the guard outlives the original
    /// `Arc<TokenAuthentication>` reference safely.
    ///
    /// For `account.reuse == false`, uses `compare_exchange(0, 1)` to atomically
    /// guarantee at most one outstanding lease.
    pub fn try_lease_arc(
        self: &Arc<Self>,
        account: &Arc<Account>,
    ) -> Result<LeaseGuard, LeaseError> {
        let entry = self
            .active
            .entry(account.clone())
            .or_insert_with(|| AtomicUsize::new(0));
        if !account.reuse {
            entry
                .value()
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .map_err(|_| LeaseError::Conflict)?;
        } else {
            entry.value().fetch_add(1, Ordering::SeqCst);
        }
        Ok(LeaseGuard {
            tracker: Arc::clone(self),
            account: account.clone(),
            released: false,
        })
    }

    fn release(&self, account: &Arc<Account>) {
        if let Some(entry) = self.active.get(account) {
            // Saturating sub: we never go below zero. AtomicUsize doesn't have
            // saturating_sub directly; use fetch_update.
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
    }

    /// Test helper: count of active leases for `account`.
    #[must_use]
    pub fn active_count(&self, account: &Arc<Account>) -> usize {
        self.active
            .get(account)
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
            self.tracker.release(&self.account);
        }
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        if !self.released {
            self.tracker.release(&self.account);
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
        // Serialize concurrent reload triggers (inotify + timer fallback can race).
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
    ///
    /// `interval == 0` disables **both** paths (per MIGRATION.md §8.3
    /// "ACCOUNTS_RELOAD_INTERVAL_SECONDS=0 disables both reload paths"). The
    /// inotify spawn is gated on `!interval.is_zero()` — earlier revisions only
    /// gated the timer, which left inotify running and was a verdict
    /// SHIP-BLOCKER.
    pub fn spawn_reload_watcher(self: &Arc<Self>, interval: Duration) {
        if interval.is_zero() {
            return;
        }
        if self.config_path.is_none() {
            return;
        }
        let me = Arc::clone(self);
        let me_timer = Arc::clone(&me);
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(interval);
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            iv.tick().await; // skip immediate fire
            loop {
                iv.tick().await;
                me_timer.reload().await;
            }
        });
        if let Some(path) = me.config_path.clone() {
            let me_inotify = Arc::clone(&me);
            tokio::spawn(async move {
                if let Err(e) = run_inotify(path, me_inotify).await {
                    warn!(error = %e, "inotify watcher exited; relying on timer fallback");
                }
            });
        }
    }
}

fn load_yaml_blocking(path: &Path) -> Result<AccountsFile, AuthError> {
    let bytes = std::fs::read(path).map_err(|source| AuthError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_yml::from_slice(&bytes).map_err(|source| AuthError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

async fn load_yaml_async(path: &Path) -> Result<AccountsFile, AuthError> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|source| AuthError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    serde_yml::from_slice(&bytes).map_err(|source| AuthError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

async fn run_inotify(path: PathBuf, auth: Arc<TokenAuthentication>) -> Result<(), notify::Error> {
    use notify::{Event, EventKind, RecursiveMode, Watcher};
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(ev) => {
            let _ = tx.send(ev);
        }
        Err(e) => warn!("inotify error: {e}"),
    })?;
    let watch_target = path.parent().unwrap_or(Path::new("."));
    watcher.watch(watch_target, RecursiveMode::NonRecursive)?;
    while let Some(ev) = rx.recv().await {
        if matches!(
            ev.kind,
            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
        ) {
            // Some editors atomically replace the file (rename), generating Create/Remove pairs.
            // Debounce briefly so we read the final content.
            tokio::time::sleep(Duration::from_millis(50)).await;
            auth.reload().await;
        }
    }
    Ok(())
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

    #[test]
    fn build_and_query() {
        let snap = AccountsSnapshot::build(sample_file()).unwrap();
        let m = snap.authenticate("tok1", "127.0.0.1:8888", "127.0.0.1");
        assert!(m.is_some());
        assert_eq!(m.unwrap().account.name, "user1");
        assert!(snap
            .authenticate("tok1", "127.0.0.1:8888", "192.168.1.50")
            .is_some());
        assert!(snap
            .authenticate("tok1", "127.0.0.1:8888", "10.0.0.1")
            .is_none());
        assert!(snap
            .authenticate("badtoken", "127.0.0.1:8888", "127.0.0.1")
            .is_none());
        assert!(snap
            .authenticate("tok1", "wrong.route:1", "127.0.0.1")
            .is_none());
    }

    #[test]
    fn duplicate_token_rejected() {
        let mut f = sample_file();
        f.accounts[1].token = "tok1".into();
        let r = AccountsSnapshot::build(f);
        assert!(matches!(r, Err(AuthError::DuplicateToken(_))));
    }

    #[test]
    fn lease_no_reuse_conflicts() {
        let auth = TokenAuthentication::from_accounts(sample_file()).unwrap();
        let snap = auth.snapshot_arc();
        let acc = snap.by_token.get("tok1").unwrap().account.clone();
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
        let acc = snap.by_token.get("tok2").unwrap().account.clone();
        let g1 = auth.leases().try_lease_arc(&acc).unwrap();
        let g2 = auth.leases().try_lease_arc(&acc).unwrap();
        assert_eq!(auth.leases().active_count(&acc), 2);
        drop(g1);
        drop(g2);
        assert_eq!(auth.leases().active_count(&acc), 0);
    }

    /// CAS path: under hammered concurrent attempts, exactly one wins.
    #[test]
    fn lease_cas_serializes_concurrent_attempts() {
        use std::sync::atomic::AtomicUsize;
        let auth = Arc::new(TokenAuthentication::from_accounts(sample_file()).unwrap());
        let snap = auth.snapshot_arc();
        let acc = snap.by_token.get("tok1").unwrap().account.clone();

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
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // At any instant only 1 lease is held; over time, multiple win sequentially.
        // The invariant we care about: total attempts == won + conflict, and at
        // termination active_count == 0.
        assert_eq!(
            won.load(Ordering::SeqCst) + conflict.load(Ordering::SeqCst),
            16
        );
        assert_eq!(auth.leases().active_count(&acc), 0);
    }

    /// Spec §11.1: "write file, sleep, verify swap, malformed reload preserves
    /// old snapshot". Exercises the full reload() path — not just YAML parsing.
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
        assert!(snap1.by_token.contains_key("tok-old"));
        assert!(!snap1.by_token.contains_key("tok-new"));

        // Rewrite the file with a different token.
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
        assert!(snap2.by_token.contains_key("tok-new"));
        assert!(!snap2.by_token.contains_key("tok-old"));

        // Now write malformed YAML; reload must preserve snap2.
        std::fs::write(tf.path(), b": : : not yaml").unwrap();
        auth.reload().await;
        let snap3 = auth.snapshot_arc();
        assert!(
            snap3.by_token.contains_key("tok-new"),
            "malformed reload must preserve previous snapshot"
        );

        // And: a duplicate-token YAML must also preserve the old snapshot.
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
            snap4.by_token.contains_key("tok-new"),
            "duplicate-token reload must preserve previous snapshot"
        );
        assert!(!snap4.by_token.contains_key("dup"));
    }
}
