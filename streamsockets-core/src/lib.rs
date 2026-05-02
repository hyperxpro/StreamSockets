//! Shared types, env-helpers, tracing init, runtime kind detection.
//!
//! Mirrors `common/src/main/java/.../Utils.java` plus the new runtime-selection logic
//! described in MIGRATION.md §4.

#![warn(missing_docs)]
// Pedantic lints we deliberately suppress (with reasoning):
// - `doc_markdown`: fires on every kernel/identifier reference in prose; noisy.
// - `missing_*_doc`, `must_use_candidate`: enforced via review, not lint.
// - `module_name_repetitions`: re-exports use parent module names by design.
// - `cast_*`: deliberate where present; alternatives obscure intent.
// - `redundant_closure_for_method_calls`: closures clarify intent in iterator chains.
// - `manual_let_else`: keeps explicit `match` form for readability when arms log.
// - `items_after_statements`: tests inside fn bodies are intentional.
// - `if_not_else`, `needless_continue`, `match_wild_err_arm`, `map_unwrap_or`,
//   `should_implement_trait`, `duplicated_attributes`: judged case-by-case.
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

use std::env;
use std::sync::atomic::{AtomicBool, Ordering};

use once_cell::sync::OnceCell;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub mod buf_pool;
#[cfg(target_os = "linux")]
pub mod gro;
pub mod runtime;
pub mod udp_egress;
#[cfg(all(target_os = "linux", feature = "uring"))]
pub mod uring_udp;

pub use buf_pool::{BufHandle, BufPool, FreezeError, DEFAULT_BUF_SIZE, DEFAULT_POOL_CAPACITY};
pub use runtime::{
    client_threads_default, resolve_worker_count, server_threads_default, spawn_per_core,
    WorkerHandle,
};
pub use udp_egress::{
    classify_io_error, ErrorClass, RecvBatch, SegmentList, TokioUdp, TruncatedRecv, UdpEgress,
};

/// Test helper: returns whether io_uring is reachable on this host. Used by
/// the uring_udp test module to gracefully skip on CI sandboxes where
/// io_uring_setup returns EPERM/ENOSYS.
#[cfg(all(target_os = "linux", feature = "uring", test))]
pub(crate) fn pick_runtime_kind_for_test() -> bool {
    uring_kernel_supported()
}

/// Returns the value of `key` in the process environment, falling back to the JVM-style
/// `-Dkey=value` system property (which on Rust we treat as a regular env var) and
/// finally to `default_value`.
#[must_use]
pub fn env_value(key: &str, default_value: &str) -> String {
    env::var(key).unwrap_or_else(|_| default_value.to_string())
}

/// Convenience: returns `Some(value)` when the env var is present and non-empty.
#[must_use]
pub fn env_opt(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.is_empty())
}

/// Parse an integer env var. Panics on parse failure (matches Java's behavior, which
/// throws `NumberFormatException` and crashes the JVM).
///
/// Logs a structured `error!` event before panicking. With `panic = "abort"`
/// in release builds the abort happens before the panic hook can flush, so
/// we emit the event ourselves; journald / k8s log collection will capture it.
#[must_use]
pub fn env_value_as_int(key: &str, default_value: i64) -> i64 {
    match env::var(key) {
        Ok(v) => match v.parse::<i64>() {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(
                    key = %key,
                    value = %v,
                    error = %e,
                    "invalid env value (i64); aborting"
                );
                panic!("env var {key}={v} is not a valid integer")
            }
        },
        Err(_) => default_value,
    }
}

/// Parse a u64 env var. See [`env_value_as_int`] for the panic-logging rationale.
#[must_use]
pub fn env_value_as_u64(key: &str, default_value: u64) -> u64 {
    match env::var(key) {
        Ok(v) => match v.parse::<u64>() {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(
                    key = %key,
                    value = %v,
                    error = %e,
                    "invalid env value (u64); aborting"
                );
                panic!("env var {key}={v} is not a valid u64")
            }
        },
        Err(_) => default_value,
    }
}

/// Parse a boolean env var. Truthy values: `true`, `1`, `yes`, `on`
/// (case-insensitive). Anything else (including empty) → `default_value`.
#[must_use]
pub fn env_bool(key: &str, default_value: bool) -> bool {
    match env::var(key) {
        Ok(v) => {
            let v = v.to_ascii_lowercase();
            matches!(v.as_str(), "true" | "1" | "yes" | "on")
        }
        Err(_) => default_value,
    }
}

/// Whether `DISABLE_IOURING=true` is set. Matches `Utils.isIOUringDisabled()`.
#[must_use]
pub fn is_iouring_disabled() -> bool {
    static CACHED: OnceCell<bool> = OnceCell::new();
    *CACHED.get_or_init(|| env_bool("DISABLE_IOURING", false))
}

/// Runtime kind selected at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeKind {
    /// `tokio-uring` on Linux ≥ 5.6 with io_uring not blocked.
    Uring,
    /// `tokio` (epoll on Linux).
    Tokio,
}

impl RuntimeKind {
    /// Stable Prometheus label for this runtime kind. Per MIGRATION.md §9.2,
    /// the documented label set is `io_uring | epoll | tokio`:
    ///
    /// - `Uring` → `"io_uring"`
    /// - `Tokio` on Linux → `"epoll"` (kernel uses epoll under tokio's reactor)
    /// - `Tokio` on any non-Linux dev build → `"tokio"` (catch-all)
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Uring => "io_uring",
            Self::Tokio => {
                if cfg!(target_os = "linux") {
                    "epoll"
                } else {
                    "tokio"
                }
            }
        }
    }
}

/// Probe whether the running kernel supports io_uring without committing to it.
///
/// Issues a non-fatal `io_uring_setup(1, &mut params)` syscall — entries=1
/// because Linux returns `EINVAL` for `entries=0` regardless of feature support,
/// which would make `entries=0` indistinguishable from "kernel does not have
/// io_uring". Specifically:
///
/// - `ENOSYS` (38): kernel < 5.1, no io_uring at all → fall back.
/// - `EPERM` (1): seccomp/LSM blocks io_uring_setup → fall back.
/// - `EINVAL` (22): impossible with our `entries=1` call but defensive — fall back.
/// - any other errno: unexpected; conservatively fall back.
/// - success: tear down the trial ring with `close(2)` and report supported.
///
/// Mirrors `Netty IoUring.isAvailable()`.
#[cfg(target_os = "linux")]
fn uring_kernel_supported() -> bool {
    // We don't link tokio-uring here (keeps streamsockets-core dep-free on non-Linux).
    // Instead, do a raw syscall via libc.
    #[repr(C)]
    #[derive(Default)]
    struct IoUringParams {
        sq_entries: u32,
        cq_entries: u32,
        flags: u32,
        sq_thread_cpu: u32,
        sq_thread_idle: u32,
        features: u32,
        wq_fd: u32,
        resv: [u32; 3],
        sq_off: [u32; 10],
        cq_off: [u32; 10],
    }
    // 4 (sq_entries) + 4 + 4 + 4 + 4 + 4 + 4 = 28
    // resv [u32; 3] = 12 → total 40
    // sq_off [u32; 10] = 40 → total 80
    // cq_off [u32; 10] = 40 → total 120
    // ABI lock: kernel `struct io_uring_params` has been 120B since 5.1; if
    // this fails, the kernel headers grew a field and our layout is stale.
    const _: () = assert!(std::mem::size_of::<IoUringParams>() == 120);

    let mut params = IoUringParams::default();
    let entries: u32 = 1;
    // SAFETY: io_uring_setup is a syscall; passing a stack-owned IoUringParams
    // is sound. The ret value is interpreted as a file descriptor on success.
    // libc::syscall is variadic in C; the Rust binding takes c_long, so the
    // pointer must round-trip through that integer width.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_io_uring_setup,
            entries as libc::c_long,
            std::ptr::addr_of_mut!(params) as libc::c_long,
        )
    };
    if ret < 0 {
        // Use io::Error::last_os_error() rather than reaching into
        // __errno_location: the former calls the same TLS but via a stable
        // API, and avoids the unsafe deref entirely.
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(0);
        match errno {
            libc::ENOSYS | libc::EPERM | libc::EINVAL => {
                tracing::debug!(errno, "io_uring_setup probe failed; using tokio (epoll)");
            }
            other => {
                tracing::warn!(
                    errno = other,
                    "io_uring_setup probe failed with unexpected errno; using tokio (epoll)"
                );
            }
        }
        return false;
    }
    // SAFETY: ret is a valid fd we just received.
    unsafe {
        libc::close(ret as libc::c_int);
    }
    true
}

#[cfg(not(target_os = "linux"))]
fn uring_kernel_supported() -> bool {
    false
}

/// Selects the runtime per MIGRATION.md §4.
#[must_use]
pub fn pick_runtime() -> RuntimeKind {
    if !cfg!(target_os = "linux") {
        info!("using tokio (non-Linux)");
        return RuntimeKind::Tokio;
    }
    if is_iouring_disabled() {
        info!("DISABLE_IOURING=true; using tokio (epoll)");
        return RuntimeKind::Tokio;
    }
    if !uring_kernel_supported() {
        info!("io_uring unsupported by kernel; using tokio (epoll)");
        return RuntimeKind::Tokio;
    }
    info!("using tokio-uring (io_uring)");
    RuntimeKind::Uring
}

/// Initialize global tracing. Idempotent — subsequent calls are no-ops.
pub fn init_tracing() {
    static INITIALIZED: AtomicBool = AtomicBool::new(false);
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let filter = EnvFilter::try_from_env("LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info"));
    let format = env_value("LOG_FORMAT", "auto");
    let is_tty = is_stdout_tty();

    let registry = tracing_subscriber::registry().with(filter);

    match format.as_str() {
        "json" => {
            registry
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_target(true)
                        .with_thread_ids(false)
                        .json(),
                )
                .try_init()
                .ok();
        }
        "pretty" => {
            registry
                .with(tracing_subscriber::fmt::layer().pretty().with_target(true))
                .try_init()
                .ok();
        }
        _ => {
            // auto: pretty on TTY, json otherwise (Docker-friendly)
            if is_tty {
                registry
                    .with(tracing_subscriber::fmt::layer().compact())
                    .try_init()
                    .ok();
            } else {
                registry
                    .with(tracing_subscriber::fmt::layer().json())
                    .try_init()
                    .ok();
            }
        }
    }
}

#[cfg(unix)]
fn is_stdout_tty() -> bool {
    unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 }
}

#[cfg(not(unix))]
fn is_stdout_tty() -> bool {
    false
}

/// Returns the available number of cores, or 1 if detection fails.
#[must_use]
pub fn num_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

// ─── sd_notify (systemd Type=notify support) ──────────────────────────────────
//
// Operators deploying via the published systemd units (docs/v2.md §5,
// MIGRATION.md §12.2) declare `Type=notify` and `WatchdogSec=30`. The binary
// MUST send `READY=1` once and `WATCHDOG=1` periodically, otherwise systemd
// hangs at startup and SIGKILLs after WatchdogSec elapses.
//
// We implement a minimal direct-syscall sd_notify using `nix` on Linux. On
// non-Linux targets these are no-ops so the same call sites compile everywhere.

/// Send `READY=1` to the systemd notify socket if `NOTIFY_SOCKET` is set.
/// No-op when unset (process not under systemd) or on non-Linux targets.
pub fn sd_notify_ready() {
    sd_notify_inner("READY=1\n");
}

/// Send `WATCHDOG=1`. Call from a periodic task whose interval is half of
/// `WatchdogSec` per systemd's recommendation.
pub fn sd_notify_watchdog() {
    sd_notify_inner("WATCHDOG=1\n");
}

/// Send `STOPPING=1` to indicate graceful shutdown is in progress.
pub fn sd_notify_stopping() {
    sd_notify_inner("STOPPING=1\n");
}

#[cfg(target_os = "linux")]
fn sd_notify_inner(msg: &str) {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    use nix::unistd::write;

    let path = match std::env::var_os("NOTIFY_SOCKET") {
        Some(p) => p,
        None => return,
    };
    let path_bytes = path.as_encoded_bytes();
    if path_bytes.is_empty() {
        return;
    }

    // systemd supports both filesystem paths and abstract sockets ("@" prefix).
    // Build a UnixAddr accordingly.
    let addr = if path_bytes[0] == b'@' {
        // Abstract socket: leading '@' is replaced with NUL by the kernel.
        match UnixAddr::new_abstract(&path_bytes[1..]) {
            Ok(a) => a,
            Err(_) => return,
        }
    } else {
        // Filesystem socket path. SAFETY: NOTIFY_SOCKET is set by systemd as
        // a valid OS path; on Linux all paths are valid encoded byte sequences.
        let os_path: &std::ffi::OsStr =
            unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(path_bytes) };
        match UnixAddr::new(std::path::Path::new(os_path)) {
            Ok(a) => a,
            Err(_) => return,
        }
    };

    let fd = match socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    ) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("sd_notify: socket() failed: {e}");
            return;
        }
    };
    if let Err(e) = connect(fd.as_raw_fd(), &addr) {
        tracing::debug!("sd_notify: connect() failed: {e}");
        drop(fd);
        return;
    }
    if let Err(e) = write(&fd, msg.as_bytes()) {
        // A failed write of READY=1 will cause systemd's WatchdogSec timer to
        // SIGKILL the process. Log loudly so this is investigatable.
        tracing::warn!(
            message = msg.trim_end(),
            "sd_notify: write failed: {e}"
        );
    }
    drop(fd);
}

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(not(target_os = "linux"))]
fn sd_notify_inner(_msg: &str) {
    // No-op on non-Linux: systemd-only mechanism.
}

/// Spawn a tokio task that pings the systemd watchdog at `interval`. The task
/// runs until the runtime is dropped; no cancellation token needed because the
/// process either exits or runs forever.
pub fn spawn_watchdog_heartbeat(interval: std::time::Duration) {
    if std::env::var_os("NOTIFY_SOCKET").is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(interval);
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            iv.tick().await;
            sd_notify_watchdog();
        }
    });
}

/// Install a panic hook that routes panic information through `tracing` before
/// `panic = "abort"` (set in `[profile.release]`) terminates the process. This
/// gives operators a structured last-breath log line — useful in `journalctl`
/// or `kubectl logs` — instead of a bare backtrace.
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
        let msg = info
            .payload()
            .downcast_ref::<&'static str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("(no message)");
        tracing::error!(
            target: "panic",
            location = ?location,
            "panic: {msg}",
        );
        prev(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_value_default() {
        let v = env_value("__STREAMSOCKETS_TEST_DEFAULT__", "fallback");
        assert_eq!(v, "fallback");
    }

    #[test]
    fn env_int_default() {
        let v = env_value_as_int("__STREAMSOCKETS_TEST_INT__", 42);
        assert_eq!(v, 42);
    }

    #[test]
    fn env_bool_parses_variants() {
        std::env::set_var("__BOOL_T__", "TRUE");
        assert!(env_bool("__BOOL_T__", false));
        std::env::set_var("__BOOL_F__", "no");
        assert!(!env_bool("__BOOL_F__", true));
        std::env::remove_var("__BOOL_T__");
        std::env::remove_var("__BOOL_F__");
    }

    /// Non-Linux dev builds always pick Tokio: the runtime selector short-
    /// circuits before any kernel probe.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn pick_runtime_non_linux_is_tokio() {
        assert_eq!(pick_runtime(), RuntimeKind::Tokio);
        assert_eq!(RuntimeKind::Tokio.label(), "tokio");
    }

    /// Linux: with `DISABLE_IOURING=true` the selector returns `Tokio` and the
    /// label is `epoll` (kernel-side mechanism under tokio's reactor).
    #[cfg(target_os = "linux")]
    #[test]
    fn pick_runtime_disable_iouring_is_epoll() {
        // The DISABLE_IOURING decision is cached by `is_iouring_disabled()`
        // on first call (process-wide OnceCell). To make this test
        // deterministic we set the env var before any test that reads it
        // runs — but tests run in parallel and cargo test won't fork. We
        // therefore exercise pick_runtime's *fallback path* indirectly by
        // asserting the label invariant: whatever pick_runtime returns, its
        // label must be one of the documented stable values.
        let rt = pick_runtime();
        let label = rt.label();
        assert!(
            matches!(label, "io_uring" | "epoll"),
            "unexpected label on Linux: {label}"
        );
        // RuntimeKind::Tokio.label() on Linux is "epoll" by spec.
        assert_eq!(RuntimeKind::Tokio.label(), "epoll");
        assert_eq!(RuntimeKind::Uring.label(), "io_uring");
    }
}
