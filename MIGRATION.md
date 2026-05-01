# StreamSockets 2.0.0 — Java → Rust Migration

> **Audience.** A future Claude Code session executing this migration end-to-end. Treat this document as the source of truth: scope, architecture, wire protocol, FSM, env vars, metrics, tests, rollout. The Java 1.7.0 sources in this repo (`server/`, `client/`, `authentication-server/`, `metrics/`, `common/`, `testsuite/`) are the behavioral spec. This document defines the deltas.

> **Non-negotiables.** (1) Rust + Tokio. (2) `tokio-uring` on Linux when io_uring is available, plain Tokio (epoll) otherwise. (3) Frame-by-frame: 1 UDP datagram = 1 WS binary frame, no batching beyond OS-level coalescing. (4) **No JSON anywhere on the wire — old v1 protocol (`X-Auth-Route` + JSON `TextWebSocketFrame` route negotiation) is removed entirely.** All auth/routing in v2 lives in HTTP headers on the WS handshake. (5) Same env vars (minus `USE_OLD_PROTOCOL`), same `accounts.yml`, same Prometheus metric names/labels as 1.7.0 (additive only). (6) Production-grade day-1: structured tracing, no `.unwrap()` on hot paths, panic = process exit, graceful shutdown. (7) Fix the reconnect/disconnect bugs catalogued below. (8) Version is **2.0.0**.

> **Breaking change.** v2 is a clean wire-protocol break. v1.7.0 clients **cannot** talk to v2 servers (they'll get HTTP `400` for missing `X-Route-Address`). v2 clients **cannot** talk to v1.7.0 servers (the v1 server doesn't recognize the new headers). Rollout strategy changes accordingly — see §14. The user-facing migration guide is at `docs/v2.md`.

---

## 1. Scope

### In scope
- Rewrite `server/` and `client/` modules as Rust 2021 crates targeting Linux x86_64 and aarch64.
- Rewrite `authentication-server/`, `metrics/`, `common/` as supporting Rust crates in the same Cargo workspace.
- Preserve every operator-facing surface that *survives* the v1 wire-protocol removal: `accounts.yml` schema, Prometheus metric names + labels (additive only), `X-Auth-Type` / `X-Auth-Token` / `X-Route-Address` / `X-Route-Port` / `CLIENT_IP_HEADER` semantics, default ports, Docker image entrypoints.
- Author `docs/v2.md` — the user-facing migration guide for operators upgrading from 1.7.0.

### Removed (breaking changes vs 1.7.0)
- **v1 wire protocol entirely**: legacy `X-Auth-Route` handshake header, JSON-payload `TextWebSocketFrame` route negotiation, the per-connection "old protocol" code path on the server, and the `USE_OLD_PROTOCOL` env var on the client. v2 servers reject v1 handshakes with `400`; v2 clients only speak v2.
- `jackson-databind` and any JSON dependency on the wire path. (Server still parses `accounts.yml` with `serde_yml`; that's unrelated.)

### Out of scope
- Schema changes to `accounts.yml`. Field names and shape stay identical.
- Replacing the WebSocket transport with anything else (QUIC, raw TLS, etc.).

### Deliverables
- New top-level `rust/` directory containing the Cargo workspace. The Java tree (`server/`, `client/`, etc.) stays in place during the dual-version rollout, then moves under `legacy-java/` after cutover. **(Post-cutover update: the `legacy-java/` tree was removed from the repo entirely; rollback to v1.7.0 is via the published `hyperxpro/streamsockets:server-1.7.0` / `:client-1.7.0` Docker images, or the `Release v1.7.0` git tag. The Cargo workspace was also flattened up to the repo root — `Cargo.toml`, `streamsockets-*/`, and friends now live at the root, not under `rust/`.)**
- Two new Docker images: `hyperxpro/streamsockets:server-2.0.0`, `hyperxpro/streamsockets:client-2.0.0`. Old `:server-1.7.0` / `:client-1.7.0` images stay published.
- `MIGRATION.md` (this file), updated `README.md`, updated GitHub Actions (`.github/workflows/`) for Rust build/test/publish.

---

## 2. Current vs Target Architecture

### 2.1 Java 1.7.0 (current)

```
┌──────────────────────────────────────────────────────────────────────┐
│  Server (Netty 4.2)                                                  │
│  ┌─────────────────┐    ┌────────────────────────┐    ┌────────────┐ │
│  │ HttpServerCodec │ →  │ AuthenticationHandler  │ →  │ WSProtocol │ │
│  └─────────────────┘    │ (X-Auth-Type/Token,    │    │  Handler   │ │
│                         │  X-Route-{Address,Port}│    └─────┬──────┘ │
│                         │  or X-Auth-Route        │          ↓        │
│                         │  ── REMOVED in v2)      │   WebSocketServer │
│                         └────────────────────────┘   Handler        │
│                                                       (per WS conn)  │
│                                                       │              │
│                                                       │ pendingFrames│
│                                                       │ (MpscQueue)  │
│                                                       ↓              │
│                                                  DownstreamHandler ─→│ → UDP upstream
└──────────────────────────────────────────────────────────────────────┘

Tokens validated in TokenAuthentication (YAML loaded, hot-reloaded every 15s).
EventLoopGroup chooses io_uring → epoll → NIO.
JSON path (TextWebSocketFrame route negotiation) existed for v1 clients — deleted in v2.
Metrics on a separate Netty pipeline at :9090.
```

```
┌──────────────────────────────────────────────────────────────────────┐
│  Client (Netty 4.2)                                                  │
│  UdpServer (SO_REUSEPORT × THREADS)                                  │
│       │                                                              │
│       ↓ DatagramHandler  (locks first src, queues frames)            │
│       │     │                                                        │
│       │     ↓ newWebSocketConnection()                               │
│       │       │                                                      │
│       │       ↓ WebSocketClient → WSClientHandler                    │
│       │              │   PING every 5s                               │
│       │              │   pong-check every 1s, 5 misses → close       │
│       │              │   RetryManager: 1, 2, 4, 8, 16, 30 (no jitter)│
│       └──────────────┴──── BinaryWSFrame ↔ DatagramPacket            │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.2 Rust 2.0.0 (target)

```
┌──────────────────────────────────────────────────────────────────────┐
│  streamsockets-server (Rust)                                         │
│                                                                      │
│  N runtimes, one per core, each pinned, each binding 0.0.0.0:8080    │
│  with SO_REUSEPORT. Kernel SYN-fanout distributes accept().          │
│                                                                      │
│  per-connection task graph:                                          │
│    accept TCP                                                        │
│      → optional PROXY-protocol-v2 parse                              │
│      → optional rustls termination (wss://)                          │
│      → hyper (HTTP/1.1) upgrade                                      │
│      → header validation + token auth + IP/CIDR check + lease        │
│      → WS handshake (101)                                            │
│      → fork two tasks joined by select!:                             │
│           • upstream_to_ws: UDP recv → encode binary frame → WS send │
│           • ws_to_upstream: WS recv → decode binary frame → UDP send │
│                                                                      │
│  Connected UDP egress socket, IP_BIND_ADDRESS_NO_PORT,               │
│  UDP_GRO on recv side, SO_RCVBUF/SO_SNDBUF realised + verified.      │
│                                                                      │
│  /metrics + /healthz + /livez + /readyz on metrics port (default     │
│  9090) via a separate hyper service.                                 │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  streamsockets-client (Rust)                                         │
│                                                                      │
│  N tokio runtimes (THREADS env), each pinned, each binding the UDP   │
│  listener with SO_REUSEPORT. Kernel hashes (saddr,sport) → worker.   │
│                                                                      │
│  Per-runtime tunnel state machine (single-source lock-on):           │
│    Disconnected ─(first UDP packet)→ Connecting ─→ Authenticating    │
│      ─→ Live ⟷ Reconnecting ─(>RETRY_BUDGET or terminal status)→     │
│      Terminated.                                                     │
│                                                                      │
│  Bounded byte-capped frame queue (drop-oldest) during Reconnecting.  │
│  Decorrelated-jitter exponential backoff. Single-deadline ping       │
│  timeout (no 1s polling). EXIT_ON_FAILURE makes Terminated → exit 1. │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Cargo workspace layout

Create at `/home/ubuntu/Programming/StreamSockets/rust/`.

```
rust/
├── Cargo.toml                          # workspace root
├── rust-toolchain.toml                 # channel = "1.84"
├── streamsockets-core/                 # shared types + env helpers + tracing init
│   ├── Cargo.toml
│   └── src/lib.rs
├── streamsockets-auth/                 # accounts.yml loader + reload + token auth
│   ├── Cargo.toml
│   └── src/lib.rs
├── streamsockets-metrics/              # prometheus registry + /metrics + /healthz HTTP
│   ├── Cargo.toml
│   └── src/lib.rs
├── streamsockets-server/               # binary: streamsockets-server
│   ├── Cargo.toml
│   └── src/{main.rs, accept.rs, handshake.rs, tunnel.rs, upstream.rs, runtime.rs}
├── streamsockets-client/               # binary: streamsockets-client
│   ├── Cargo.toml
│   └── src/{main.rs, listener.rs, fsm.rs, ws.rs, queue.rs, runtime.rs}
└── streamsockets-testsuite/            # integration tests, version-compat, chaos
    ├── Cargo.toml
    └── tests/...
```

### Pinned dependency versions (top of `Cargo.toml`, `[workspace.dependencies]`)

| Crate | Version | Why |
|---|---|---|
| `tokio` | `1.43` | mainline async runtime; `full` features in binaries, narrow features in libs |
| `tokio-uring` | `0.5` | Linux-only, gated `[target.'cfg(target_os = "linux")'.dependencies]` |
| `io-uring` | `0.7` | low-level SQE building for `UDP_SEGMENT` cmsg (re-exported by `tokio-uring`) |
| `hyper` | `1.5` | HTTP/1.1 server + client; stable Upgrade API |
| `hyper-util` | `0.1` | `TokioExecutor`, `TokioIo`, `auto::Builder` |
| `http-body-util` | `0.1` | empty/full body responses for the handshake |
| `fastwebsockets` | `0.10` | zero-alloc WS, in-place SIMD unmask, `Bytes` payload, hyper Upgrade integration; ships in Cloudflare's edge |
| `rustls` | `0.23` | TLS without OpenSSL; deterministic verification; `aws-lc-rs` provider for FIPS |
| `tokio-rustls` | `0.26` | rustls + tokio I/O |
| `rustls-platform-verifier` | `0.5` | client-side cert verification using OS root store |
| `rustls-pemfile` | `2.2` | PEM parsing |
| `hickory-resolver` | `0.24` | async DNS, real TTL respect, replaces glibc `getaddrinfo` |
| `prometheus` | `0.13` | identical metric model to Java's `io.prometheus.client` |
| `serde` | `1.0` | accounts.yml deserialization |
| `serde_yml` | `0.0.12` | **`serde_yaml` was archived in 2024**; `serde_yml` is the maintained fork |
| `ipnet` | `2.10` | CIDR membership, replaces `inet.ipaddr.IPAddressString` |
| `bytes` | `1.9` | `Bytes`/`BytesMut`, `Bytes::slice_ref` for zero-copy frame splitting |
| `tracing` | `0.1` | structured logs + spans |
| `tracing-subscriber` | `0.3` | `env-filter`, `json`, `fmt` |
| `socket2` | `0.5` | raw setsockopt for `SO_REUSEPORT`, `IP_BIND_ADDRESS_NO_PORT`, `TCP_DEFER_ACCEPT`, `UDP_GRO`, cmsg send |
| `core_affinity` | `0.8` | pin worker runtimes under `SO_REUSEPORT` |
| `tokio-util` | `0.7` | hierarchical `CancellationToken` for tunnel teardown |
| `flume` | `0.11` | runtime-agnostic MPMC channels; works across tokio + tokio-uring without `Send` issues |
| `arc-swap` | `1.7` | atomic `AccountsSnapshot` swap for hot reload |
| `proxy-protocol` | `0.5` | PROXY v1/v2 parsing (behind `PROXY_PROTOCOL` env) |
| `mimalloc` | `0.1` | `#[global_allocator]` in both binaries; 10–30% latency win vs glibc malloc on small-buffer workload |
| `nix` / `rustix` | `0.29` / `0.38` | sysconf, signals, `utsname` for kernel-version probe, `sd_notify` |
| `notify` | `7.0` | inotify-driven `accounts.yml` reload (timer fallback) |
| `thiserror` / `anyhow` | `2.0` / `1.0` | typed errors / binary `main()` wrapping |
| `rand` | `0.8` | decorrelated-jitter backoff |
| `criterion` | `0.5` | dev: hot-path benchmarks |

Rust edition `2021`, MSRV `1.81` (declared in each crate's `Cargo.toml`).

---

## 4. Runtime selection: io_uring vs epoll

Single decision point at startup. Pseudocode in `streamsockets-core::runtime`:

```rust
pub fn pick_runtime() -> RuntimeKind {
    if cfg!(not(target_os = "linux")) {
        info!(reason = "not_linux", "using tokio (epoll fallback)");
        return RuntimeKind::Tokio;
    }
    if env_bool("DISABLE_IOURING", false) {
        info!(reason = "DISABLE_IOURING=true", "using tokio (epoll)");
        return RuntimeKind::Tokio;
    }
    if !uring_kernel_supported() {     // io_uring_setup probe, see below
        info!(reason = "kernel_unsupported", "using tokio (epoll)");
        return RuntimeKind::Tokio;
    }
    info!("using tokio-uring (io_uring) for high-performance I/O");
    RuntimeKind::Uring
}
```

`uring_kernel_supported()` does a *non-fatal* `io_uring_setup(0, &mut params)` syscall; on `ENOSYS`/`EPERM`/`EINVAL` we fall back. This is the same behavior Netty's `IoUring.isAvailable()` exhibits. Fallback ladder: io_uring → epoll → (non-Linux) tokio default.

The `tokio-uring` crate is single-runtime-per-thread today (no work-stealing). On the server, that maps cleanly to our **per-core current-thread runtime + `SO_REUSEPORT`** model: each pinned core gets its own `tokio_uring::Runtime`. On epoll fallback, each pinned core gets a `tokio::runtime::Builder::new_current_thread().enable_all().build()`.

**hyper does not support tokio-uring** (requires `tokio::net::TcpStream`). Resolution: TCP/TLS/HTTP path uses the standard tokio reactor, UDP path uses tokio-uring. Both runtimes coexist in one process — `tokio_uring::start()` runs a current-thread tokio under the hood. Per-tunnel state pins to one worker, so the WS task and the UDP task share a thread; cross-task communication is `Rc<RefCell<...>>` or direct ownership (no `Send` required).

The single platform abstraction is the `UdpEgress` trait:

```rust
pub trait UdpEgress: 'static {
    async fn send(&mut self, frame: Bytes) -> io::Result<()>;
    async fn recv_segments(&mut self, pool: &BufPool) -> io::Result<RecvBatch>;
}
pub struct RecvBatch {
    pub buf: BufHandle,                            // returns to pool on drop
    pub segments: SmallVec<[(usize, usize); 16]>,  // (offset, len) per datagram
}
```

Concrete impls: `IoUringUdp` (Linux+iouring, with `IORING_REGISTER_BUFFERS` against a per-worker pool of 1024 × 64 KiB buffers — saves `get_user_pages` per recv, 5–10% throughput win at high PPS) and `TokioUdp` (everywhere else). `segments.len() == 1` when GRO is unavailable; multi-segment when the kernel coalesces. Caller iterates `segments` and emits one WS binary frame per segment — same code path on every platform; the kernel decides count.

Document the decision matrix in `README.md`:

| Platform | Default I/O backend | Override |
|---|---|---|
| Linux ≥ 5.6 with io_uring not blocked | `tokio-uring` | `DISABLE_IOURING=true` → tokio/epoll |
| Linux < 5.6, or io_uring blocked by seccomp | tokio/epoll | n/a |

Docker images default `DISABLE_IOURING=true` (matches Java images today — most cloud seccomp profiles still block io_uring syscalls).

---

## 5. Wire protocol v2 (headers-only)

### 5.1 Handshake request (client → server)

```http
GET /tunnel HTTP/1.1
Host: example.com:8080
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: <base64-16-bytes>
X-Auth-Type: Token
X-Auth-Token: <opaque-token>
X-Route-Address: upstream.example.com
X-Route-Port: 5050
X-StreamSockets-Version: 2          # optional in v2; server echoes if present
```

Optional:

| Header | Behavior |
|---|---|
| `X-Forwarded-For` (or whatever `CLIENT_IP_HEADER` env names) | Overrides peer IP for `allowedIps` CIDR check. |
| `Sec-WebSocket-Protocol: streamsockets.v2` | Optional subprotocol marker. Server echoes if present. v3 will require this. |

**Removed in v2:** `X-Auth-Route` (legacy v1 route format). A handshake carrying `X-Auth-Route` without `X-Route-Address` + `X-Route-Port` is treated as a malformed request and rejected with `400 Bad Request`. There is no v1 fallback path on the wire.

### 5.2 Handshake response (server → client)

| Outcome | Status | Headers |
|---|---|---|
| Handshake OK | `101 Switching Protocols` | `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Accept: <hash>` |
| Token unknown | `401 Unauthorized` | `WWW-Authenticate: Token` |
| IP not in `allowedIps` | `403 Forbidden` | body `IP not allowed` |
| Route not in `routes` | `403 Forbidden` | body `Route not allowed` |
| Account in use, `reuse: false` | `409 Conflict` | body `Account already in use` |
| Server at `MAX_CONCURRENT_CONNECTIONS` | `503 Service Unavailable` | `Retry-After: 5` |
| Required header missing / `X-Auth-Type` not `Token` | `400 Bad Request` | body `Bad request` |
| HTTP request without `Upgrade: websocket` | `426 Upgrade Required` | `Upgrade: websocket`, `Sec-WebSocket-Version: 13` |
| `X-StreamSockets-Version` mismatch (e.g. `99`) | `400 Bad Request` | response includes `X-StreamSockets-Version: 2`. **Reserve `426` for actual WS-version negotiation per RFC 6455 §4.4** — don't overload it for app-level version. |

> **Java 1.7.0 conflates IP-not-allowed and route-not-allowed both as 401** (`server/AuthenticationHandler.java:105`). v2 fixes this — splits them as 403, splits reuse-conflict as 409. v1 clients won't observe the new codes anyway, since v1 clients can't complete the v2 handshake (missing `X-Route-Address`/`X-Route-Port`).

### 5.3 Post-handshake frame protocol

- **Binary frames only** carry payload. Each binary frame == one UDP datagram, both directions. Max frame size = `MAX_FRAME_SIZE` env var (default 65536 — same as Java).
- **Ping/Pong**: WS-level. Client sends `Ping` every `PING_INTERVAL_MS` (default 5000). Server MUST echo Pong with the same payload (RFC 6455 §5.5.2/§5.5.3 — fastwebsockets does this by default).
- **Continuation frames**: handle per RFC 6455. Bound reassembly buffer at `MAX_FRAME_SIZE × 2 = 131072` to defeat slow-loris.
- **Text frames are forbidden in v2**: any `TextWebSocketFrame` after handshake closes the connection with **WS close 1003 (Unsupported Data)** and increments `streamsockets_protocol_violations_total{reason="text_frame"}`. Java's permissive log-and-ignore behavior (`server/WebSocketServerHandler.java:213`) is a latent bug being closed.
- **Any other frame opcode** (RSV bits set, unknown opcode): close 1002 (Protocol Error).

### 5.4 Upstream-failure signaling

Critical: DNS resolution and UDP `connect()` are **post-handshake**. Reasons (a) Java already does this (`server/WebSocketServerHandler.java:123`); (b) pre-handshake DNS would turn the public WS endpoint into a probe oracle for internal infrastructure; (c) a DNS-flap timeout would block the handshake response for several seconds.

| Upstream failure | Action |
|---|---|
| DNS resolve fail | WS Close `1011 Internal Error`, reason `dns: <upstream>: <error>` |
| UDP `connect()` fails (`ECONNREFUSED`, `EHOSTUNREACH`) | WS Close `1011`, reason `connect: <upstream>: <error>` |
| ICMP "destination unreachable" delivered post-connect | WS Close `1011` |

Client treats `1011` as transient and retries with backoff. Client treats `1003`, `1008`, `1002` as terminal (do not retry).

### 5.5 Server-initiated graceful close

On SIGTERM, server sends WS Close `1001 (Going Away)`, then keeps forwarding bytes until `SHUTDOWN_GRACE_SECONDS` elapses, then closes the TCP. Clients see `1001` ⇒ retry with backoff (will hit either the new server or `503` while LB drains).

---

## 6. Reconnect/disconnect FSM (the heart of v2)

Owned by `streamsockets-client::fsm`. Single-source lock-on per client process — see §6.4 for the policy change from Java.

```
                                      first UDP pkt
                                      received
                                          │
                          ┌───────────────▼────────────────┐
                          │  Connecting                     │
                          │  - DNS resolve (hickory)        │
                          │  - TCP/TLS dial                 │
                          │  - HTTP/WS upgrade              │
                          └───────┬───────────────┬─────────┘
                                  │101            │error / close
                                  ▼               │
                          ┌──────────────┐        │
                          │Authenticating│        │
                          │ (waits for   │        │
                          │  upgrade ack)│        │
                          └──────┬───────┘        │
                                 │success         │
                                 ▼                │
                ┌────────────────────────────┐    │
                │ Live                        │   │
                │ - bidirectional copy        │   │
                │ - PING every PING_INTERVAL  │   │
                │ - pong deadline reset       │   │
                │ - retry counter = 0         │   │
                └────┬──────────────────────┬─┘   │
                     │ws close /            │     │
                     │ping miss /           │idle │
                     │tcp error             │timeout (UDP_TIMEOUT)
                     ▼                      ▼     │
            ┌──────────────────┐   ┌──────────────┴──┐
            │ Reconnecting     │   │ Idle             │
            │ - close UDP egress│   │ - close WS clean │
            │ - apply backoff   │   │ - return to      │
            │ - drop-oldest     │   │   Idle (waiting  │
            │   queue datagrams │   │   for next UDP   │
            │ - increment epoch │   │   packet)        │
            └────┬─────────┬───┘   └──────────────────┘
                 │backoff  │RETRY_BUDGET                          ┌──────────────┐
                 │elapsed  │exhausted, or                         │ Terminated    │
                 │         │terminal status (401/403/409/1003/    │ - if EXIT_ON_ │
                 │         │1008/1002)                            │   FAILURE:    │
                 ▼         ▼                                       │   exit 1      │
              (Connecting)                                  ────→ │ - else: stay  │
                                                                   │   Idle, log   │
                                                                   └──────────────┘
```

### 6.1 Invariants per state

| State | Invariants |
|---|---|
| `Idle` | no WS, no UDP egress; UDP listener up; queue empty |
| `Connecting` | epoch incremented; CancellationToken minted; DNS/TCP/TLS in flight; queue accepting writes |
| `Authenticating` | TCP up, waiting for `101`; queue still accepting writes |
| `Live` | WS handle owned by FSM; UDP egress connected; ping deadline armed; retry counter = 0 |
| `Reconnecting` | epoch incremented; backoff timer running; queue accepts writes (drop-oldest at cap); WS closed |
| `Terminated` | terminal log line emitted; if `EXIT_ON_FAILURE`, process has called `std::process::exit(1)` |

### 6.2 How this kills every reconnect bug

| Java bug | Source | v2 fix |
|---|---|---|
| Stale `authenticationFuture` listener | `WebSocketClientHandler.java:228` reassigns the future after `DatagramHandler` already has a listener attached | No JSON re-route path. Reconnect always goes through the FSM, which mints a new `CancellationToken` per epoch. Old listeners hold a clone and short-circuit when cancelled. |
| `socketAddress` mutated mid-reconnect | `DatagramHandler.java:96-104` sets `socketAddress = packet.sender()` before WS comes up | `socketAddress` is per-`Live`-state field, owned. New tunnel = new state struct. Old struct drops on transition. Rust ownership makes the bug uncompilable. |
| `writeToUdpClient` NPE on null `socketAddress` | `DatagramHandler.java:151` | Method only callable from `Live` state, where `socketAddress: SocketAddr` (not `Option`). Type-system enforced. |
| `wsChannel.close()` without nulling | `DatagramHandler.java:223` | WS handle dropped at state transition. No "stale handle still in scope" possible. |
| Slow ping detection (~15s) | `WebSocketClientHandler.java:107-118`: 1s polling × 5 missed | Single deadline: `tokio::time::sleep_until(last_pong + PING_TIMEOUT_MS)`. **Reset** (don't recreate) the sleep on each pong via `Pin<&mut Sleep>::reset`. `PING_PERMITTED_MISSES` env (default 1) allows 1 missed pong before close. Worst-case detection = `PING_INTERVAL + PING_TIMEOUT × (PERMITTED_MISSES + 1)`. With defaults: `5 + 10 × 2 = 25s`. With aggressive setting (`INTERVAL=2000 TIMEOUT=4000 MISSES=0`) drops to `6s`. |
| No backoff jitter | `RetryManager.java:43` deterministic exponential | **Decorrelated jitter** (Marc Brooker / AWS): `next = min(cap, rand_between(base, prev × 3))`. Initial = `RETRY_INITIAL_DELAY_SECONDS` (default 1s), cap = `RETRY_MAX_DELAY_SECONDS` (default 30s). Reset on transition to `Live`. |
| Old-protocol "new UDP source" no-op | `DatagramHandler.java:103` calls `newUdpConnection()` reusing the same ROUTE | v2 has no old-protocol path at all. Single-source lock-on (§6.4) makes the multi-source path unreachable. |

### 6.3 Bounded queue

Defined in `streamsockets-client::queue`. Backed by a `VecDeque<Bytes>` plus a running byte total. Lock-free not required — the FSM is single-task per worker.

| Setting | Default | Behavior |
|---|---|---|
| `QUEUE_MAX_BYTES` | `1048576` (1 MiB) | Capped by total payload bytes, not frame count. UDP datagrams are small; bounding by bytes prevents pathological queue growth from a flood. |
| `QUEUE_DRAIN_TIMEOUT_MS` | `30000` (30 s) | If still in `Reconnecting` after this, **purge the queue**. Holding 30-second-old datagrams is useless for any realtime workload. |
| Backoff initial | `100 ms` | Java's 1 s default is too long for transient flaps; honor `RETRY_INITIAL_DELAY_SECONDS` env when ≥ 1 s, else clamp at 100 ms floor. |
| Drop policy | drop-**oldest** | UDP-tunnel semantics: a fresh snapshot strictly beats a stale one (Wireguard, QUIC unreliable streams use the same). |
| Flush trigger | transition to `Live` | All queued frames sent FIFO before resuming normal forwarding. |
| Metrics | `streamsockets_queue_depth_bytes`, `streamsockets_queue_dropped_total{reason}`, `streamsockets_queue_purged_total` | per-account labels |

### 6.4 Single-source lock-on (policy change)

Java spawns a fresh WS for every new UDP source (`DatagramHandler.java:96-98`). This was buggy (the cause of three of the seven reconnect bugs) and isn't covered by tests.

**v2 client** locks `(src_ip, src_port)` on the first UDP packet seen, for the lifetime of the process. Subsequent packets from a different source are silently dropped + counted (`streamsockets_client_foreign_sources_total`). Operators who need multi-source semantics run multiple client processes — exactly the systemd model the README already documents.

Justification: the typical deployment is one game-client → one StreamSockets-client (sidecar / systemd unit), so a fixed lock-on is what 99% of users need. The multi-source path was experimental and broken.

### 6.5 `EXIT_ON_FAILURE`

- `Terminated` state → if `EXIT_ON_FAILURE=true`, immediate `std::process::exit(1)`. systemd/k8s restart-on-failure picks it up.
- Terminal classifications:
  1. HTTP `401`, `403`, `409` from server (config-level — retrying just thrashes).
  2. WS close codes `1003` (unsupported data), `1008` (policy violation), `1002` (protocol error).
  3. Retry budget exhausted: 100 consecutive failed `Connecting` attempts. With cap 30s, that's ~50 min of failure → not transient.
- `Live` ⇒ `Reconnecting` (transient) does NOT exit; goes through backoff.
- `Idle` (UDP timeout) does NOT exit; we wait for new UDP traffic.

### 6.6 Cancellation safety

**Hierarchical `CancellationToken`** (`tokio_util::sync::CancellationToken`):
- Per-tunnel parent token, owned by the FSM.
- Per-attempt child token via `parent.child_token()`. Each Connecting/Authenticating/Live cycle gets its own child.
- On reconnect: cancel current child, mint fresh child for next epoch. Spawned tasks `select!` on `child.cancelled()` and bail. No manual epoch comparison — cancellation *is* the mechanism. Replaces Java's `connectionEpoch` int + `synchronized` blocks.

**Cancel-safety per `select!` arm** is non-trivial:
- `ws.read_frame()` (fastwebsockets), `udp.recv_from()` (tokio), `tokio::time::sleep_until` — all cancel-safe.
- `ws.write_frame()`, `udp.send_to()` — **NOT cancel-safe**. Wrap each in a dedicated branch where, if cancelled mid-write, the entire tunnel drops rather than the in-progress write being torn out. The frame is lost — correct UDP semantics, since UDP is unreliable by definition.

### 6.7 Server-side: graceful drain

| Signal | Behavior |
|---|---|
| First `SIGTERM` / `SIGINT` | Set `/healthz` → 503; stop accepting new TCP. For each tunnel: send WS Close 1001, keep forwarding bytes. Sleep `SHUTDOWN_GRACE_SECONDS` (default 30). |
| Second `SIGTERM` | Skip remaining grace, force-close all tunnels. (k8s sends a second when `terminationGracePeriodSeconds` runs out.) |
| Per-tunnel hard-close | WS Close 1012 ("Service Restart"), close UDP egress last to flush in-flight datagrams. |

---

## 7. Data flow (frame-by-frame)

### 7.1 Server data flow

Each incoming TCP connection becomes one tunnel. Steps:

1. **Accept** (current-thread runtime, per-core, SO_REUSEPORT). `socket2::Socket` to set `TCP_NODELAY`, `SO_KEEPALIVE`, `TCP_DEFER_ACCEPT=1`. `accept()` returns `(TcpStream, SocketAddr)`.
2. **PROXY-protocol-v2** (optional): if `PROXY_PROTOCOL=v2|optional|v1`, peek the first 12 bytes; on match, parse with `proxy-protocol`. Real client IP overrides `peer_addr` for `allowedIps` check.
3. **TLS** (optional): `wss://` deployments terminate TLS via `tokio_rustls::TlsAcceptor`. ALPN `http/1.1`. Client cert verification off (we authenticate with bearer tokens).
4. **HTTP upgrade**: `hyper::server::conn::http1::Builder::new().serve_connection(stream, service_fn(handle_handshake)).with_upgrades()`. The handler:
   - Validates headers per §5.1.
   - Looks up token in the `Arc<AccountsSnapshot>` (RCU-style hot-reload).
   - Checks IP against `allowedIps` (pre-parsed `ipnet::IpNet`).
   - Checks route against the account's allowlist.
   - Calls `lease_account()` (atomic add to `DashSet<Arc<Account>>`).
   - On success, returns `101` and stores `(account, route, client_ip)` for the upgrade callback.
5. **WS handshake done** ⇒ `hyper::upgrade::on(...)` fires. Body of upgrade callback:
   - Resolve DNS for `route` via `hickory-resolver`. Fail → WS Close 1011.
   - Bind UDP socket: `socket2::Socket::new(IPPROTO_UDP)`, `IP_BIND_ADDRESS_NO_PORT=1`, `bind(0.0.0.0:0)`, `connect(upstream)`. Set `SO_RCVBUF`/`SO_SNDBUF=4MiB`, verify with `getsockopt`, log warn if kernel capped. Set `UDP_GRO=1`.
   - Spawn two tasks joined by `tokio::select!`:
     - `upstream_to_ws`: `loop { recv = udp.recv(buf).await; ws.send_binary(buf[..n]).await; }`. With UDP_GRO, `recv` may return multiple datagrams concatenated; split by inferred segment length (cmsg `UDP_GRO`) into individual frames.
     - `ws_to_upstream`: `loop { match ws.recv().await { Frame::Binary(b) => udp.send(&b).await, Frame::Ping => ws.send(Pong).await, ... } }`.
   - Either task completing/erroring cancels the other (`CancellationToken`). Tunnel teardown releases the account lease.

### 7.2 Client data flow

1. **UDP listener** (per-runtime, SO_REUSEPORT × THREADS). Workers each `recv_from`. First non-spurious packet locks `(src_ip, src_port)` for the process. Foreign-source packets dropped + counted.
2. **FSM** transitions to `Connecting` on first packet.
3. **WS dial**: `hyper` client, custom `tokio::net::TcpStream`, optional `tokio-rustls` for `wss://`. Build the upgrade request with all v2 headers per §5.1. On `101`, `hyper::upgrade::on(...)` returns the `Upgraded` stream; wrap in `fastwebsockets::WebSocket`.
4. **Live**: same dual-task `select!` topology as server, except the UDP side is the listener (sender lock-on enforced).
5. **Ping task** uses `tokio::time::interval` for sends, and a single `Pin<Box<Sleep>>` deadline armed at `last_pong + PING_TIMEOUT`. On pong receive, `sleep.as_mut().reset(now + PING_TIMEOUT)`. Single deadline, no polling.

### 7.3 Zero-copy

- WS payload: `Bytes` (refcounted; slice operations don't allocate). `fastwebsockets` returns `Frame<'_>` borrowing into its internal buffer; on the data path we use `Bytes::slice_ref` (zero-copy share of the same allocation) where possible, and `Bytes::copy_from_slice` only when crossing an ownership boundary the kernel demands.
- On `tokio-uring`, owned-buffer API requires `Vec<u8>` ownership across the await boundary. We use a per-worker pool of 1024 × 64 KiB buffers, registered at startup with `IORING_REGISTER_BUFFERS`. Buffers return to the pool when the last `Bytes` slice drops, via a custom `bytes::Vtable`.
- mimalloc as `#[global_allocator]` in both binaries handles incidental allocations on the epoll path; the Linux+iouring path has zero hot-path allocations in steady state.

**Steady-state allocation budget on hot path:**

| Operation | Allocations |
|---|---|
| UDP recv (Linux+iouring, GRO active) | 0 (registered buf reused) |
| UDP recv (tokio epoll) | 1 `BytesMut` per recv (mimalloc) |
| WS frame parse (fastwebsockets) | 0 (in-place SIMD unmask, slice into recv buffer) |
| WS frame write | 0 (`Bytes` refcount only) |
| UDP send | 0 |
| Auth lookup | 0 (`Arc<ArcSwap<AccountsSnapshot>>` load + `HashMap::get`) |
| Metrics increment | 0 (atomic on label-bound counter) |

---

## 8. Authentication module

`streamsockets-auth` mirrors `authentication-server/` Java behavior 1:1.

### 8.1 `accounts.yml` schema (unchanged)

```yaml
accounts:
  - name: user1
    token: '123456'
    reuse: false
    routes:
      - '127.0.0.1:8888'
      - 'example.com:5050'
    allowedIps:
      - '127.0.0.1'
      - '192.168.1.0/24'
```

### 8.2 In-memory representation

```rust
pub struct AccountsSnapshot {
    by_token: HashMap<String, Arc<AccountCache>>,
}
pub struct AccountCache {
    pub account: Account,
    pub route_set: HashSet<String>,
    pub allowed_cidrs: Vec<ipnet::IpNet>,
}
```

Wrapped as `Arc<ArcSwap<AccountsSnapshot>>` (crate `arc-swap` 1.7) for lock-free RCU-style hot reload — same atomic-replace semantics as Java's `volatile AccountsSnapshot snapshot` (`TokenAuthentication.java:42`).

### 8.3 Reload

Two paths, whichever fires first wins:
- **inotify** (`notify` crate, default): wakes immediately on file write/move.
- **timer fallback**: `tokio::time::interval(ACCOUNTS_RELOAD_INTERVAL_SECONDS)` covers FS-events-disabled environments (some container runtimes mask inotify).

Reload reads YAML, parses with `serde_yml`, validates uniqueness of tokens, builds a new snapshot, calls `arc_swap.store(Arc::new(new_snapshot))`. On parse error, log warn and keep the old snapshot.

`ACCOUNTS_RELOAD_INTERVAL_SECONDS=0` disables both reload paths.

### 8.4 Lease tracking

- `active: DashMap<Arc<Account>, AtomicUsize>` — count of active sessions per account.
- `lease()` increments; for `reuse=false`, `compare_exchange(0, 1)`, fail returns `Err(LeaseError::Conflict)` ⇒ HTTP 409.
- `release()` decrements.
- `Drop` impl on the per-tunnel `LeaseGuard` ensures release on every exit path (panic, cancellation, error). This is the Rust win over Java's `closeFuture` listener (`server/AuthenticationHandler.java:123`) — no leak surface.

---

## 9. Metrics (`streamsockets-metrics`)

### 9.1 Preserved metric names + labels (must match Java exactly)

```
streamsockets_active_connections{account_name}        (Gauge)
streamsockets_connection_status{account_name}         (Gauge, 1/0)
streamsockets_total_connections{account_name}         (Counter)
streamsockets_bytes_received_total{account_name}      (Counter)
streamsockets_bytes_sent_total{account_name}          (Counter)
streamsockets_connection_duration_seconds{account_name}  (Histogram, buckets: 1, 5, 10, 30, 60, 300, 600, 1800, 3600)
```

### 9.2 New metrics for v2

```
streamsockets_handshake_failures_total{reason}          # auth, ip_denied, route_denied, reuse_conflict, capacity, bad_request
streamsockets_handshake_version{version}                # v1, v2
streamsockets_handshake_timeouts_total
streamsockets_tls_handshake_failures_total{reason}
streamsockets_reconnect_attempts_total{account_name}
streamsockets_reconnect_state{account_name}             # 0=Live, 1=Reconnecting, 2=Terminated
streamsockets_ping_timeouts_total{account_name}
streamsockets_ping_rtt_seconds{account_name}            # Histogram, buckets ms-resolution
streamsockets_ws_close_total{side, code}                # side: client|server, code: 1000..1015
streamsockets_protocol_violations_total{reason}
streamsockets_upstream_dns_failures_total
streamsockets_upstream_connect_failures_total
streamsockets_upstream_unreachable_total
streamsockets_upstream_send_drops_total                 # EAGAIN/ENOBUFS, rate-limited log
streamsockets_queue_depth_bytes{account_name}           # Gauge
streamsockets_queue_dropped_total{account_name, reason}
streamsockets_queue_purged_total{account_name}
streamsockets_client_foreign_sources_total
streamsockets_active_tunnels                            # server-wide Gauge
streamsockets_udp_egress_socket_buffer_bytes{direction} # Gauge, getsockopt-realized
streamsockets_runtime_kind{kind}                        # Gauge, set once at startup: io_uring|epoll|tokio
streamsockets_client_state{state}                       # Gauge: disconnected|connecting|live|reconnecting|terminal
```

All in `streamsockets_*` namespace. Per-account labels only where Java uses them today (no cardinality explosion).

### 9.3 HTTP service

`streamsockets-metrics` exposes a `hyper::service::service_fn` handling four routes on the metrics port (default `9090`):

| Path | Behavior |
|---|---|
| `/metrics` (configurable via `METRICS_PATH` env) | `200`, `text/plain; version=0.0.4`, body = `prometheus::TextEncoder` |
| `/healthz` | `200 OK` body `OK` while accepting; `503 Service Unavailable` body `draining` after SIGTERM |
| `/livez` | `200 OK` while process is up |
| `/readyz` | `200 OK` once accept loop is running |

---

## 10. Env var compatibility (full table)

### 10.1 Server (preserved, behavior unchanged unless noted)

| Env var | Default | Preserved | Notes |
|---|---|---|---|
| `ACCOUNTS_CONFIG_FILE` | `accounts.yaml` | yes | path |
| `CLIENT_IP_HEADER` | unset | yes | overrides peer IP |
| `PARENT_THREADS` | `n_cores` | yes | now controls accept loops |
| `CHILD_THREADS` | `n_cores` | yes | now equals worker runtimes (same value) |
| `BIND_ADDRESS` | `0.0.0.0` | yes | |
| `BIND_PORT` | `8080` | yes | |
| `HTTP_MAX_CONTENT_LENGTH` | `65536` | yes | |
| `WS_PATH` | `/tunnel` | yes | |
| `MAX_FRAME_SIZE` | `65536` | yes | |
| `METRICS_ENABLED` | `true` | yes | |
| `METRICS_BIND_ADDRESS` | `0.0.0.0` | yes | |
| `METRICS_PORT` | `9090` | yes | also serves `/healthz` |
| `METRICS_PATH` | `/metrics` | yes | |
| `ACCOUNTS_RELOAD_INTERVAL_SECONDS` | `15` | yes | `0` disables |
| `DISABLE_IOURING` | `false` (Docker: `true`) | yes | |
| **NEW** `PROXY_PROTOCOL` | `disabled` | new | `v1` \| `v2` \| `optional` \| `disabled` |
| **NEW** `MAX_CONCURRENT_CONNECTIONS` | `100000` | new | `0` = unlimited |
| **NEW** `SHUTDOWN_GRACE_SECONDS` | `30` | new | |
| **NEW** `LOG_FORMAT` | `json` (Docker) / `pretty` (TTY) | new | |
| **NEW** `LOG_LEVEL` | `info` | new | tracing env-filter |
| **NEW** `TLS_CERT_FILE`, `TLS_KEY_FILE` | unset | new | enables `wss://` natively (Java relied on terminating proxy) |
| **NEW** `TLS_REQUIRE_CLIENT_CERT` | `false` | new | enables mTLS (server-side trust of client cert) |
| **NEW** `TOKIO_CONSOLE_BIND` | unset | new | enables `console-subscriber` for prod debugging; localhost-only by default |

### 10.2 Client (preserved)

| Env var | Default | Preserved | Notes |
|---|---|---|---|
| `THREADS` | `n_cores * 2` (Linux) / `1` | yes | |
| `BIND_ADDRESS` | `0.0.0.0` | yes | UDP listener |
| `BIND_PORT` | `9000` | yes | |
| `WEBSOCKET_URI` | `ws://localhost:8080/tunnel` | yes | |
| `AUTH_TOKEN` | `` | yes | |
| `ROUTE` | `127.0.0.1:8888` | yes | `host:port` |
| `PING_INTERVAL_MILLIS` | `5000` | yes | |
| `PING_TIMEOUT_MILLIS` | `10000` | yes | |
| `RETRY_INITIAL_DELAY_SECONDS` | `1` | yes | |
| `RETRY_MAX_DELAY_SECONDS` | `30` | yes | |
| `UDP_TIMEOUT` | `300` (s) | yes | |
| `EXIT_ON_FAILURE` | `false` | yes | |
| ~~`USE_OLD_PROTOCOL`~~ | n/a | **REMOVED** | v1 wire protocol no longer exists; setting this on a v2 client is ignored with a warn log |
| `DISABLE_IOURING` | `false` (Docker: `true`) | yes | |
| **NEW** `PING_PERMITTED_MISSES` | `1` | new | extra missed pongs allowed before close — fixes the 15s detection bug |
| **NEW** `RETRY_BUDGET` | `100` | new | consecutive failures before terminal |
| **NEW** `QUEUE_MAX_BYTES` | `1048576` | new | reconnect queue cap |
| **NEW** `QUEUE_DRAIN_TIMEOUT_MS` | `30000` | new | queue purge after sustained reconnect |
| **NEW** `LOG_FORMAT`, `LOG_LEVEL` | as server | new | |

> Defaults match Java behavior except where the new knob's default = "off" / "current behavior preserved".

---

## 11. Test plan

### 11.1 Crate-level unit tests (`#[tokio::test]`)

| Java test | Rust equivalent |
|---|---|
| `RetryManagerTest` | `streamsockets-client::fsm::backoff::tests` — verify decorrelated jitter distribution (10 K samples in expected range), reset on success |
| `ExitOnFailureTest` | `streamsockets-client::fsm::tests::exit_on_failure_terminal` — terminal status triggers `std::process::exit(1)` (use `assert_cmd` from a parent test process) |
| `MetricsRegistryTest` | `streamsockets-metrics::tests` — render text, all metrics present, label cardinality |
| `AuthenticationHandlerTest` | `streamsockets-auth::tests` — token unknown → None, IP denied → None, route denied → None, reuse-conflict → Err, hot reload swap |
| `TokenAuthenticationTest`, `TokenAuthenticationReloadTest` | `streamsockets-auth::reload::tests` — write file, sleep, verify swap, malformed reload preserves old snapshot |

### 11.2 Workspace integration tests (`streamsockets-testsuite/tests/`)

| Java testsuite | Rust equivalent |
|---|---|
| `EndToEndTest` | `e2e_basic.rs` — spawn server + client + UDP echo server in-proc, send 100 datagrams, assert echo |
| `MultipleConnectionsTest` | `e2e_concurrency.rs` — N concurrent client procs, assert all isolated |
| `DomainResolutionTest` | `e2e_dns.rs` — route is `localhost:port`, assert resolved |
| `ProtocolCompatibilityTest` | `e2e_v1_rejection.rs` — v2 server + Java 1.7.0 v1 client (`USE_OLD_PROTOCOL=true`, run via `mvn`); assert handshake fails with HTTP `400` and `streamsockets_handshake_failures_total{reason="bad_request"}` increments. Also: v2 server + raw HTTP request with only `X-Auth-Route` (no `X-Route-Address`) → `400`. |
| `ReconnectionTest` (9 scenarios) | `e2e_reconnect.rs` — port every scenario: server restart, multiple restarts, server-not-available, epoch prevents stale listeners, isConnecting reset on failure, queued frames after reconnect, ping-pong maintains connection, exponential backoff, retry-counter resets. Replace Netty channel introspection with our `streamsockets_reconnect_attempts_total` metric values. |

### 11.3 Chaos / load tests (new)

- **Reconnect storm**: 10 K clients connected; SIGKILL the server; measure (a) all clients reconnect within 5 × `RETRY_MAX_DELAY_SECONDS`, (b) backoff distribution is jittered (no synchronized retry waves visible in `streamsockets_reconnect_attempts_total` over time).
- **Queue overflow**: pause server pong responses; client builds queue under sustained UDP load; verify drop-oldest and `QUEUE_DRAIN_TIMEOUT_MS` purge.
- **Slow upstream**: upstream UDP echo with artificial 200 ms delay; verify p99 added latency through proxy.
- **High-PPS single tunnel**: 100 K pps × 1024 B; verify GRO path engages on Linux ≥ 5.0.
- **Soak**: 1000 tunnels × 10 pps × 24 h; assert no FD leak, no memory growth, no metric drift.

### 11.4 CI matrix

GitHub Actions:
- Linux x86_64 (Ubuntu 22.04, kernel 6.x): full suite including io_uring path.
- Linux aarch64 (cross via `cross-rs`): build + unit only.
- `cargo deny check` (advisories, licenses, bans) on every PR.
- `cargo audit` weekly cron.
- `cargo fmt --check`, `cargo clippy -- -D warnings -W clippy::pedantic` (selectively allow noisy lints).
- Rust toolchains: `1.84` (current MSRV) and `stable`. MSRV bumps require RFC.

---

## 12. Build, packaging, deployment

### 12.1 Multi-stage Dockerfiles

`docker/Dockerfile-Server-Rust`:

```dockerfile
# Stage 1: build
FROM rust:1.84-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY rust/Cargo.toml rust/Cargo.lock ./
COPY rust/crates ./crates
RUN cargo build --release --locked --bin streamsockets-server

# Stage 2: runtime — distroless, nonroot UID, has /etc/resolv.conf + CA bundle
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/streamsockets-server /usr/local/bin/streamsockets-server
COPY accounts.yml /etc/streamsockets/accounts.yml

# Match Java image defaults
ENV ACCOUNTS_CONFIG_FILE=/etc/streamsockets/accounts.yml \
    DISABLE_IOURING=true \
    LOG_FORMAT=json
EXPOSE 8080/tcp 9090/tcp
USER nonroot
ENTRYPOINT ["/usr/local/bin/streamsockets-server"]
```

Same shape for `Dockerfile-Client-Rust` (different binary, exposes `8888/udp`).

**Image-size and link decisions:**
- **glibc, not MUSL**. MUSL's allocator pathologically degrades above ~1k concurrent allocations per thread; on glibc with `mimalloc` we see a 10–30% latency win on the small-buffer workload (HAProxy's published jemalloc shape).
- **`gcr.io/distroless/cc-debian12:nonroot`** (~25 MiB) — has `/etc/resolv.conf`, `/etc/ssl/certs`. Don't use `scratch` (we need DNS + CA bundle). Don't use Alpine (MUSL).
- Final image target: **~30–35 MiB** (binary 12–15 MiB stripped + base ~22 MiB).
- `RUSTFLAGS="-C target-cpu=x86-64-v3"` for production x86_64 builds (AVX2 baseline).
- Build with `--locked` — never let CI silently bump a dep.

### 12.2 systemd unit (Rust)

Both binaries call `sd_notify(READY=1)` after first successful bind / first `Live` transition, and `sd_notify(WATCHDOG=1)` from a 10-second heartbeat task. Unit uses `Type=notify` so systemd waits for readiness rather than treating any process start as success.

```ini
[Unit]
Description=StreamSockets Client (Rust 2.0.0)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=streamsockets
Group=streamsockets
WorkingDirectory=/opt/streamsockets
ExecStart=/opt/streamsockets/streamsockets-client
Restart=always
RestartSec=2
StartLimitBurst=10
StartLimitIntervalSec=60
WatchdogSec=30

LimitNOFILE=1048576
LimitNPROC=65536
TasksMax=infinity

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native

# Allow io_uring syscalls — distros default seccomp blocks them.
# Drop these three syscall names if running with DISABLE_IOURING=true.
SystemCallFilter=@system-service @io-event io_uring_setup io_uring_enter io_uring_register

# EnvironmentFile=/etc/streamsockets/client.env
Environment="WEBSOCKET_URI=ws://your-server:8080/tunnel"
Environment="AUTH_TOKEN=your-secret-token"
Environment="ROUTE=example.com:8888"
Environment="EXIT_ON_FAILURE=true"

[Install]
WantedBy=multi-user.target
```

### 12.3 Recommended sysctls (host-level)

```
# /etc/sysctl.d/99-streamsockets.conf
net.core.rmem_max            = 33554432
net.core.wmem_max            = 33554432
net.core.rmem_default        = 4194304
net.core.wmem_default        = 4194304
net.core.netdev_max_backlog  = 10000
net.core.somaxconn           = 8192
net.ipv4.udp_mem             = 12148128 16197504 24296256
net.netfilter.nf_conntrack_udp_timeout         = 60
net.netfilter.nf_conntrack_udp_timeout_stream  = 600
net.netfilter.nf_conntrack_max                 = 1048576
net.ipv4.ip_local_port_range = 1024 65535
fs.nr_open                   = 1048576
```

The `nf_conntrack_udp_timeout_stream=600` change matters: stock 180 s reaps idle UDP-tunnel conntrack entries while the WS leg is still alive. Document this prominently.

### 12.4 LB configuration (operators' guide)

| LB | Setting | Value |
|---|---|---|
| AWS NLB | idle timeout | `350s` (max) |
| AWS ALB | idle timeout | `4000s` |
| GCP TCP LB | timeout | `86400s` |
| HAProxy | `timeout tunnel` | `1h` |
| HAProxy | `timeout client/server` | `30s` |
| Nginx | `proxy_read_timeout` | `3600s` |
| Nginx | `proxy_buffering` | `off` (for `/tunnel`) |
| Envoy | cluster `idle_timeout` | `3600s` |
| Envoy | `upgrade_configs` | `websocket` |
| All | `PING_INTERVAL_MILLIS` | < (LB idle / 2) |

L4 LB is sufficient (the WS is one long-lived TCP). Health check: HTTP `GET /healthz` on the metrics port. Optional ProxyProtocol v2 for real-client-IP preservation under L4 LB.

---

## 13. Observability

### 13.1 Tracing init

`tracing_subscriber::registry().with(EnvFilter::try_from_env("LOG_LEVEL").or_else(|_| EnvFilter::new("info"))).with(fmt_layer).init()`.

`fmt_layer` is `.json()` when `LOG_FORMAT=json`, `.pretty()` when `pretty`, default `compact` when stdout is a TTY.

### 13.2 Standard log fields

Every log line includes (via `tracing` span fields):

```
account=<name>
client_ip=<ip>
ws_remote=<ip:port>
route=<host:port>
tunnel_id=<uuid>      # NEW: per-tunnel UUID, lets ops grep across logs
state=<fsm-state>     # client only
epoch=<n>             # client only
```

This matches the prefix Java emits today (`server/WebSocketServerHandler.java:103`) plus the `tunnel_id` addition for log correlation.

### 13.3 Failure-mode catalog

(Operator-facing reference; mirrors §6 of lb-engineer brief.)

| # | Failure | Where | Status / WS | Metric | Log | Recovery |
|---|---|---|---|---|---|---|
| 1 | Auth fail (token) | server, pre-101 | 401 | `streamsockets_handshake_failures_total{reason="auth"}` | warn | client: terminal |
| 2 | Auth fail (IP) | server, pre-101 | 403 | `..{reason="ip_denied"}` | warn | client: terminal |
| 3 | Route not allowed | server, pre-101 | 403 | `..{reason="route_denied"}` | warn | client: terminal |
| 4 | Reuse conflict | server, pre-101 | 409 | `..{reason="reuse_conflict"}` | warn | client: terminal |
| 5 | Capacity | server, pre-101 | 503 + Retry-After | `..{reason="capacity"}` | warn | client: backoff retry |
| 6 | Bad request | server, pre-101 | 400 | `..{reason="bad_request"}` | info | client: terminal |
| 7 | DNS fail | server, post-101 | WS 1011 | `streamsockets_upstream_dns_failures_total` | error | client: backoff retry |
| 8 | UDP connect fail | server, post-101 | WS 1011 | `streamsockets_upstream_connect_failures_total` | error | client: backoff retry |
| 9 | UDP send EAGAIN | server, runtime | drop | `streamsockets_upstream_send_drops_total` | warn (ratelimit) | none |
| 10 | ICMP unreachable | server, runtime | WS 1011 | `streamsockets_upstream_unreachable_total` | error | client: backoff retry |
| 11 | WS close from server | client | log code | `streamsockets_ws_close_total{side="server",code}` | info | route by code |
| 12 | WS close from client | server | log code | `streamsockets_ws_close_total{side="client",code}` | info | clean teardown |
| 13 | UDP idle timeout | client | WS 1000 | `streamsockets_udp_idle_closes_total` | info | wait for next pkt |
| 14 | Ping timeout | both | WS 1006 | `streamsockets_ping_timeouts_total` | warn | client: backoff retry |
| 15 | Queue overflow | client | drop pkt | `streamsockets_queue_dropped_total{reason}` | warn (ratelimit) | none |
| 16 | OOM | both | exit 137 | n/a | fatal | orchestrator restart |
| 17 | Text frame on v2 | server | WS 1003 | `streamsockets_protocol_violations_total{reason="text_frame"}` | warn | client: terminal |
| 18 | TLS handshake fail | server, pre-101 | TCP close | `streamsockets_tls_handshake_failures_total{reason}` | warn | n/a |
| 19 | Handshake timeout | server, pre-101 | TCP close | `streamsockets_handshake_timeouts_total` | warn | n/a |

---

## 14. Phased rollout

> **No on-the-wire mixed mode.** v1 and v2 do not interoperate. A v2 server returns `400` to a v1 client; a v2 client cannot complete a handshake against a v1 server. Rollout is therefore **endpoint-pair-based**, not protocol-bridge-based: the v2 fleet runs alongside the v1 fleet on **separate endpoints**, and clients are migrated by repointing them at the v2 endpoint.

### 14.1 What stays compatible across the cut

- **`accounts.yml`**: schema unchanged. The same file feeds a v1 and a v2 server.
- **Prometheus metrics**: every preserved metric name/label is byte-identical to v1; new v2 metrics are additive. Existing Grafana dashboards keep working without edits.
- **Operator-facing env vars**: every v1 env var preserved on its respective binary (with one removal — `USE_OLD_PROTOCOL`) and several additions (§10).
- **Default ports**: v2 binaries listen on the same defaults (8080/9090 for server, 9000 for client UDP).

### 14.2 Recommended canary path (run two endpoints, migrate clients)

| Step | Action |
|---|---|
| T-2 w | v2 image built, full test matrix green, 24 h internal soak. |
| T-1 w | Deploy v2 server on a **new endpoint** — different port (`:8081`) and/or different hostname (`tunnel-v2.example.com`). v1.7.0 stays on `:8080` / `tunnel.example.com`. **Same `accounts.yml` mounted on both.** Both pointed at the same upstream. |
| T 0 | Migrate canary clients (5 %) by changing their `WEBSOCKET_URI` to the v2 endpoint **and** upgrading to the v2 client binary in the same change (one client deploy, atomic). Watch `streamsockets_handshake_failures_total`, `streamsockets_reconnect_attempts_total`, p99 latency. |
| T+1 d | Ramp to 25 % if clean. |
| T+3 d | 50 %. Compare metric deltas against the v1 baseline. |
| T+7 d | 100 %. v1 server stays running, idle, draining any stragglers. |
| T+14 d | Decommission v1 server and v1 client image. Move the Java tree to `legacy-java/`. Update README + delete v1-specific docs. |

Single-endpoint rollouts (LB-side routing on `X-StreamSockets-Version`, etc.) are **not viable** — v1 and v2 don't share a wire format, so any LB rule that routes the same TCP connection to either backend is just a 50/50 failure mode.

### 14.3 Required client-side coordination

Because v2 client ↔ v1 server fails handshake, **you must upgrade the client and switch its `WEBSOCKET_URI` in the same deploy**. For systemd-managed clients, that's a single `systemctl restart` after dropping in the new binary + updated env file. For Docker, it's a single `docker-compose up -d` with both the new image tag and the new URI in the same edit. The detailed user-facing procedure (Docker, docker-compose, systemd, Kubernetes) lives in `docs/v2.md`.

### 14.4 Rollback

- **v2 server regression detected post-cutover**: stop routing clients at the v2 endpoint, point them back at v1 (`WEBSOCKET_URI` revert, `systemctl revert` on systemd units, image-tag revert in Compose / Helm). Migrated clients must also revert to the v1 client image — they cannot speak to v1 server. v2 server stays running for forensics; orchestrator drains it.
- **v2 client misbehaves on one host**: revert that host's container/unit to `client-1.7.0` and revert its `WEBSOCKET_URI` to the v1 endpoint.
- **No data migration ever needed**: every config artifact is unchanged across versions; rollback is purely binary + URI flip.

---

## 15. Risks and open questions

### 15.1 Risks

| Risk | Mitigation |
|---|---|
| `tokio-uring`'s owned-buffer model imposes per-frame `Vec<u8>` ownership transfer; could allocate-thrash under high PPS | Per-worker `IORING_REGISTER_BUFFERS` pool (§7.3). Benchmark `tokio-uring` vs `tokio` epoll on the target kernel — if uring shows no win at 100 K pps, default to epoll in production despite kernel support. |
| Hyper 1.x WS upgrade + fastwebsockets integration is less battle-tested than Netty's | Build a minimal harness in `streamsockets-testsuite` that runs 1 M handshakes against the same backend as a test gate; detect regressions early. |
| `nf_conntrack_udp_timeout_stream` default (180 s) silently kills idle long-lived tunnels behind NAT | Documented sysctl in §12.3. On Linux, the v2 server can `setsockopt(IP_RECVERR)` and react to ICMP errors; that catches the conntrack-flush case as `streamsockets_upstream_unreachable_total`. |
| Single-source lock-on (§6.4) is a behavior change from Java | Document. Operators relying on the multi-source path (which was buggy) get explicit drop metrics + warn logs; can run multiple client processes. |
| 401 → {403, 409} status-code split | Clients that match specifically on 401 may break. Only relevant to third-party / custom v2 clients (the Java v1 client cannot complete a v2 handshake at all). Document loudly in changelog and `docs/v2.md`. |
| `mimalloc` fragmentation under long uptime | 24h soak under `dhat` and `valgrind massif`. Build-time feature flag falls back to system allocator if the soak shows growth. |
| MUSL deferred — image size will be larger | Acceptable for v2.0.0; revisit after p99 latency benchmarks confirm glibc parity. |
| `arc-swap` is not a stdlib primitive | Battle-tested (used in `tracing` ecosystem); add `cargo deny` advisory check; trivial to replace with `RwLock<Arc<...>>` if it ever becomes a problem. |
| `serde_yaml` archived in 2024 | Use `serde_yml` (maintained fork) — already pinned in §3. |

### 15.2 Open questions (resolve before T-1w)

1. **Does upstream support `wss://` natively?** Java relied on a terminating proxy. v2 includes native `rustls`. Ops decision: turn it on or keep relying on proxy?
2. **PROXY-protocol-v2 default**: ship as `disabled` (current) or `optional` (accept both)? `optional` is safer for misconfigured LBs but opens an IP-spoofing window if the LB doesn't strip the header. Recommend `disabled` default.
3. **MAX_CONCURRENT_CONNECTIONS default**: 100 K is generous; some operators may want a lower cap. Make it loud in the README.
4. **TLS cert hot-reload**: Java doesn't have it (relied on proxy). Skip for v2.0.0; add in v2.1 if asked.
5. **IPv6**: Java works (Netty handles it). Confirm the Rust workspace works the same — `BIND_ADDRESS=::` should bind dual-stack. Test explicitly.
6. **v1-protocol removal communication**: how long do we keep `legacy-java/` around as a buildable rollback artifact? Recommend keep through v2.2 (~6 months); call it out in `docs/v2.md`.

---

## 16. Execution checklist (for the future Claude Code session)

Tasks in execution order. Each task is small enough to commit atomically.

- [ ] **0**: Create branch `rust-2.0.0`. Add `rust/` directory at repo root.
- [ ] **1**: Scaffold Cargo workspace with the six crates from §3. Pin all dep versions per §3 table. Verify `cargo build` produces both binaries empty.
- [ ] **2**: Implement `streamsockets-core` (env helpers matching Java's `Utils.envValue` / `envValueAsInt`, tracing init, runtime kind detection per §4).
- [ ] **3**: Implement `streamsockets-auth` (YAML loader, `AccountsSnapshot`, lease tracker, hot reload). Port unit tests from `authentication-server/src/test`.
- [ ] **4**: Implement `streamsockets-metrics` (registry with all preserved + new metrics per §9, hyper service for `/metrics`/`/healthz`/`/livez`/`/readyz`).
- [ ] **5**: Implement `streamsockets-server` accept + handshake + auth flow (no UDP yet). Prove handshake compatibility with the existing Java client on `localhost`.
- [ ] **6**: Implement server upstream UDP + bidirectional copy (§7.1). End-to-end echo test with the Java client.
- [ ] **7**: Implement `streamsockets-client` UDP listener + FSM skeleton (§6) + WS dial. Single-source lock-on. Prove echo against the Java server.
- [ ] **8**: Implement client reconnect FSM with bounded queue + decorrelated jitter + permitted-misses ping (§6). Run all 9 reconnection scenarios from `testsuite/.../ReconnectionTest.java` ported as Rust integration tests.
- [ ] **9**: Implement v1-handshake rejection: any request with `X-Auth-Route` and no `X-Route-Address` returns `400`. Add the `e2e_v1_rejection.rs` integration test (§11).
- [ ] **10**: Implement TLS termination (`rustls`), PROXY-protocol-v2 parser, graceful shutdown.
- [ ] **11**: Wire all new metrics. Verify against Prometheus' textfile output that all preserved metric names are character-for-character identical to Java's output.
- [ ] **12**: Author Dockerfiles + GitHub Actions Rust workflows (build, test, publish images on tag).
- [ ] **13**: Run chaos / load tests (§11.3). Tune defaults if required.
- [ ] **14**: Update `README.md` with Rust-image quick start. Move Java sources to `legacy-java/` (still buildable).
- [ ] **15**: Tag `v2.0.0`, publish images, begin canary rollout per §14.2.

---

*End of MIGRATION.md. Maintained alongside the Rust workspace; bump on schema-affecting changes only.*
