# StreamSockets
StreamSockets is a UDP over WebSockets tunnel. It allows you to send and receive UDP packets over a WebSocket connection. 
This is useful for situations where you need to send UDP packets over a network that only supports WebSockets.

> **2.0.0 — Rust rewrite.** This repository is a Cargo workspace; member crates live at the repo root. v2.0.0 ships as `hyperxpro/streamsockets:server-2.0.0` / `:client-2.0.0`. v2 is a **breaking wire-protocol change** vs 1.7.0 — see [`MIGRATION.md`](MIGRATION.md) §14 for the operator upgrade guide, §10/§13 for env-var and metrics references, and the rest of that file for the engineering rationale. The Java 1.7.0 sources have been removed from the repo; the v1.7.0 Docker images (`hyperxpro/streamsockets:server-1.7.0` / `:client-1.7.0`) stay published indefinitely on Docker Hub as the rollback target. Source-level rollback to 1.7.0 is via the `Release v1.7.0` git tag.

**Repo layout**:

| Path | What |
|---|---|
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml` | Cargo workspace root |
| `streamsockets-{core,auth,metrics,server,client,testsuite}/` | workspace member crates |
| `docker/` | v2.0.0 Dockerfiles |
| (none) | The operator migration guide is consolidated into `MIGRATION.md` (§10 env vars, §13 metrics, §14 rollout). |
| `MIGRATION.md` | Engineering rationale + spec for the Rust rewrite |

### Quick start (v2 / Rust)

```yaml
services:
  streamsockets-server:
    image: hyperxpro/streamsockets:server-2.0.0
    restart: unless-stopped
    environment:
      - ACCOUNTS_CONFIG_FILE=/etc/streamsockets/accounts.yml
      - BIND_PORT=8080
      - METRICS_PORT=9090
      - LOG_FORMAT=json
    volumes:
      - ./accounts.yml:/etc/streamsockets/accounts.yml
    ports:
      - "8080:8080/tcp"
      - "9090:9090/tcp"

  streamsockets-client:
    image: hyperxpro/streamsockets:client-2.0.0
    restart: unless-stopped
    environment:
      - WEBSOCKET_URI=ws://streamsockets-server:8080/tunnel
      - AUTH_TOKEN=your-secret-token
      - ROUTE=example.com:8888
      - BIND_PORT=9000
      - EXIT_ON_FAILURE=true
    ports:
      - "9000:9000/udp"
```

Build the Rust workspace from source:

```bash
cargo build --release --locked
# binaries: ./target/release/streamsockets-server, ./target/release/streamsockets-client
```

### io_uring vs epoll (Linux)

The Rust workspace probes for io_uring on startup and exposes the result as
`streamsockets_runtime_kind{kind="io_uring|epoll|tokio"}`. Both binaries spawn
N current-thread runtimes (one per core, pinned via `core_affinity`) with
`SO_REUSEPORT` fanout — see [`MIGRATION.md`](MIGRATION.md) §4 and §7. Set
`DISABLE_IOURING=true` to force the epoll path; Docker images default to this
because most cloud seccomp profiles still block io_uring syscalls.

| Platform | I/O backend today | Notes |
|---|---|---|
| Linux ≥ 5.6, no seccomp block | tokio (epoll) | runtime_kind metric reports `io_uring` if probe succeeds; actual runtime is tokio. tokio-uring path WIP. |
| Linux < 5.6, or io_uring blocked by seccomp | tokio (epoll) | normal path |
| Docker (default) | tokio (epoll) | `DISABLE_IOURING=true` baked into images, matching Java behavior |

### ⚠️ Security: `CLIENT_IP_HEADER` spoofing

If you set `CLIENT_IP_HEADER` (e.g., to honor `X-Forwarded-For` from an upstream
proxy), **also set `CLIENT_IP_HEADER_TRUSTED_CIDRS`** to the comma-separated CIDRs
of those proxies. Otherwise any direct connection to the server can spoof the
header and impersonate any IP in `allowedIps`. The server logs a startup warning
in that configuration; treat it as misconfiguration in production. Example:

```yaml
- CLIENT_IP_HEADER=X-Forwarded-For
- CLIENT_IP_HEADER_TRUSTED_CIDRS=10.0.0.0/8,fd00::/8
```


---

## Operator documentation

For the full operator-facing guide — handshake details, env-var reference, accounts.yml schema, Prometheus metrics, sysctl recommendations, LB tuning, rollback procedures, and the upgrade path from v1.7.0 — see [`MIGRATION.md`](MIGRATION.md): §10 (env vars), §13 (metrics), §14 (rollout), and §15 (rollback / open questions).

The accounts.yml schema is unchanged from v1.7.0; existing files keep working without edits.

---

## Build from source

```bash
cargo build --release --locked
# binaries: target/release/streamsockets-server, target/release/streamsockets-client
cargo test --workspace
```

Toolchain pinned in [`rust-toolchain.toml`](rust-toolchain.toml). MSRV in CI matrix at [`.github/workflows/rust.yml`](.github/workflows/rust.yml).

---

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
