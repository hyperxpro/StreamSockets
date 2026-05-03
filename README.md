# StreamSockets
StreamSockets tunnels UDP over WebSockets so UDP traffic can traverse WebSocket-only networks.

**Repo layout**:

| Path | What |
|---|---|
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml` | Cargo workspace root |
| `streamsockets-{core,auth,metrics,server,client,testsuite}/` | workspace member crates |
| `docker/` | Dockerfiles |

## Quick start (Docker)

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

## Build from source

```bash
cargo build --release --locked
# binaries: target/release/streamsockets-server, target/release/streamsockets-client
cargo test --workspace
```

Toolchain pinned in [`rust-toolchain.toml`](rust-toolchain.toml). MSRV in CI matrix at [`.github/workflows/rust.yml`](.github/workflows/rust.yml).

## IO backend (io_uring vs epoll)

The binaries probe for io_uring on startup and expose the result as
`streamsockets_runtime_kind{kind="io_uring|epoll|tokio"}`.

To enable io_uring:

- Run on Linux >= 5.6.
- Allow io_uring syscalls in your seccomp profile (Docker defaults block them).
- Set `DISABLE_IOURING=false` or remove it from the environment.

If io_uring is blocked or unavailable, the runtime falls back to tokio/epoll.

## Security: CLIENT_IP_HEADER spoofing

If you set `CLIENT_IP_HEADER` (e.g., to honor `X-Forwarded-For` from an upstream
proxy), also set `CLIENT_IP_HEADER_TRUSTED_CIDRS` to the comma-separated CIDRs
of those proxies. Otherwise any direct connection to the server can spoof the
header and impersonate any IP in `allowedIps`. The server logs a startup warning
in that configuration; treat it as misconfiguration in production. Example:

```yaml
- CLIENT_IP_HEADER=X-Forwarded-For
- CLIENT_IP_HEADER_TRUSTED_CIDRS=10.0.0.0/8,fd00::/8
```

## License

Apache-2.0 - see [`LICENSE`](LICENSE).
