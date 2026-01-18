# StreamSockets
StreamSockets is a UDP over WebSockets tunnel. It allows you to send and receive UDP packets over a WebSocket connection. 
This is useful for situations where you need to send UDP packets over a network that only supports WebSockets.

### Docker Compose

#### Server
```yaml
services:
  streamsockets-server:
    image: hyperxpro/streamsockets:server-1.6.0
    container_name: streamsockets-server
    restart: unless-stopped
    environment:
      - ACCOUNTS_CONFIG_FILE=/app/accounts.yml
      - CLIENT_IP_HEADER=X-Forwarded-For
      - PARENT_THREADS=4
      - CHILD_THREADS=4
      - BIND_ADDRESS=0.0.0.0
      - BIND_PORT=8080
      - HTTP_MAX_CONTENT_LENGTH=65536
      - WS_PATH=/tunnel
      - METRICS_ENABLED=true
      - METRICS_BIND_ADDRESS=0.0.0.0
      - METRICS_PORT=9090
      - METRICS_PATH=/metrics
    volumes:
      - ./accounts.yml:/app/accounts.yml
    ports:
      - "8080:8080/tcp"
      - "9090:9090/tcp"
```

#### Client

```yaml
services:
  streamsockets-client:
    image: hyperxpro/streamsockets:client-1.6.0
    container_name: streamsockets-client
    restart: unless-stopped
    environment:
      - THREADS=4
      - BIND_ADDRESS=0.0.0.0
      - BIND_PORT=8888
      - WEBSOCKET_URI=ws://localhost:8080/tunnel
      - AUTH_TOKEN=secret
      - ROUTE=example.com:8888
      - PING_INTERVAL_MILLIS=1000
      - PING_TIMEOUT_MILLIS=10000
      - UDP_TIMEOUT=300
    ports:
      - "8888:8888/udp"
```

### Environment Variables

#### Server
- `ACCOUNTS_CONFIG_FILE` - Path to the accounts configuration file.
- `CLIENT_IP_HEADER` - Header to use for the client IP address.
- `PARENT_THREADS` - Number of parent threads.
- `CHILD_THREADS` - Number of child threads.
- `BIND_ADDRESS` - Address to bind the server to.
- `BIND_PORT` - Port to bind the server to.
- `HTTP_MAX_CONTENT_LENGTH` - Maximum content length for HTTP requests, this is used to during the WebSocket handshake.
- `WS_PATH` - Path to the WebSocket endpoint.
- `METRICS_ENABLED` - Enable Prometheus metrics (default: true).
- `METRICS_BIND_ADDRESS` - Address to bind the metrics server to (default: 0.0.0.0).
- `METRICS_PORT` - Port to bind the metrics server to (default: 9090).
- `METRICS_PATH` - Path to the metrics endpoint (default: /metrics).

#### Client
- `THREADS` - Number of threads.
- `WEBSOCKET_URI` - URI of the WebSocket endpoint. 
- `AUTH_TOKEN` - Authentication token.
- `ROUTE` - Route to the endpoint. Can be an IP address (e.g., `127.0.0.1:8888`) or a domain name (e.g., `example.com:8888`). The domain will be resolved by the server on each connection.
- `BIND_ADDRESS` - Address to bind the UDP server to (default: 0.0.0.0).
- `BIND_PORT` - Port to bind the UDP server to (default: 9000).
- `PING_INTERVAL_MILLIS` - Interval in milliseconds to send ping messages to the server (default: 5000).
- `PING_TIMEOUT_MILLIS` - Timeout in milliseconds to wait for a pong message from the server. After 5 consecutive failures, the connection is closed and retried (default: 10000).
- `RETRY_INITIAL_DELAY_SECONDS` - Initial delay in seconds before the first retry attempt (default: 1).
- `RETRY_MAX_DELAY_SECONDS` - Maximum delay in seconds between retry attempts (default: 30).
- `UDP_TIMEOUT` - Timeout in seconds for UDP inactivity. If no UDP packets are received within this period, the WebSocket connection is closed (default: 300).
- `EXIT_ON_FAILURE` - When set to `true`, the JVM will exit with status code 1 on connection failure or disconnect, allowing systemd to manage restarts. By default, the client will retry connections with exponential backoff (default: false).

### Running Client with systemd

For production deployments, you can run the StreamSockets client as a systemd service. This allows systemd to automatically restart the client on failures.

#### Build the Client JAR

```bash
mvn clean package -pl client -am
```

The built JAR will be located at `client/client.jar`.

#### Create systemd Service File

Create a file at `/etc/systemd/system/streamsockets-client.service`:

```ini
[Unit]
Description=StreamSockets Client
After=network.target

[Service]
Type=simple
User=streamsockets
Group=streamsockets
WorkingDirectory=/opt/streamsockets
ExecStart=/usr/bin/java -jar /opt/streamsockets/client.jar
Restart=always
RestartSec=10

# Environment variables
Environment="THREADS=4"
Environment="BIND_ADDRESS=0.0.0.0"
Environment="BIND_PORT=8888"
Environment="WEBSOCKET_URI=ws://your-server:8080/tunnel"
Environment="AUTH_TOKEN=your-secret-token"
Environment="ROUTE=example.com:8888"
Environment="EXIT_ON_FAILURE=true"

# Security settings
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

#### Deploy and Start the Service

```bash
# Create user and directories
sudo useradd -r -s /bin/false streamsockets
sudo mkdir -p /opt/streamsockets
sudo cp client/client.jar /opt/streamsockets/
sudo chown -R streamsockets:streamsockets /opt/streamsockets

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable streamsockets-client
sudo systemctl start streamsockets-client

# Check status
sudo systemctl status streamsockets-client

# View logs
sudo journalctl -u streamsockets-client -f
```

When `EXIT_ON_FAILURE=true`, the client will exit immediately on connection failures, and systemd will automatically restart it after the configured `RestartSec` interval.

### Accounts Configuration

```yaml
accounts:
-   name: user1
    allowedIps:
    - '127.0.0.1'
    - '192.168.1.1'
    reuse: false
    routes:
    - '192.168.1.2:5050'
    - '127.0.0.1:5050'
    - '127.0.0.1:8888'
    token: '123456'
-   name: user2
    allowedIps:
    - '127.0.0.1'
    - '192.168.1.1'
    - '172.16.1.0/16'
    reuse: false
    routes:
    - '192.168.1.2:5050'
    - '127.0.0.1:5050'
    token: 'abcdef'

```

- `name` - Account name.
- `allowedIps` - List of allowed IP addresses or CIDR ranges for client.
- `reuse` - Whether to allow reuse of the account concurrently.
- `routes` - List of routes for the client. Can be IP addresses or domain names (e.g., `example.com:8888`). Domain names will be resolved by the server on each connection.
- `token` - Authentication token for the client. (`openssl rand -hex 32`)

### Prometheus Metrics

The server exposes Prometheus metrics for monitoring and visualization with Grafana. The metrics are available at the configured endpoint (default: `http://localhost:9090/metrics`).

#### Available Metrics

- `streamsockets_active_connections{account_name}` - Number of active WebSocket connections by account
- `streamsockets_connection_status{account_name}` - Connection status by account (1 = connected, 0 = disconnected)
- `streamsockets_total_connections{account_name}` - Total number of connections by account (counter)
- `streamsockets_bytes_received_total{account_name}` - Total bytes received from clients by account (counter)
- `streamsockets_bytes_sent_total{account_name}` - Total bytes sent to clients by account (counter)
- `streamsockets_connection_duration_seconds{account_name}` - Histogram of connection durations in seconds by account

#### Grafana Dashboard

You can create a Grafana dashboard to visualize these metrics:

1. **Active Connections Panel**: Graph showing `streamsockets_active_connections` over time
2. **Connection Status Panel**: Table showing current connection status per account
3. **Data Transfer Panel**: Graph showing rate of `streamsockets_bytes_received_total` and `streamsockets_bytes_sent_total`
4. **Connection Duration Panel**: Histogram showing distribution of connection durations
