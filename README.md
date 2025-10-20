# StreamSockets
StreamSockets is a UDP over WebSockets tunnel. It allows you to send and receive UDP packets over a WebSocket connection. 
This is useful for situations where you need to send UDP packets over a network that only supports WebSockets.

### Docker Compose

#### Server
```yaml
services:
  streamsockets-server:
    image: hyperxpro/streamsockets:server-1.0.0
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
    volumes:
      - ./accounts.yml:/app/accounts.yml
    ports:
      - "8080:8080/tcp"
```

#### Client

```yaml
services:
  streamsockets-client:
    image: hyperxpro/streamsockets:client-1.0.0
    container_name: streamsockets-client
    restart: unless-stopped
    environment:
      - THREADS=4
      - BIND_ADDRESS=0.0.0.0
      - BIND_PORT=8888
      - WEBSOCKET_URI=ws://localhost:8080/tunnel
      - AUTH_TOKEN=secret
      - ROUTE=127.0.0.1:8888
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

#### Client
- `THREADS` - Number of threads.
- `WEBSOCKET_URI` - URI of the WebSocket endpoint. 
- `AUTH_TOKEN` - Authentication token.
- `ROUTE` - Route to the endpoint.
- `PING_INTERVAL_MILLIS` - Interval in milliseconds to send ping messages to the server (default: 5000).
- `PING_TIMEOUT_MILLIS` - Timeout in milliseconds to wait for a pong message from the server. After 5 consecutive failures, the connection is closed and retried (default: 10000).
- `RETRY_INITIAL_DELAY_SECONDS` - Initial delay in seconds before the first retry attempt (default: 1).
- `RETRY_MAX_DELAY_SECONDS` - Maximum delay in seconds between retry attempts (default: 30).
- `UDP_TIMEOUT` - Timeout in seconds for UDP inactivity. If no UDP packets are received within this period, the WebSocket connection is closed (default: 300).

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
- `routes` - List of routes for the client.
- `token` - Authentication token for the client. (`openssl rand -hex 32`)
