# StreamSockets
StreamSockets is a UDP over WebSockets tunnel. It allows you to send and receive UDP packets over a WebSocket connection. 
This is useful for situations where you need to send UDP packets over a network that only supports WebSockets.

### Docker Compose

#### Server
```yaml
services:
  stream:
    image: hyperxpro/streamsockets:server-1.0.0
    container_name: streamsockets-server
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
  stream:
    image: hyperxpro/streamsockets:client-1.0.0
    container_name: streamsockets-client
    environment:
      - THREADS=4
      - BIND_ADDRESS=0.0.0.0
      - BIND_PORT=8888
      - WEBSOCKET_URI=ws://localhost:8080/tunnel
      - AUTH_TOKEN=secret
      - ROUTE=127.0.0.1:8888
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
- `token` - Authentication token for the client.
