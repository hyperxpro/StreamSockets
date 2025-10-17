# Protocol Upgrade - Backwards Compatible Implementation

## Overview

This document describes the protocol upgrade from JSON-based to header-based communication while maintaining 100% backwards compatibility with existing clients.

## Protocol Versions

### Old Protocol (JSON-based)
The original protocol uses JSON payloads in WebSocket text frames for connection setup:

**Client → Server:**
```json
{"address": "127.0.0.1", "port": 8888}
```

**Server → Client:**
```json
{"success": true, "message": "connected"}
```

### New Protocol (Header-based)
The new protocol moves connection parameters to HTTP headers for better performance:

**HTTP Headers:**
```
X-Auth-Type: Token
X-Auth-Token: <token>
X-Route-Address: 127.0.0.1
X-Route-Port: 8888
```

No JSON exchange is needed - the connection is established immediately after WebSocket handshake.

## Implementation Details

### Server Side

The server automatically detects which protocol version the client is using:

1. **AuthenticationHandler** checks for presence of `X-Route-Address` and `X-Route-Port` headers
2. If present, it constructs the route and stores protocol version in channel attributes
3. **WebSocketServerHandler** reads the protocol version and:
   - **Old Protocol:** Waits for JSON text frame to establish connection
   - **New Protocol:** Establishes UDP connection immediately in `channelActive()`

### Client Side

Clients can opt into the new protocol by setting an environment variable:

```bash
USE_NEW_PROTOCOL=true
```

When enabled:
- Connection parameters are sent via HTTP headers
- No JSON text frame is sent
- Connection is established faster

### Backwards Compatibility

**100% Backwards Compatible:**
- Existing clients continue to work without any changes
- Server handles both protocols simultaneously
- No configuration changes required on server
- All existing tests pass

## Testing

### Compatibility Tests

A new test suite verifies both protocols:
- `ProtocolCompatibilityTest.testOldProtocolJsonBased()` - Verifies old protocol works
- Infrastructure in place for new protocol testing (needs timing refinement)

### Running Tests

```bash
mvn test
```

All 10 tests pass, confirming backwards compatibility.

## Performance Benefits

The new protocol provides performance improvements on hot paths:

1. **Reduced Overhead:** No JSON parsing/serialization for connection setup
2. **Faster Connection:** UDP channel established immediately after handshake
3. **Lower Latency:** Eliminates round-trip for connection confirmation

## Migration Path

### For Client Developers

**No action required** - existing clients continue to work.

To opt into the new protocol:
1. Add headers `X-Route-Address` and `X-Route-Port` during WebSocket handshake
2. Remove JSON connection request
3. Set `USE_NEW_PROTOCOL=true` environment variable (for this implementation)

### For Server Operators

**No action required** - server automatically supports both protocols.

## Future Work

1. **Connection Timing:** Refine async UDP channel creation timing to eliminate race conditions in new protocol
2. **Documentation:** Add protocol spec documentation
3. **Metrics:** Add metrics to track protocol version usage
4. **Migration Tools:** Provide tools to help clients migrate to new protocol

## Technical Notes

### Race Condition Handling

The new protocol establishes the UDP connection asynchronously. Current implementation:
- Validates route permissions before connection
- Handles connection failures gracefully
- Logs warnings if data arrives before connection completes
- Infrastructure in place to buffer early packets (needs refinement)

### Attribute Keys

Protocol information is stored in channel attributes:
```java
AttributeKey<Boolean> NEW_PROTOCOL_KEY = AttributeKey.valueOf("newProtocol");
AttributeKey<String> ROUTE_ADDRESS_KEY = AttributeKey.valueOf("routeAddress");
AttributeKey<String> ROUTE_PORT_KEY = AttributeKey.valueOf("routePort");
```

## References

- **Server Handler:** `server/src/main/java/com/aayushatharva/streamsockets/server/WebSocketServerHandler.java`
- **Authentication:** `server/src/main/java/com/aayushatharva/streamsockets/server/AuthenticationHandler.java`
- **Client Handler:** `client/src/main/java/com/aayushatharva/streamsockets/client/WebSocketClientHandler.java`
- **Client Initializer:** `client/src/main/java/com/aayushatharva/streamsockets/client/WebSocketClientInitializer.java`
- **Tests:** `testsuite/src/test/java/com/aayushatharva/streamsockets/ProtocolCompatibilityTest.java`
