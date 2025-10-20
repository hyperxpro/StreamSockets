/*
 *    Copyright 2025, Aayush Atharva
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 */

package com.aayushatharva.streamsockets.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PongWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler.ClientHandshakeStateEvent;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.util.ReferenceCounted;
import lombok.extern.log4j.Log4j2;

import static com.aayushatharva.streamsockets.common.Utils.envValue;
import static com.aayushatharva.streamsockets.common.Utils.envValueAsInt;
import static io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler.ClientHandshakeStateEvent.HANDSHAKE_COMPLETE;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

/**
 * This class receives {@link WebSocketFrame} from the WebSocket server and sends them to the UDP client.
 */
@Log4j2
public final class WebSocketClientHandler extends ChannelInboundHandlerAdapter {

    // Use unreleasableBuffer to prevent accidental releases and reuse ObjectMapper for performance (thread-safe)
    private static final ByteBuf PING = Unpooled.unreleasableBuffer(Unpooled.wrappedBuffer("PING".getBytes()));
    private static final int PING_INTERVAL_MILLIS = envValueAsInt("PING_INTERVAL_MILLIS", 5000);
    private static final int PING_TIMEOUT_MILLIS = envValueAsInt("PING_TIMEOUT_MILLIS", 10_000);
    private static final int MAX_PING_FAILURES = 5;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String ROUTE = envValue("ROUTE", "127.0.0.1:8888");
    
    private final DatagramHandler datagramHandler;
    private final boolean useNewProtocol;

    private ChannelPromise websocketHandshakeFuture;
    private ChannelPromise authenticationFuture;
    private ChannelHandlerContext ctx;

    private long lastPongTime;
    private int consecutivePingFailures = 0;

    WebSocketClientHandler(DatagramHandler datagramHandler, boolean useNewProtocol) {
        this.datagramHandler = datagramHandler;
        this.useNewProtocol = useNewProtocol;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        this.ctx = ctx;
        websocketHandshakeFuture = ctx.newPromise();
        authenticationFuture = ctx.newPromise();
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        // If the handshake is complete, create a new UDP connection on server end and set the handshake future to success
        if (evt instanceof ClientHandshakeStateEvent event && event == HANDSHAKE_COMPLETE) {
            if (!useNewProtocol) {
                // Old protocol: send connection request via JSON
                newUdpConnection();
            } else {
                // New protocol: connection already established via headers, mark as ready
                log.info("Connected to remote server: {} (new protocol)", ctx.channel().remoteAddress());
                authenticationFuture.setSuccess();
                
                // Reset ping failure counter on successful connection
                consecutivePingFailures = 0;

                // Send a ping at configurable interval (default 5 seconds)
                ctx.channel().eventLoop().scheduleAtFixedRate(() -> {
                    ctx.writeAndFlush(new PingWebSocketFrame(PING.duplicate()));
                }, 0, PING_INTERVAL_MILLIS, MILLISECONDS);

                lastPongTime = System.currentTimeMillis();
                ctx.channel().eventLoop().scheduleAtFixedRate(() -> {
                    if (System.currentTimeMillis() - lastPongTime > PING_TIMEOUT_MILLIS) {
                        consecutivePingFailures++;
                        log.warn("Ping timeout (failure {} of {})", consecutivePingFailures, MAX_PING_FAILURES);
                        
                        if (consecutivePingFailures >= MAX_PING_FAILURES) {
                            log.error("Max ping failures reached ({}), closing connection for reconnection...", MAX_PING_FAILURES);
                            ctx.close();
                        }
                    }
                }, 0, 1000, MILLISECONDS);
            }
            websocketHandshakeFuture.setSuccess();
            return;
        }
        super.userEventTriggered(ctx, evt);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof TextWebSocketFrame textWebSocketFrame) {
            String text = textWebSocketFrame.text();
            
            if (useNewProtocol) {
                // New protocol: handle tunnel ID responses
                if (text.startsWith("SOCKET ID: ")) {
                    int tunnelId = Integer.parseInt(text.substring(11));
                    log.info("Created UDP tunnel with ID: {}", tunnelId);
                    datagramHandler.onTunnelCreated(tunnelId);
                    
                    // First tunnel creation completes authentication
                    if (tunnelId == 1 && !authenticationFuture.isDone()) {
                        authenticationFuture.setSuccess();
                        
                        // Reset ping failure counter on successful connection
                        consecutivePingFailures = 0;

                        // Send a ping at configurable interval (default 5 seconds)
                        ctx.channel().eventLoop().scheduleAtFixedRate(() -> {
                            ctx.writeAndFlush(new PingWebSocketFrame(PING.duplicate()));
                        }, 0, PING_INTERVAL_MILLIS, MILLISECONDS);

                        lastPongTime = System.currentTimeMillis();
                        ctx.channel().eventLoop().scheduleAtFixedRate(() -> {
                            if (System.currentTimeMillis() - lastPongTime > PING_TIMEOUT_MILLIS) {
                                consecutivePingFailures++;
                                log.warn("Ping timeout (failure {} of {})", consecutivePingFailures, MAX_PING_FAILURES);
                                
                                if (consecutivePingFailures >= MAX_PING_FAILURES) {
                                    log.error("Max ping failures reached ({}), closing connection for reconnection...", MAX_PING_FAILURES);
                                    ctx.close();
                                }
                            }
                        }, 0, 1000, MILLISECONDS);
                    }
                } else if (text.startsWith("CLOSE ID: ")) {
                    int tunnelId = Integer.parseInt(text.substring(10));
                    log.info("Server closed UDP tunnel with ID: {}", tunnelId);
                    datagramHandler.onTunnelClosed(tunnelId);
                } else {
                    log.warn("Received unknown text frame in new protocol: {}", text);
                }
            } else {
                // Old protocol: handle JSON responses
                try {
                    JsonNode requestJson = OBJECT_MAPPER.readTree(text);

                    // If the server sends a success message, set the authentication future to success
                    if (requestJson.get("success").asBoolean() && requestJson.get("message").asText().equalsIgnoreCase("connected")) {
                        log.info("Connected to remote server: {}", ctx.channel().remoteAddress());
                        authenticationFuture.setSuccess();
                        
                        // Reset ping failure counter on successful connection
                        consecutivePingFailures = 0;

                        // Send a ping at configurable interval (default 5 seconds)
                        ctx.channel().eventLoop().scheduleAtFixedRate(() -> {
                            ctx.writeAndFlush(new PingWebSocketFrame(PING.duplicate()));
                        }, 0, PING_INTERVAL_MILLIS, MILLISECONDS);

                        lastPongTime = System.currentTimeMillis();
                        ctx.channel().eventLoop().scheduleAtFixedRate(() -> {
                            if (System.currentTimeMillis() - lastPongTime > PING_TIMEOUT_MILLIS) {
                                consecutivePingFailures++;
                                log.warn("Ping timeout (failure {} of {})", consecutivePingFailures, MAX_PING_FAILURES);
                                
                                if (consecutivePingFailures >= MAX_PING_FAILURES) {
                                    log.error("Max ping failures reached ({}), closing connection for reconnection...", MAX_PING_FAILURES);
                                    ctx.close();
                                }
                            }
                        }, 0, 1000, MILLISECONDS);
                    } else {
                        log.error("Failed to connect to remote server: {}", requestJson.get("message").asText());
                        authenticationFuture.setFailure(new Exception(requestJson.get("message").asText()));
                        ctx.close();
                    }
                } catch (Exception e) {
                    log.error("Failed to parse JSON response", e);
                    authenticationFuture.setFailure(e);
                    ctx.close();
                }
            }
            textWebSocketFrame.release();
        } else if (msg instanceof BinaryWebSocketFrame binaryWebSocketFrame) {
            // Pass to datagram handler (it will handle tunnel ID extraction)
            datagramHandler.handleBinaryFrame(binaryWebSocketFrame);
        } else if (msg instanceof PongWebSocketFrame pongWebSocketFrame) {
            // Release the frame itself (content will be released automatically)
            pongWebSocketFrame.release();
            lastPongTime = System.currentTimeMillis();
            // Reset consecutive failures on successful pong
            consecutivePingFailures = 0;
        } else {
            log.error("Unknown frame type: {}", msg.getClass().getName());

            // Release the message if it is a reference counted object
            if (msg instanceof ReferenceCounted referenceCounted) {
                referenceCounted.release();
            }
        }
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        // Flush pending writes for better batching
        ctx.flush();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.error("WebSocketClientHandler exception", cause);

        if (!websocketHandshakeFuture.isDone()) {
            websocketHandshakeFuture.setFailure(cause);
        }

        ctx.close();
    }

    void newUdpConnection() {
        authenticationFuture = ctx.newPromise();

        // Avoid splitting the route string twice
        int colonIndex = ROUTE.indexOf(':');
        String address = ROUTE.substring(0, colonIndex);
        int port = Integer.parseInt(ROUTE.substring(colonIndex + 1));

        try {
            ObjectNode requestJson = OBJECT_MAPPER.createObjectNode();
            requestJson.put("address", address);
            requestJson.put("port", port);

            ctx.writeAndFlush(new TextWebSocketFrame(OBJECT_MAPPER.writeValueAsString(requestJson)));
        } catch (Exception e) {
            log.error("Failed to create connection request JSON", e);
            authenticationFuture.setFailure(e);
            ctx.close();
        }
    }

    boolean isReadyForWrite() {
        return websocketHandshakeFuture.isSuccess() && authenticationFuture.isSuccess();
    }

    public ChannelFuture websocketHandshakeFuture() {
        return websocketHandshakeFuture;
    }

    public ChannelFuture authenticationFuture() {
        return authenticationFuture;
    }

    public boolean isUsingNewProtocol() {
        return useNewProtocol;
    }
    
    public void requestNewTunnel() {
        if (useNewProtocol && ctx != null) {
            ctx.writeAndFlush(new TextWebSocketFrame("NEW"));
            log.debug("Requested new UDP tunnel from server");
        }
    }
}
