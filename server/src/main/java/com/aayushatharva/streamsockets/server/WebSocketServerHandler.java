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

package com.aayushatharva.streamsockets.server;

import com.aayushatharva.streamsockets.authentication.server.TokenAuthentication;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFactory;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelOption;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollDatagramChannel;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCounted;
import io.netty.util.concurrent.ScheduledFuture;
import lombok.extern.log4j.Log4j2;
import org.jctools.queues.MpscUnboundedArrayQueue;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.aayushatharva.streamsockets.common.Utils.envValueAsInt;
import static io.netty.channel.ChannelFutureListener.CLOSE;

@Log4j2
final class WebSocketServerHandler extends ChannelInboundHandlerAdapter {

    // Reuse ObjectMapper instance and static buffers for better performance (thread-safe)
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final byte[] NEW_BYTES = "NEW".getBytes(StandardCharsets.UTF_8);
    
    // Configuration constants
    private static final int UDP_TUNNEL_TIMEOUT_SECONDS = envValueAsInt("UDP_TUNNEL_TIMEOUT_SECONDS", 300);
    private static final int MAX_UDP_TUNNELS_PER_CLIENT = envValueAsInt("MAX_UDP_TUNNELS_PER_CLIENT", 10);
    
    // AttributeKeys for reading protocol information
    private static final AttributeKey<Boolean> NEW_PROTOCOL_KEY = AttributeKey.valueOf("newProtocol");
    private static final AttributeKey<String> ROUTE_ADDRESS_KEY = AttributeKey.valueOf("routeAddress");
    private static final AttributeKey<String> ROUTE_PORT_KEY = AttributeKey.valueOf("routePort");
    private static final AttributeKey<String> ROUTE_STRING_KEY = AttributeKey.valueOf("routeString");
    private static final AttributeKey<String> ACCOUNT_NAME_KEY = AttributeKey.valueOf("accountName");
    private static final AttributeKey<String> CLIENT_IP_KEY = AttributeKey.valueOf("clientIp");
    
    private final TokenAuthentication tokenAuthentication;
    private final Queue<BinaryWebSocketFrame> pendingFrames = new MpscUnboundedArrayQueue<>(128);
    
    // Multi-tunnel support for new protocol
    private final ConcurrentHashMap<Integer, UdpTunnel> udpTunnels = new ConcurrentHashMap<>();
    private final AtomicInteger nextTunnelId = new AtomicInteger(1);
    private ScheduledFuture<?> timeoutCheckTask;
    
    // Legacy single tunnel support for old protocol
    private InetSocketAddress socketAddress;
    private Channel udpChannel;
    
    private String routeCache; // Cache the route string to avoid repeated concatenation
    private boolean newProtocol; // Flag to track which protocol version client is using

    WebSocketServerHandler(TokenAuthentication tokenAuthentication, boolean newProtocol) {
        this.tokenAuthentication = tokenAuthentication;
        this.newProtocol = newProtocol;
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        // Handle WebSocket handshake complete event for new protocol
        if (evt instanceof io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler.HandshakeComplete) {
            // Cache channel reference to avoid repeated ctx.channel() calls
            Channel channel = ctx.channel();
            
            // Check for new protocol from channel attributes
            Boolean newProtocolAttr = channel.attr(NEW_PROTOCOL_KEY).get();
            if (newProtocolAttr != null && newProtocolAttr) {
                newProtocol = true;
                
                // Get account info and client IP from channel attributes
                String accountName = channel.attr(ACCOUNT_NAME_KEY).get();
                String clientIp = channel.attr(CLIENT_IP_KEY).get();
                
                log.info("account={}, clientIp={}, wsRemoteAddress={} - WebSocket handshake complete with new protocol", 
                        accountName, clientIp, channel.remoteAddress());
                
                // Get pre-built route string from channel attributes (no string concatenation needed)
                routeCache = channel.attr(ROUTE_STRING_KEY).get();
                String address = channel.attr(ROUTE_ADDRESS_KEY).get();
                String portStr = channel.attr(ROUTE_PORT_KEY).get();
                
                try {
                    int port = Integer.parseInt(portStr);
                    socketAddress = new InetSocketAddress(address, port);

                    // Check if the route is allowed (using cached route string)
                    if (!tokenAuthentication.containsRoute(routeCache)) {
                        log.error("account={}, clientIp={}, wsRemoteAddress={}, route={} - attempted to connect to unauthorized route", 
                                accountName, clientIp, channel.remoteAddress(), routeCache);
                        ctx.close();
                        return;
                    }

                    // Create the first UDP tunnel
                    createNewTunnel(ctx, accountName, clientIp, true);
                    
                } catch (Exception e) {
                    log.error("account={}, clientIp={}, wsRemoteAddress={} - invalid route parameters: address={}, port={}", 
                            accountName, clientIp, channel.remoteAddress(), address, portStr, e);
                    cleanupPendingFrames();
                    ctx.close();
                }
            }
        }
        super.userEventTriggered(ctx, evt);
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        // channelActive is called before WebSocket handshake, so we can't use it for new protocol
        // The new protocol connection will be established in userEventTriggered after handshake
        super.channelActive(ctx);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof TextWebSocketFrame textWebSocketFrame) {
            // Old protocol: handle JSON-based connection setup
            if (!newProtocol) {
                // Close existing connection if any and create a new connection
                // This is done to prevent multiple connections to the same remote server
                if (socketAddress != null) {
                    // Retain the frame since it will be used in the listener callback
                    textWebSocketFrame.retain();
                    udpChannel.close().addListener((ChannelFutureListener) future -> {
                        try {
                            newConnectionFromJson(textWebSocketFrame, ctx);
                        } finally {
                            textWebSocketFrame.release();
                        }
                    });
                } else {
                    newConnectionFromJson(textWebSocketFrame, ctx);
                }
            } else {
                // New protocol: handle "NEW" text frame to create additional UDP tunnels
                String text = textWebSocketFrame.text();
                if ("NEW".equals(text)) {
                    String accountName = ctx.channel().attr(ACCOUNT_NAME_KEY).get();
                    String clientIp = ctx.channel().attr(CLIENT_IP_KEY).get();
                    
                    // Check if we've reached the max tunnel limit
                    if (udpTunnels.size() >= MAX_UDP_TUNNELS_PER_CLIENT) {
                        log.warn("account={}, clientIp={}, wsRemoteAddress={} - max UDP tunnels limit ({}) reached", 
                                accountName, clientIp, ctx.channel().remoteAddress(), MAX_UDP_TUNNELS_PER_CLIENT);
                        textWebSocketFrame.release();
                        return;
                    }
                    
                    // Create a new tunnel
                    createNewTunnel(ctx, accountName, clientIp, false);
                } else {
                    // Unknown text frame
                    String accountName = ctx.channel().attr(ACCOUNT_NAME_KEY).get();
                    String clientIp = ctx.channel().attr(CLIENT_IP_KEY).get();
                    log.warn("account={}, clientIp={}, wsRemoteAddress={} - received unexpected text frame: {}", 
                            accountName, clientIp, ctx.channel().remoteAddress(), text);
                }
                textWebSocketFrame.release();
            }
        } else if (msg instanceof BinaryWebSocketFrame binaryWebSocketFrame) {
            // Extract tunnel ID from first byte
            if (!newProtocol) {
                // Old protocol: single tunnel, no ID
                handleLegacyBinaryFrame(binaryWebSocketFrame);
            } else {
                // New protocol: multi-tunnel with ID in first byte
                handleMultiTunnelBinaryFrame(binaryWebSocketFrame);
            }
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
        log.error("WebSocketServerHandler exception", cause);
    }

    private void newConnectionFromJson(TextWebSocketFrame textWebSocketFrame, ChannelHandlerContext ctx) {
        // Validate address and port from JSON (old protocol)
        try {
            JsonNode requestJson = OBJECT_MAPPER.readTree(textWebSocketFrame.text());
            String address = requestJson.get("address").asText();
            int port = requestJson.get("port").asInt();
            socketAddress = new InetSocketAddress(address, port);

            // Build route string once using StringBuilder to avoid string concatenation
            routeCache = new StringBuilder(address.length() + 1 + String.valueOf(port).length())
                    .append(address).append(':').append(port).toString();

            // Check if the route is allowed
            if (!tokenAuthentication.containsRoute(routeCache)) {
                ObjectNode responseJson = OBJECT_MAPPER.createObjectNode();
                responseJson.put("success", false);
                responseJson.put("message", "Route is not allowed");
                ctx.writeAndFlush(new TextWebSocketFrame(OBJECT_MAPPER.writeValueAsString(responseJson))).addListener(CLOSE);
                return;
            }
        } catch (Exception e) {
            ObjectNode responseJson = OBJECT_MAPPER.createObjectNode();
            responseJson.put("success", false);
            responseJson.put("message", "Invalid address or port");

            try {
                ctx.writeAndFlush(new TextWebSocketFrame(OBJECT_MAPPER.writeValueAsString(responseJson))).addListener(CLOSE);
            } catch (Exception ex) {
                log.error("Failed to write error response", ex);
                ctx.close();
            }
            return;
        }

        // Connect to remote server and send response
        connectToRemote(ctx, 0).addListener((ChannelFutureListener) future -> {
            try {
                // Get account info and client IP from channel attributes
                String accountName = ctx.channel().attr(ACCOUNT_NAME_KEY).get();
                String clientIp = ctx.channel().attr(CLIENT_IP_KEY).get();
                
                ObjectNode responseJson = OBJECT_MAPPER.createObjectNode();
                if (future.isSuccess()) {
                    log.info("account={}, clientIp={}, wsRemoteAddress={}, route={} - connected to remote server (old protocol)", 
                            accountName, clientIp, ctx.channel().remoteAddress(), socketAddress);

                    udpChannel = future.channel();
                    responseJson.put("success", true);
                    responseJson.put("message", "connected");
                    ctx.writeAndFlush(new TextWebSocketFrame(OBJECT_MAPPER.writeValueAsString(responseJson)));

                    // If the WebSocket connection is closed, close the UDP channel
                    ctx.channel().closeFuture().addListener((ChannelFutureListener) future1 -> {
                        log.info("account={}, clientIp={}, wsRemoteAddress={}, route={} - disconnected from remote server (old protocol)", 
                                accountName, clientIp, ctx.channel().remoteAddress(), socketAddress);
                        udpChannel.close();
                    });
                } else {
                    log.error("account={}, clientIp={}, wsRemoteAddress={}, route={} - failed to connect to remote server (old protocol)", 
                            accountName, clientIp, ctx.channel().remoteAddress(), socketAddress);

                    responseJson.put("status", "failed");
                    responseJson.put("message", future.cause().getMessage());

                    cleanupPendingFrames();
                    ctx.writeAndFlush(new TextWebSocketFrame(OBJECT_MAPPER.writeValueAsString(responseJson))).addListener(CLOSE);
                }
            } catch (Exception e) {
                log.error("Failed to write connection response", e);
                cleanupPendingFrames();
                ctx.close();
            }
        });
    }

    private ChannelFuture connectToRemote(ChannelHandlerContext ctx, int tunnelId) {
        Bootstrap bootstrap = new Bootstrap()
                .group(ctx.channel().eventLoop())
                .channelFactory(channelFactory())
                .option(ChannelOption.SO_RCVBUF, 1048576)
                .option(ChannelOption.SO_SNDBUF, 1048576)
                .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                .handler(new DownstreamHandler(ctx.channel(), tunnelId, newProtocol));

        return bootstrap.connect(socketAddress);
    }

    private static ChannelFactory<DatagramChannel> channelFactory() {
        if (Epoll.isAvailable()) {
            return EpollDatagramChannel::new;
        } else {
            return NioDatagramChannel::new;
        }
    }

    private void createNewTunnel(ChannelHandlerContext ctx, String accountName, String clientIp, boolean isFirstTunnel) {
        int tunnelId = nextTunnelId.getAndIncrement();
        
        ChannelFuture connectFuture = connectToRemote(ctx, tunnelId);
        if (log.isDebugEnabled()) {
            log.debug("account={}, clientIp={}, wsRemoteAddress={}, tunnelId={}, route={} - initiated UDP tunnel", 
                    accountName, clientIp, ctx.channel().remoteAddress(), tunnelId, socketAddress);
        }
        
        connectFuture.addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                log.info("account={}, clientIp={}, wsRemoteAddress={}, tunnelId={}, route={} - UDP tunnel connected", 
                        accountName, clientIp, ctx.channel().remoteAddress(), tunnelId, socketAddress);
                
                Channel udpCh = future.channel();
                UdpTunnel tunnel = new UdpTunnel(tunnelId, udpCh, socketAddress);
                udpTunnels.put(tunnelId, tunnel);
                
                // For the first tunnel, also set the legacy udpChannel reference
                if (isFirstTunnel) {
                    udpChannel = udpCh;
                    
                    // Send any pending frames
                    while (!pendingFrames.isEmpty()) {
                        BinaryWebSocketFrame frame = pendingFrames.poll();
                        if (frame != null) {
                            // Prepend tunnel ID to the frame
                            udpCh.writeAndFlush(new DatagramPacket(frame.content(), socketAddress));
                            frame.release();
                        }
                    }
                }
                
                // Send tunnel ID to client
                String response = "SOCKET ID: " + tunnelId;
                ctx.writeAndFlush(new TextWebSocketFrame(response));
                
                // Start timeout monitoring if this is the second tunnel (first one has no timeout)
                if (udpTunnels.size() == 2 && timeoutCheckTask == null) {
                    startTimeoutMonitoring(ctx, accountName, clientIp);
                }
                
            } else {
                log.error("account={}, clientIp={}, wsRemoteAddress={}, tunnelId={}, route={} - failed to create UDP tunnel, cause: {}", 
                        accountName, clientIp, ctx.channel().remoteAddress(), tunnelId, socketAddress, future.cause());
                if (isFirstTunnel) {
                    cleanupPendingFrames();
                    ctx.close();
                }
            }
        });
    }
    
    private void startTimeoutMonitoring(ChannelHandlerContext ctx, String accountName, String clientIp) {
        timeoutCheckTask = ctx.channel().eventLoop().scheduleAtFixedRate(() -> {
            try {
                long timeoutMillis = UDP_TUNNEL_TIMEOUT_SECONDS * 1000L;
                udpTunnels.forEach((id, tunnel) -> {
                    if (tunnel.isIdle(timeoutMillis)) {
                        log.info("account={}, clientIp={}, wsRemoteAddress={}, tunnelId={} - UDP tunnel timed out after {} seconds of inactivity", 
                                accountName, clientIp, ctx.channel().remoteAddress(), id, UDP_TUNNEL_TIMEOUT_SECONDS);
                        closeTunnel(ctx, id, accountName, clientIp);
                    }
                });
            } catch (Exception e) {
                log.error("Error during timeout check", e);
            }
        }, UDP_TUNNEL_TIMEOUT_SECONDS, UDP_TUNNEL_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }
    
    private void closeTunnel(ChannelHandlerContext ctx, int tunnelId, String accountName, String clientIp) {
        UdpTunnel tunnel = udpTunnels.remove(tunnelId);
        if (tunnel != null) {
            tunnel.getUdpChannel().close();
            
            // Notify client
            String closeMessage = "CLOSE ID: " + tunnelId;
            ctx.writeAndFlush(new TextWebSocketFrame(closeMessage));
            
            log.info("account={}, clientIp={}, wsRemoteAddress={}, tunnelId={} - UDP tunnel closed", 
                    accountName, clientIp, ctx.channel().remoteAddress(), tunnelId);
            
            // Stop timeout monitoring if only one tunnel remains
            if (udpTunnels.size() == 1 && timeoutCheckTask != null) {
                timeoutCheckTask.cancel(false);
                timeoutCheckTask = null;
            }
        }
    }
    
    private void handleLegacyBinaryFrame(BinaryWebSocketFrame binaryWebSocketFrame) {
        // Old protocol: single tunnel, no ID
        if (udpChannel == null || !udpChannel.isActive()) {
            // Queue the frame to be sent once the UDP channel is ready
            pendingFrames.add(binaryWebSocketFrame.retain());
        } else {
            // Retain content since it's being passed to another channel
            udpChannel.writeAndFlush(new DatagramPacket(binaryWebSocketFrame.content().retain(), socketAddress));
            // Release the frame after content has been retained and sent
            binaryWebSocketFrame.release();
        }
    }
    
    private void handleMultiTunnelBinaryFrame(BinaryWebSocketFrame binaryWebSocketFrame) {
        // New protocol: first byte is tunnel ID
        if (binaryWebSocketFrame.content().readableBytes() < 1) {
            log.warn("Received binary frame with no tunnel ID");
            binaryWebSocketFrame.release();
            return;
        }
        
        int tunnelId = binaryWebSocketFrame.content().readByte() & 0xFF;
        UdpTunnel tunnel = udpTunnels.get(tunnelId);
        
        if (tunnel == null) {
            log.warn("Received data for unknown tunnel ID: {}", tunnelId);
            binaryWebSocketFrame.release();
            return;
        }
        
        // Update activity timestamp
        tunnel.updateActivity();
        
        // Send data without the tunnel ID byte
        Channel udpCh = tunnel.getUdpChannel();
        if (udpCh.isActive()) {
            udpCh.writeAndFlush(new DatagramPacket(binaryWebSocketFrame.content().retain(), tunnel.getSocketAddress()));
        }
        binaryWebSocketFrame.release();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        // Clean up any pending frames when the channel becomes inactive
        cleanupPendingFrames();
        
        // Close all UDP tunnels
        if (timeoutCheckTask != null) {
            timeoutCheckTask.cancel(false);
            timeoutCheckTask = null;
        }
        
        udpTunnels.values().forEach(tunnel -> tunnel.getUdpChannel().close());
        udpTunnels.clear();
        
        super.channelInactive(ctx);
    }

    private void cleanupPendingFrames() {
        // Release all pending frames to prevent memory leak
        while (!pendingFrames.isEmpty()) {
            BinaryWebSocketFrame frame = pendingFrames.poll();
            if (frame != null) {
                frame.release();
            }
        }
    }
}
