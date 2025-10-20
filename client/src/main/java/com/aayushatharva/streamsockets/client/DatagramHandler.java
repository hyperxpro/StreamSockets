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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.util.ReferenceCounted;
import lombok.extern.log4j.Log4j2;
import org.jctools.queues.MpscUnboundedArrayQueue;

import javax.net.ssl.SSLException;
import java.net.InetSocketAddress;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class receives {@link DatagramPacket} from the UDP client and sends them to the WebSocket server.
 */
@Log4j2
@ChannelHandler.Sharable
public final class DatagramHandler extends ChannelInboundHandlerAdapter {

    private final Queue<BinaryWebSocketFrame> queuedFrames = new MpscUnboundedArrayQueue<>(128);
    private final EventLoopGroup eventLoopGroup;
    private final RetryManager retryManager = new RetryManager();
    private final ConcurrentHashMap<Integer, InetSocketAddress> tunnelIdToAddress = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<InetSocketAddress, Integer> addressToTunnelId = new ConcurrentHashMap<>();
    private final AtomicInteger defaultTunnelId = new AtomicInteger(0);

    private InetSocketAddress socketAddress;
    private Channel udpChannel;
    private Channel wsChannel;
    private ChannelFuture webSocketClientFuture;
    private WebSocketClientHandler webSocketClientHandler;

    DatagramHandler(EventLoopGroup eventLoopGroup) throws SSLException {
        this.eventLoopGroup = eventLoopGroup;
        newWebSocketConnection();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof DatagramPacket packet) {
            // If the socket address is not set, set it to the sender of the packet and the UDP channel to the current channel.
            // This happens when the first packet is received on the UDP channel.
            if (socketAddress == null) {
                socketAddress = packet.sender();
                udpChannel = ctx.channel();
            } else if (!isInetSocketAddressEquals(socketAddress, packet.sender())) {
                // Check if using new protocol - new protocol supports multi-tunnel
                if (webSocketClientHandler.isUsingNewProtocol()) {
                    // New protocol: check if we already have a tunnel for this address
                    if (!addressToTunnelId.containsKey(packet.sender())) {
                        // Request a new tunnel from the server
                        log.info("Requesting new UDP tunnel for sender: {}", packet.sender());
                        webSocketClientHandler.requestNewTunnel();
                        // Queue this packet until tunnel is created
                        queuedFrames.add(createFrameWithTunnelId(packet.content().retain(), 0));
                        packet.release();
                        return;
                    }
                } else {
                    // Old protocol: send text frame to change route
                    webSocketClientHandler.newUdpConnection();
                    socketAddress = packet.sender();

                    // Wait for the WebSocket connection to finish authentication before sending queued frames.
                    webSocketClientHandler.authenticationFuture().addListener((ChannelFutureListener) future -> {
                        if (future.isSuccess()) {
                            if (log.isDebugEnabled()) {
                                log.debug("WebSocket connection authenticated successfully, sending queued frames");
                            }
                            while (!queuedFrames.isEmpty()) {
                                wsChannel.writeAndFlush(queuedFrames.poll());
                            }
                        } else {
                            log.error("Failed to authenticate WebSocket connection", future.cause());
                            retryManager.scheduleRetry(() -> {
                                try {
                                    newWebSocketConnection();
                                } catch (SSLException e) {
                                    log.error("Failed to create new WebSocket connection during retry", e);
                                    retryManager.scheduleRetry(() -> {
                                        try {
                                            newWebSocketConnection();
                                        } catch (SSLException ex) {
                                            log.error("Retry failed, giving up", ex);
                                        }
                                    }, eventLoopGroup.next());
                                }
                            }, eventLoopGroup.next());
                        }
                    });
                    packet.release();
                    return;
                }
            }

            // Create frame with tunnel ID if using new protocol
            BinaryWebSocketFrame binaryWebSocketFrame;
            if (webSocketClientHandler.isUsingNewProtocol()) {
                int tunnelId = addressToTunnelId.getOrDefault(packet.sender(), defaultTunnelId.get());
                binaryWebSocketFrame = createFrameWithTunnelId(packet.content().retain(), tunnelId);
            } else {
                binaryWebSocketFrame = new BinaryWebSocketFrame(packet.content().retain());
            }
            packet.release();

            // If the WebSocket channel is active and ready for write, send the frame directly.
            // Else add the frame to the queue.
            if (wsChannel != null && wsChannel.isActive() && webSocketClientHandler.isReadyForWrite()) {
                wsChannel.writeAndFlush(binaryWebSocketFrame);
            } else {
                queuedFrames.add(binaryWebSocketFrame);
            }
        } else {
            log.error("Unknown frame type: {}", msg.getClass().getName());

            // Release the message if it is a reference counted object
            if (msg instanceof ReferenceCounted referenceCounted) {
                referenceCounted.release();
            }
        }
    }

    /**
     * Write and flush a {@link DatagramPacket} to the UDP client.
     * This is kept for backward compatibility (old protocol).
     */
    void writeToUdpClient(ByteBuf byteBuf) {
        udpChannel.writeAndFlush(new DatagramPacket(byteBuf, socketAddress));
    }
    
    /**
     * Handle binary frame from WebSocket (new protocol with tunnel ID support).
     */
    void handleBinaryFrame(BinaryWebSocketFrame binaryWebSocketFrame) {
        if (webSocketClientHandler.isUsingNewProtocol()) {
            // New protocol: first byte is tunnel ID
            if (binaryWebSocketFrame.content().readableBytes() < 1) {
                log.warn("Received binary frame with no tunnel ID");
                binaryWebSocketFrame.release();
                return;
            }
            
            int tunnelId = binaryWebSocketFrame.content().readByte() & 0xFF;
            InetSocketAddress targetAddress = tunnelIdToAddress.get(tunnelId);
            
            if (targetAddress == null) {
                log.warn("Received data for unknown tunnel ID: {}", tunnelId);
                binaryWebSocketFrame.release();
                return;
            }
            
            // Send data without the tunnel ID byte
            if (udpChannel != null && udpChannel.isActive()) {
                udpChannel.writeAndFlush(new DatagramPacket(binaryWebSocketFrame.content().retain(), targetAddress));
            }
            binaryWebSocketFrame.release();
        } else {
            // Old protocol: no tunnel ID
            writeToUdpClient(binaryWebSocketFrame.content().retain());
            binaryWebSocketFrame.release();
        }
    }
    
    /**
     * Called when a new tunnel is created by the server.
     */
    void onTunnelCreated(int tunnelId) {
        if (defaultTunnelId.get() == 0) {
            // First tunnel - this is the default for the initial address
            defaultTunnelId.set(tunnelId);
            tunnelIdToAddress.put(tunnelId, socketAddress);
            addressToTunnelId.put(socketAddress, tunnelId);
            log.info("Default tunnel {} created for address: {}", tunnelId, socketAddress);
        } else {
            // Additional tunnel - this will be used for future packets
            log.info("Additional tunnel {} created", tunnelId);
            // The address will be associated when we receive packets from it
        }
    }
    
    /**
     * Called when the server closes a tunnel.
     */
    void onTunnelClosed(int tunnelId) {
        InetSocketAddress address = tunnelIdToAddress.remove(tunnelId);
        if (address != null) {
            addressToTunnelId.remove(address);
            log.info("Tunnel {} closed for address: {}", tunnelId, address);
        }
    }
    
    /**
     * Create a binary frame with tunnel ID prepended.
     */
    private BinaryWebSocketFrame createFrameWithTunnelId(ByteBuf content, int tunnelId) {
        ByteBuf frame = Unpooled.buffer(1 + content.readableBytes());
        frame.writeByte(tunnelId);
        frame.writeBytes(content);
        content.release();
        return new BinaryWebSocketFrame(frame);
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        // Flush pending writes for better batching
        ctx.flush();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        // Clean up any queued frames
        while (!queuedFrames.isEmpty()) {
            BinaryWebSocketFrame frame = queuedFrames.poll();
            if (frame != null) {
                frame.release();
            }
        }
        
        // Clear tunnel mappings
        tunnelIdToAddress.clear();
        addressToTunnelId.clear();
        defaultTunnelId.set(0);
        
        if (webSocketClientFuture != null) {
            webSocketClientFuture.channel().close();
        }
    }

    /**
     * Create a new WebSocket connection.
     * @throws SSLException if the SSL context cannot be created
     */
    private void newWebSocketConnection() throws SSLException {
        // If existing WebSocket channel exists, close it.
        if (wsChannel != null) {
            wsChannel.close();
        }

        webSocketClientFuture = new WebSocketClient().start(eventLoopGroup, this);

        // Wait for the WebSocket connection to be established before sending queued frames.
        webSocketClientFuture.addListener((ChannelFutureListener) future -> {

            // If the future is successful, set the WebSocket channel and WebSocket client handler.
            // If the future is not successful, log the error and retry.
            if (future.isSuccess()) {
                wsChannel = future.channel();
                webSocketClientHandler = wsChannel.pipeline().get(WebSocketClientHandler.class);
                
                // Reset retry counter on successful connection
                retryManager.reset();

                // Wait for the WebSocket connection to finish authentication before sending queued frames.
                webSocketClientHandler.authenticationFuture().addListener((ChannelFutureListener) handshakeFuture -> {

                    // If the authentication future is successful, send the queued frames.
                    // If the authentication future is not successful, log the error and retry.
                    if (handshakeFuture.isSuccess()) {
                        // Send queued frames
                        while (!queuedFrames.isEmpty()) {
                            wsChannel.writeAndFlush(queuedFrames.poll());
                        }

                        // Retry the WebSocket connection if it is closed unexpectedly.
                        wsChannel.closeFuture().addListener(closeFuture -> {
                            log.warn("WebSocket connection closed, will retry");
                            retryManager.scheduleRetry(() -> {
                                try {
                                    newWebSocketConnection();
                                } catch (SSLException e) {
                                    log.error("Failed to create new WebSocket connection during retry", e);
                                }
                            }, eventLoopGroup.next());
                        });
                    } else {
                        log.error("Failed to authenticate WebSocket connection", handshakeFuture.cause());
                        retryManager.scheduleRetry(() -> {
                            try {
                                newWebSocketConnection();
                            } catch (SSLException e) {
                                log.error("Failed to create new WebSocket connection during retry", e);
                            }
                        }, eventLoopGroup.next());
                    }
                });
            } else {
                log.error("Failed to connect to WebSocket server", future.cause());
                retryManager.scheduleRetry(() -> {
                    try {
                        newWebSocketConnection();
                    } catch (SSLException e) {
                        log.error("Failed to create new WebSocket connection during retry", e);
                    }
                }, eventLoopGroup.next());
            }
        });
    }

    public ChannelFuture webSocketClientFuture() {
        return webSocketClientFuture;
    }

    private static boolean isInetSocketAddressEquals(InetSocketAddress socketAddress1, InetSocketAddress socketAddress2) {
        return socketAddress1.getAddress().equals(socketAddress2.getAddress()) && socketAddress1.getPort() == socketAddress2.getPort();
    }

    public ChannelFuture close() {
        if (udpChannel != null) {
            return udpChannel.close();
        }
        return null;
    }
}
