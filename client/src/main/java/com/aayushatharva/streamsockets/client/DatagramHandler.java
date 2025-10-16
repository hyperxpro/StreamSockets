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

import javax.net.ssl.SSLException;
import java.net.InetSocketAddress;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class receives {@link DatagramPacket} from the UDP client and sends them to the WebSocket server.
 */
@Log4j2
@ChannelHandler.Sharable
public final class DatagramHandler extends ChannelInboundHandlerAdapter {

    private static final int MAX_RECONNECT_ATTEMPTS = 5;
    private static final int INITIAL_RECONNECT_DELAY_MS = 1000;
    
    // ArrayDeque is faster than ConcurrentLinkedQueue since we access it only from event loop thread
    private final Queue<BinaryWebSocketFrame> queuedFrames = new ArrayDeque<>();
    private final EventLoopGroup eventLoopGroup;
    private final AtomicInteger reconnectAttempts = new AtomicInteger(0);

    private InetSocketAddress socketAddress;
    private Channel udpChannel;
    private Channel wsChannel;
    private ChannelFuture webSocketClientFuture;
    private WebSocketClientHandler webSocketClientHandler;
    private volatile boolean shutdown = false;

    DatagramHandler(EventLoopGroup eventLoopGroup) throws SSLException {
        this.eventLoopGroup = eventLoopGroup;
        newWebSocketConnection();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof DatagramPacket packet) {
            // If the socket address is not set, set it to the sender of the packet and the UDP channel to the current channel.
            // This happens when the first packet is received on the UDP channel.
            // If the sender of the packet is different from the current socket address, reconnect WebSocket
            // This happens when the client creates new connections to the UDP server.
            if (socketAddress == null) {
                socketAddress = packet.sender();
                udpChannel = ctx.channel();
            } else if (!isInetSocketAddressEquals(socketAddress, packet.sender())) {
                socketAddress = packet.sender();
                
                // Reconnect to get a new route/connection
                reconnectWebSocket();

                // Wait for the WebSocket connection to finish handshake before sending queued frames.
                if (webSocketClientHandler != null) {
                    webSocketClientHandler.handshakeFuture().addListener((ChannelFutureListener) future -> {
                        if (future.isSuccess()) {
                            log.debug("WebSocket connection established successfully, sending queued frames");

                            // Send queued frames
                            while (!queuedFrames.isEmpty()) {
                                wsChannel.writeAndFlush(queuedFrames.poll());
                            }
                        } else {
                            log.error("Failed to establish WebSocket connection", future.cause());
                            // Queue will be processed when connection is re-established
                        }
                    });
                }
            }

            BinaryWebSocketFrame binaryWebSocketFrame = new BinaryWebSocketFrame(packet.content().retain());
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
     */
    void writeToUdpClient(ByteBuf byteBuf) {
        udpChannel.writeAndFlush(new DatagramPacket(byteBuf, socketAddress));
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        shutdown = true;
        releaseQueuedFrames();
        if (webSocketClientFuture != null) {
            webSocketClientFuture.channel().close();
        }
    }

    /**
     * Release all queued frames to prevent memory leak
     */
    private void releaseQueuedFrames() {
        BinaryWebSocketFrame frame;
        while ((frame = queuedFrames.poll()) != null) {
            frame.release();
        }
    }

    /**
     * Reconnect WebSocket with exponential backoff
     */
    private void reconnectWebSocket() {
        if (shutdown) {
            return;
        }

        int attempts = reconnectAttempts.incrementAndGet();
        if (attempts > MAX_RECONNECT_ATTEMPTS) {
            log.error("Max reconnection attempts ({}) reached, giving up", MAX_RECONNECT_ATTEMPTS);
            reconnectAttempts.set(0); // Reset for next time
            return;
        }

        int delay = INITIAL_RECONNECT_DELAY_MS * (1 << (attempts - 1)); // Exponential backoff
        log.info("Scheduling WebSocket reconnection attempt {} in {}ms", attempts, delay);

        eventLoopGroup.schedule(() -> {
            try {
                newWebSocketConnection();
            } catch (SSLException e) {
                log.error("Failed to reconnect WebSocket, attempt {}/{}", attempts, MAX_RECONNECT_ATTEMPTS, e);
                // Will retry on next packet or connection close
            }
        }, delay, TimeUnit.MILLISECONDS);
    }

    /**
     * Create a new WebSocket connection.
     * @throws SSLException if the SSL context cannot be created
     */
    private void newWebSocketConnection() throws SSLException {
        if (shutdown) {
            return;
        }

        // If existing WebSocket channel exists, close it.
        if (wsChannel != null) {
            wsChannel.close();
        }

        webSocketClientFuture = new WebSocketClient().start(eventLoopGroup, this);

        // Wait for the WebSocket connection to be established before sending queued frames.
        webSocketClientFuture.addListener((ChannelFutureListener) future -> {

            // If the future is successful, set the WebSocket channel and WebSocket client handler.
            if (future.isSuccess()) {
                wsChannel = future.channel();
                webSocketClientHandler = wsChannel.pipeline().get(WebSocketClientHandler.class);

                // Wait for the WebSocket handshake to complete before sending queued frames.
                webSocketClientHandler.handshakeFuture().addListener((ChannelFutureListener) handshakeFuture -> {

                    if (handshakeFuture.isSuccess()) {
                        // Reset reconnect attempts on successful connection
                        reconnectAttempts.set(0);
                        
                        // Send queued frames
                        while (!queuedFrames.isEmpty()) {
                            wsChannel.writeAndFlush(queuedFrames.poll());
                        }

                        // Retry the WebSocket connection if it is closed unexpectedly.
                        wsChannel.closeFuture().addListener(closeFuture -> {
                            if (!shutdown) {
                                log.warn("WebSocket connection closed unexpectedly, will reconnect");
                                reconnectWebSocket();
                            }
                        });
                    } else {
                        log.error("Failed to complete WebSocket handshake", handshakeFuture.cause());
                        reconnectWebSocket();
                    }
                });
            } else {
                log.error("Failed to connect to WebSocket server", future.cause());
                reconnectWebSocket();
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
