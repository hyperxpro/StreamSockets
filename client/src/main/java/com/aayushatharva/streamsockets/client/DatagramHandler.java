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
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * This class receives {@link DatagramPacket} from the UDP client and sends them to the WebSocket server.
 */
@Log4j2
@ChannelHandler.Sharable
public final class DatagramHandler extends ChannelInboundHandlerAdapter {

    private final Queue<BinaryWebSocketFrame> queuedFrames = new ConcurrentLinkedQueue<>();
    private final EventLoopGroup eventLoopGroup;

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
            // If the sender of the packet is different from the current socket address, reconnect WebSocket
            // This happens when the client creates new connections to the UDP server.
            if (socketAddress == null) {
                socketAddress = packet.sender();
                udpChannel = ctx.channel();
            } else if (!isInetSocketAddressEquals(socketAddress, packet.sender())) {
                socketAddress = packet.sender();
                
                // Reconnect to get a new route/connection
                try {
                    newWebSocketConnection();
                } catch (SSLException e) {
                    log.error("Failed to create new WebSocket connection", e);
                    System.exit(1);
                }

                // Wait for the WebSocket connection to finish handshake before sending queued frames.
                webSocketClientHandler.handshakeFuture().addListener((ChannelFutureListener) future -> {

                    // If the future is successful, send the queued frames.
                    // if the future is not successful, log the error and exit the JVM.
                    if (future.isSuccess()) {
                        log.debug("WebSocket connection established successfully, sending queued frames");

                        // Send queued frames
                        while (!queuedFrames.isEmpty()) {
                            wsChannel.writeAndFlush(queuedFrames.poll());
                        }
                    } else {
                        log.error("Failed to establish WebSocket connection", future.cause());
                        System.exit(1);
                    }
                });
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
            // If the future is not successful, log the error and exit the JVM.
            if (future.isSuccess()) {
                wsChannel = future.channel();
                webSocketClientHandler = wsChannel.pipeline().get(WebSocketClientHandler.class);

                // Wait for the WebSocket handshake to complete before sending queued frames.
                webSocketClientHandler.handshakeFuture().addListener((ChannelFutureListener) handshakeFuture -> {

                    // If the handshake future is successful, send the queued frames.
                    // If the handshake future is not successful, log the error and exit the JVM.
                    if (handshakeFuture.isSuccess()) {
                        // Send queued frames
                        while (!queuedFrames.isEmpty()) {
                            wsChannel.writeAndFlush(queuedFrames.poll());
                        }

                        // Retry the WebSocket connection if it is closed unexpectedly.
                        wsChannel.closeFuture().addListener(closeFuture -> {
                            try {
                                newWebSocketConnection();
                            } catch (SSLException e) {
                                log.error("Failed to reconnect WebSocket", e);
                                System.exit(1);
                            }
                        });
                    } else {
                        log.error("Failed to complete WebSocket handshake", handshakeFuture.cause());
                        System.exit(1);
                    }
                });
            } else {
                log.error("Failed to connect to WebSocket server", future.cause());
                System.exit(1);
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
