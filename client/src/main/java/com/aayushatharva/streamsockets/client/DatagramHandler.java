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
            // If the socket address is not set, set it to the sender of the packet
            if (socketAddress == null) {
                socketAddress = packet.sender();
                udpChannel = ctx.channel();
            } else if (!socketAddress.equals(packet.sender())) {
                webSocketClientHandler.newUdpConnection(ctx);
                socketAddress = packet.sender();

                webSocketClientHandler.authenticationFuture().addListener((ChannelFutureListener) future -> {
                    if (future.isSuccess()) {
                        // Send queued frames
                        while (!queuedFrames.isEmpty()) {
                            wsChannel.writeAndFlush(queuedFrames.poll());
                        }
                    }
                });
            }

            BinaryWebSocketFrame binaryWebSocketFrame = new BinaryWebSocketFrame(packet.content().retain());
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
    public void writeToClient(ByteBuf byteBuf) {
        udpChannel.writeAndFlush(new DatagramPacket(byteBuf, socketAddress));
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (webSocketClientFuture != null) {
            webSocketClientFuture.channel().close();
        }
    }

    private void newWebSocketConnection() throws SSLException {
        if (wsChannel != null) {
            wsChannel.close();
        }

        webSocketClientFuture = new WebSocketClient().start(eventLoopGroup, this);
        webSocketClientFuture.addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                wsChannel = future.channel();
                webSocketClientHandler = wsChannel.pipeline().get(WebSocketClientHandler.class);

                webSocketClientHandler.authenticationFuture().addListener((ChannelFutureListener) handshakeFuture -> {
                    if (handshakeFuture.isSuccess()) {
                        // Send queued frames
                        while (!queuedFrames.isEmpty()) {
                            wsChannel.writeAndFlush(queuedFrames.poll());
                        }

                        // Retry next connection when the current connection closes
                        wsChannel.closeFuture().addListener(closeFuture -> newWebSocketConnection());
                    }
                });
            }
        });
    }

    public ChannelFuture webSocketClientFuture() {
        return webSocketClientFuture;
    }
}
