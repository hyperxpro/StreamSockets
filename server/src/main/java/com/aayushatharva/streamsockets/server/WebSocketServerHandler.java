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
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFactory;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollDatagramChannel;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCounted;
import lombok.extern.log4j.Log4j2;

import java.net.InetSocketAddress;

@Log4j2
final class WebSocketServerHandler extends ChannelInboundHandlerAdapter {

    static final AttributeKey<String> ROUTE_ATTR = AttributeKey.valueOf("route");
    private static final Bootstrap UDP_BOOTSTRAP = new Bootstrap().channelFactory(channelFactory());

    private final TokenAuthentication tokenAuthentication;
    private InetSocketAddress socketAddress;
    private Channel udpChannel;
    private boolean connectionEstablished = false;

    WebSocketServerHandler(TokenAuthentication tokenAuthentication) {
        this.tokenAuthentication = tokenAuthentication;
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        // When WebSocket handshake is complete, establish UDP connection
        if (evt instanceof WebSocketServerProtocolHandler.HandshakeComplete && !connectionEstablished) {
            connectionEstablished = true;
            String route = ctx.channel().attr(ROUTE_ATTR).get();
            
            if (route == null || route.isEmpty()) {
                log.error("Route not found in channel attributes");
                ctx.close();
                return;
            }

            // Parse route (format: "address:port")
            try {
                String[] parts = route.split(":");
                String address = parts[0];
                int port = Integer.parseInt(parts[1]);
                socketAddress = new InetSocketAddress(address, port);
            } catch (Exception e) {
                log.error("Invalid route format: {}", route, e);
                ctx.close();
                return;
            }

            // Connect to remote server
            connectToRemote(ctx).addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    log.info("{} connected to remote server: {}", ctx.channel().remoteAddress(), socketAddress);
                    udpChannel = future.channel();

                    // If the WebSocket connection is closed, close the UDP channel
                    ctx.channel().closeFuture().addListener((ChannelFutureListener) future1 -> {
                        log.info("{} disconnected from remote server: {}", ctx.channel().remoteAddress(), socketAddress);
                        udpChannel.close();
                    });
                } else {
                    log.error("{} failed to connect to remote server: {}", ctx.channel().remoteAddress(), socketAddress, future.cause());
                    ctx.close();
                }
            });
        }
        super.userEventTriggered(ctx, evt);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof BinaryWebSocketFrame binaryWebSocketFrame) {
            // Check if UDP channel is writable before sending to prevent buffer bloat
            if (udpChannel != null && udpChannel.isWritable()) {
                // Retain the content since it will be used by DatagramPacket
                udpChannel.writeAndFlush(new DatagramPacket(binaryWebSocketFrame.content().retain(), socketAddress));
            } else {
                log.warn("UDP channel not writable, dropping packet");
            }
            binaryWebSocketFrame.release();
        } else {
            log.error("Unknown frame type: {}", msg.getClass().getName());

            // Release the message if it is a reference counted object
            if (msg instanceof ReferenceCounted referenceCounted) {
                referenceCounted.release();
            }
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.error("WebSocketServerHandler exception", cause);
    }

    private ChannelFuture connectToRemote(ChannelHandlerContext ctx) {
        return UDP_BOOTSTRAP.clone()
                .group(ctx.channel().eventLoop())
                .handler(new DownstreamHandler(ctx.channel()))
                .connect(socketAddress);
    }

    private static ChannelFactory<DatagramChannel> channelFactory() {
        if (Epoll.isAvailable()) {
            return EpollDatagramChannel::new;
        } else {
            return NioDatagramChannel::new;
        }
    }
}
