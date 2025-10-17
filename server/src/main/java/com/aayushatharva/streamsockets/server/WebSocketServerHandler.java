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
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.PooledByteBufAllocator;
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
import lombok.extern.log4j.Log4j2;

import java.net.InetSocketAddress;

import static io.netty.channel.ChannelFutureListener.CLOSE;

@Log4j2
final class WebSocketServerHandler extends ChannelInboundHandlerAdapter {

    // Reuse Gson instance for better performance
    private static final Gson GSON = new Gson();
    
    // AttributeKeys for reading protocol information
    private static final AttributeKey<Boolean> NEW_PROTOCOL_KEY = AttributeKey.valueOf("newProtocol");
    private static final AttributeKey<String> ROUTE_ADDRESS_KEY = AttributeKey.valueOf("routeAddress");
    private static final AttributeKey<String> ROUTE_PORT_KEY = AttributeKey.valueOf("routePort");
    
    private final TokenAuthentication tokenAuthentication;
    private InetSocketAddress socketAddress;
    private Channel udpChannel;
    private String routeCache; // Cache the route string to avoid repeated concatenation
    private boolean newProtocol; // Flag to track which protocol version client is using

    WebSocketServerHandler(TokenAuthentication tokenAuthentication, boolean newProtocol) {
        this.tokenAuthentication = tokenAuthentication;
        this.newProtocol = newProtocol;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        // Check for new protocol from channel attributes
        Boolean newProtocolAttr = ctx.channel().attr(NEW_PROTOCOL_KEY).get();
        if (newProtocolAttr != null) {
            newProtocol = newProtocolAttr;
            log.info("{} channel active with new protocol: {}", ctx.channel().remoteAddress(), newProtocol);
        }
        
        // If using new protocol, establish connection immediately using headers
        if (newProtocol) {
            String address = ctx.channel().attr(ROUTE_ADDRESS_KEY).get();
            String portStr = ctx.channel().attr(ROUTE_PORT_KEY).get();
            
            try {
                int port = Integer.parseInt(portStr);
                socketAddress = new InetSocketAddress(address, port);
                routeCache = address + ':' + port;

                // Check if the route is allowed
                if (!tokenAuthentication.containsRoute(routeCache)) {
                    log.error("{} attempted to connect to unauthorized route: {}", ctx.channel().remoteAddress(), routeCache);
                    ctx.close();
                    return;
                }

                // Connect to remote server immediately
                ChannelFuture connectFuture = connectToRemote(ctx);
                
                // For UDP, connect() should complete almost immediately
                if (connectFuture.isDone()) {
                    if (connectFuture.isSuccess()) {
                        log.info("{} connected to remote server: {} (new protocol)", ctx.channel().remoteAddress(), socketAddress);
                        udpChannel = connectFuture.channel();

                        // If the WebSocket connection is closed, close the UDP channel
                        ctx.channel().closeFuture().addListener((ChannelFutureListener) future1 -> {
                            log.info("{} disconnected from remote server: {}", ctx.channel().remoteAddress(), socketAddress);
                            udpChannel.close();
                        });
                    } else {
                        log.error("{} failed to connect to remote server: {} (new protocol), cause: {}", 
                                ctx.channel().remoteAddress(), socketAddress, connectFuture.cause());
                        ctx.close();
                    }
                } else {
                    // Add listener for async completion
                    connectFuture.addListener((ChannelFutureListener) future -> {
                        if (future.isSuccess()) {
                            log.info("{} connected to remote server: {} (new protocol)", ctx.channel().remoteAddress(), socketAddress);
                            udpChannel = future.channel();

                            // If the WebSocket connection is closed, close the UDP channel
                            ctx.channel().closeFuture().addListener((ChannelFutureListener) future1 -> {
                                log.info("{} disconnected from remote server: {}", ctx.channel().remoteAddress(), socketAddress);
                                udpChannel.close();
                            });
                        } else {
                            log.error("{} failed to connect to remote server: {} (new protocol), cause: {}", 
                                    ctx.channel().remoteAddress(), socketAddress, future.cause());
                            ctx.close();
                        }
                    });
                }
            } catch (Exception e) {
                log.error("{} invalid route parameters: address={}, port={}", ctx.channel().remoteAddress(), address, portStr);
                ctx.close();
            }
        }
        
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
                // New protocol: text frames are not expected, ignore or log
                log.warn("{} received unexpected text frame with new protocol", ctx.channel().remoteAddress());
                textWebSocketFrame.release();
            }
        } else if (msg instanceof BinaryWebSocketFrame binaryWebSocketFrame) {
            // Check if udpChannel and socketAddress are ready
            if (udpChannel != null && socketAddress != null) {
                // Retain content since it's being passed to another channel
                udpChannel.writeAndFlush(new DatagramPacket(binaryWebSocketFrame.content().retain(), socketAddress));
            } else {
                log.warn("{} received binary frame before UDP connection is established", ctx.channel().remoteAddress());
                binaryWebSocketFrame.release();
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
            JsonObject requestJson = JsonParser.parseString(textWebSocketFrame.text()).getAsJsonObject();
            String address = requestJson.get("address").getAsString();
            int port = requestJson.get("port").getAsInt();
            socketAddress = new InetSocketAddress(address, port);

            // Cache the route string for reuse
            routeCache = address + ':' + port;

            // Check if the route is allowed
            if (!tokenAuthentication.containsRoute(routeCache)) {
                JsonObject responseJson = new JsonObject();
                responseJson.addProperty("success", false);
                responseJson.addProperty("message", "Route is not allowed");
                ctx.writeAndFlush(new TextWebSocketFrame(GSON.toJson(responseJson))).addListener(CLOSE);
                return;
            }
        } catch (Exception e) {
            JsonObject responseJson = new JsonObject();
            responseJson.addProperty("success", false);
            responseJson.addProperty("message", "Invalid address or port");

            ctx.writeAndFlush(new TextWebSocketFrame(GSON.toJson(responseJson))).addListener(CLOSE);
            return;
        }

        // Connect to remote server and send response
        connectToRemote(ctx).addListener((ChannelFutureListener) future -> {
            JsonObject responseJson = new JsonObject();
            if (future.isSuccess()) {
                log.info("{} connected to remote server: {}", ctx.channel().remoteAddress(), socketAddress);

                udpChannel = future.channel();
                responseJson.addProperty("success", true);
                responseJson.addProperty("message", "connected");
                ctx.writeAndFlush(new TextWebSocketFrame(GSON.toJson(responseJson)));

                // If the WebSocket connection is closed, close the UDP channel
                ctx.channel().closeFuture().addListener((ChannelFutureListener) future1 -> {
                    log.info("{} disconnected from remote server: {}", ctx.channel().remoteAddress(), socketAddress);
                    udpChannel.close();
                });
            } else {
                log.error("{} failed to connect to remote server: {}", ctx.channel().remoteAddress(), socketAddress);

                responseJson.addProperty("status", "failed");
                responseJson.addProperty("message", future.cause().getMessage());

                ctx.writeAndFlush(new TextWebSocketFrame(GSON.toJson(responseJson))).addListener(CLOSE);
            }
        });
    }

    private ChannelFuture connectToRemote(ChannelHandlerContext ctx) {
        Bootstrap bootstrap = new Bootstrap()
                .group(ctx.channel().eventLoop())
                .channelFactory(channelFactory())
                .option(ChannelOption.SO_RCVBUF, 1048576)
                .option(ChannelOption.SO_SNDBUF, 1048576)
                .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                .handler(new DownstreamHandler(ctx.channel()));

        return bootstrap.connect(socketAddress);
    }

    private static ChannelFactory<DatagramChannel> channelFactory() {
        if (Epoll.isAvailable()) {
            return EpollDatagramChannel::new;
        } else {
            return NioDatagramChannel::new;
        }
    }
}
