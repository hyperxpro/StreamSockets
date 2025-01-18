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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.util.ReferenceCounted;
import lombok.extern.log4j.Log4j2;

import java.net.InetSocketAddress;

import static io.netty.channel.ChannelFutureListener.CLOSE;

@Log4j2
final class WebSocketServerHandler extends ChannelInboundHandlerAdapter {

    private InetSocketAddress socketAddress;
    private Channel channel;

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof TextWebSocketFrame textWebSocketFrame) {

            // Check if already connected to a remote server
            if (socketAddress != null) {
                log.warn("{} already connected to a remote server: {}", ctx.channel().remoteAddress(), socketAddress);

                JsonObject responseJson = new JsonObject();
                responseJson.addProperty("success", false);
                responseJson.addProperty("message", "Already connected to a remote server");

                ctx.writeAndFlush(new TextWebSocketFrame(responseJson.toString())).addListener(CLOSE);
                return;
            }

            // Validate address and port
            try {
                JsonObject requestJson = JsonParser.parseString(textWebSocketFrame.text()).getAsJsonObject();
                socketAddress = new InetSocketAddress(requestJson.get("address").getAsString(), requestJson.get("port").getAsInt());
            } catch (Exception e) {
                JsonObject responseJson = new JsonObject();
                responseJson.addProperty("success", false);
                responseJson.addProperty("message", "Invalid address or port");

                ctx.writeAndFlush(new TextWebSocketFrame(responseJson.toString())).addListener(CLOSE);
                return;
            }

            // Connect to remote server and send response
            connectToRemote(ctx).addListener((ChannelFutureListener) future -> {

                JsonObject responseJson = new JsonObject();
                if (future.isSuccess()) {
                    log.info("{} connected to remote server: {}", ctx.channel().remoteAddress(), socketAddress);

                    channel = future.channel();
                    responseJson.addProperty("success", true);
                    responseJson.addProperty("message", "connected");
                    ctx.writeAndFlush(new TextWebSocketFrame(responseJson.toString()));
                } else {
                    log.error("{} failed to connect to remote server: {}", ctx.channel().remoteAddress(), socketAddress);

                    responseJson.addProperty("status", "failed");
                    responseJson.addProperty("message", future.cause().getMessage());

                    ctx.writeAndFlush(new TextWebSocketFrame(responseJson.toString())).addListener(CLOSE);
                }
            });
        } else if (msg instanceof BinaryWebSocketFrame binaryWebSocketFrame) {
            channel.writeAndFlush(new DatagramPacket(binaryWebSocketFrame.content(), socketAddress));
        } else if (msg instanceof PingWebSocketFrame pingWebSocketFrame) {
            ctx.writeAndFlush(pingWebSocketFrame);
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
        Bootstrap bootstrap = new Bootstrap()
                .group(ctx.channel().eventLoop())
                .channelFactory(channelFactory())
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
