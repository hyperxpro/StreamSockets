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

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFactory;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollSocketChannel;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.websocketx.WebSocketClientHandshaker;
import lombok.extern.log4j.Log4j2;

import java.net.URI;

import static com.aayushatharva.streamsockets.common.Utils.envValue;

@Log4j2
final class WebSocketClient {

    ChannelFuture start(EventLoopGroup eventLoopGroup, DatagramHandler datagramHandler) {
        URI uri = URI.create(envValue("WEBSOCKET_URI", "ws://localhost:8080/tunnel"));

        Bootstrap bootstrap = new Bootstrap()
                .group(eventLoopGroup)
                .channelFactory(channelFactory())
                .option(ChannelOption.TCP_NODELAY, true)
                .handler(new WebSocketClientInitializer(datagramHandler, uri));

        log.info("Connecting to WebSocketServer at {}:{}", uri.getHost(), uri.getPort());
        ChannelFuture channelFuture = bootstrap.connect(uri.getHost(), uri.getPort());

        channelFuture.addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                log.info("WebSocketClient connected to {}", future.channel().remoteAddress());
            } else {
                log.error("WebSocketClient failed to connect to {}", uri, future.cause());
            }
        });

        return channelFuture;
    }

    private static ChannelFactory<SocketChannel> channelFactory() {
        if (Epoll.isAvailable()) {
            return EpollSocketChannel::new;
        } else {
            return NioSocketChannel::new;
        }
    }
}
