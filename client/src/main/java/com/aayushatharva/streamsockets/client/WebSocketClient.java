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
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.ChannelFactory;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollSocketChannel;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import lombok.extern.log4j.Log4j2;

import javax.net.ssl.SSLException;
import java.net.URI;

import static com.aayushatharva.streamsockets.common.Utils.envValue;

@Log4j2
final class WebSocketClient {

    static {
        log.info("OpenSSL available: {}", OpenSsl.isAvailable());
    }

    ChannelFuture start(EventLoopGroup eventLoopGroup, DatagramHandler datagramHandler) throws SSLException {
        URI uri = URI.create(envValue("WEBSOCKET_URI", "ws://localhost:8080/tunnel"));

        SslContext sslContext = null;
        if (uri.getScheme().equals("wss")) {
            sslContext = SslContextBuilder.forClient()
                    .protocols("TLSv1.3", "TLSv1.2")
                    .sslProvider(OpenSsl.isAvailable() ? SslProvider.OPENSSL : SslProvider.JDK)
                    .build();
        }

        Bootstrap bootstrap = new Bootstrap()
                .group(eventLoopGroup)
                .channelFactory(channelFactory())
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.SO_KEEPALIVE, true)
                // Use pooled direct buffers for zero-copy I/O performance
                .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                // Conservative water marks for proxy: high watermark at 1MB to protect against slow upstream
                .option(ChannelOption.WRITE_BUFFER_WATER_MARK, new WriteBufferWaterMark(512 * 1024, 1024 * 1024))
                .handler(new WebSocketClientInitializer(datagramHandler, uri, sslContext));

        log.info("Connecting to WebSocketServer at {}:{}", uri.getHost(), uri.getPort());
        ChannelFuture channelFuture = bootstrap.connect(uri.getHost(), uri.getPort());

        channelFuture.addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                log.info("WebSocketClient connected to {}", future.channel().remoteAddress());
            } else {
                log.error("WebSocketClient failed to connect to {}", uri, future.cause());
            }
        });

        channelFuture.channel().closeFuture().addListener((ChannelFutureListener) future -> {
            log.info("WebSocketClient disconnected from {}", future.channel().remoteAddress());
            ChannelFuture datagramCloseFuture = datagramHandler.close();
            if (datagramCloseFuture != null) {
                datagramCloseFuture.addListener((ChannelFutureListener) datagramFuture -> {
                    if (datagramFuture.isSuccess()) {
                        log.info("DatagramHandler closed successfully");
                    } else {
                        log.error("DatagramHandler failed to close", datagramFuture.cause());
                    }
                    eventLoopGroup.shutdownGracefully();
                });
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
