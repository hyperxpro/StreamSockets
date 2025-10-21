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

package com.aayushatharva.streamsockets.metrics;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFactory;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollServerSocketChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.ServerSocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.log4j.Log4j2;

import static lombok.AccessLevel.PRIVATE;

@Log4j2
@RequiredArgsConstructor
@FieldDefaults(level = PRIVATE)
public final class MetricsServer {

    final EventLoopGroup parentGroup;
    final EventLoopGroup childGroup;
    final String metricsPath;
    
    ChannelFuture channelFuture;

    public void start(String bindAddress, int bindPort) {
        ServerBootstrap serverBootstrap = new ServerBootstrap()
                .group(parentGroup, childGroup)
                .channelFactory(channelFactory())
                .childHandler(new MetricsServerInitializer(metricsPath))
                .option(ChannelOption.SO_BACKLOG, 128)
                .option(ChannelOption.SO_REUSEADDR, true);

        channelFuture = serverBootstrap.bind(bindAddress, bindPort);
        channelFuture.addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                log.info("MetricsServer started on {}", future.channel().localAddress());
            } else {
                log.error("MetricsServer failed to start on {}:{}", bindAddress, bindPort, future.cause());
            }
        });
    }

    private static ChannelFactory<ServerSocketChannel> channelFactory() {
        if (Epoll.isAvailable()) {
            return EpollServerSocketChannel::new;
        } else {
            return NioServerSocketChannel::new;
        }
    }

    public void stop() throws InterruptedException {
        if (channelFuture != null) {
            channelFuture.channel().close().sync();
        }
        log.info("MetricsServer stopped");
    }
}
