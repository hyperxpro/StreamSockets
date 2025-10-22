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
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFactory;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.epoll.EpollServerSocketChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.ServerSocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static com.aayushatharva.streamsockets.common.Utils.envValue;
import static com.aayushatharva.streamsockets.common.Utils.envValueAsInt;

public final class WebSocketServer {

    private static final Logger logger = LogManager.getLogger();

    private final EventLoopGroup parentGroup = eventLoopGroup(envValueAsInt("PARENT_THREADS", Runtime.getRuntime().availableProcessors()));
    private final EventLoopGroup childGroup = eventLoopGroup(envValueAsInt("CHILD_THREADS", Runtime.getRuntime().availableProcessors()));
    private ChannelFuture channelFuture;

    public EventLoopGroup getParentGroup() {
        return parentGroup;
    }

    public EventLoopGroup getChildGroup() {
        return childGroup;
    }

    public void start() {
        TokenAuthentication tokenAuthentication = new TokenAuthentication(envValue("ACCOUNTS_CONFIG_FILE", "accounts.yaml"));
        start(tokenAuthentication);
    }

    public void start(TokenAuthentication tokenAuthentication) {
        ServerBootstrap serverBootstrap = new ServerBootstrap()
                .group(parentGroup, childGroup)
                .channelFactory(channelFactory())
                .childHandler(new WebSocketServerInitializer(tokenAuthentication))
                .option(ChannelOption.SO_BACKLOG, 1024)
                .option(ChannelOption.SO_REUSEADDR, true)
                .childOption(ChannelOption.TCP_NODELAY, true)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .childOption(ChannelOption.SO_RCVBUF, 65536)
                .childOption(ChannelOption.SO_SNDBUF, 65536)
                .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK, new io.netty.channel.WriteBufferWaterMark(32 * 1024, 64 * 1024))
                .childOption(ChannelOption.ALLOCATOR, io.netty.buffer.PooledByteBufAllocator.DEFAULT);

        String bindAddress = envValue("BIND_ADDRESS", "0.0.0.0");
        int bindPort = envValueAsInt("BIND_PORT", 8080);

        channelFuture = serverBootstrap.bind(bindAddress, bindPort);
        channelFuture.addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                logger.info("WebSocketServer started on {}", future.channel().localAddress());
            } else {
                logger.error("WebSocketServer failed to start on {}", future.channel().localAddress(), future.cause());
            }
        });
    }

    private static EventLoopGroup eventLoopGroup(int threads) {
        if (Epoll.isAvailable()) {
            return new EpollEventLoopGroup(threads);
        } else {
            return new NioEventLoopGroup(threads);
        }
    }

    private static ChannelFactory<ServerSocketChannel> channelFactory() {
        if (Epoll.isAvailable()) {
            return EpollServerSocketChannel::new;
        } else {
            return NioServerSocketChannel::new;
        }
    }

    public void stop() throws InterruptedException {
        channelFuture.channel().close().sync();
        childGroup.shutdownGracefully();
        parentGroup.shutdownGracefully();

        logger.info("WebSocketServer stopped");
    }
}
