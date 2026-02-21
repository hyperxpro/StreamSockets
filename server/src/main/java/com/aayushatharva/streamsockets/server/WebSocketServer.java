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
import io.netty.channel.IoHandlerFactory;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollIoHandler;
import io.netty.channel.epoll.EpollServerSocketChannel;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.ServerSocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.uring.IoUring;
import io.netty.channel.uring.IoUringIoHandler;
import io.netty.channel.uring.IoUringServerSocketChannel;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.aayushatharva.streamsockets.common.Utils.envValue;
import static com.aayushatharva.streamsockets.common.Utils.envValueAsInt;
import static com.aayushatharva.streamsockets.common.Utils.isIOUringDisabled;
import static io.netty.buffer.PooledByteBufAllocator.*;

public final class WebSocketServer {

    private static final Logger logger = LogManager.getLogger();

    private static boolean isIOUringAvailable() {
        return !isIOUringDisabled() && IoUring.isAvailable();
    }

    static {
        logger.info("Epoll available: {}", Epoll.isAvailable());
        logger.info("IoUring available: {}", IoUring.isAvailable());
        if (isIOUringDisabled()) {
            logger.info("IOUring disabled via DISABLE_IOURING environment variable");
        }

        if (isIOUringAvailable()) {
            logger.info("Using IOUring for high-performance I/O");
        } else if (Epoll.isAvailable()) {
            logger.info("Using Epoll for high-performance I/O");
        } else {
            logger.info("Using NIO (consider using Linux with Epoll for better performance)");
        }
    }

    @Getter
    private final EventLoopGroup parentGroup = eventLoopGroup(envValueAsInt("PARENT_THREADS", Runtime.getRuntime().availableProcessors()));

    @Getter
    private final EventLoopGroup childGroup = eventLoopGroup(envValueAsInt("CHILD_THREADS", Runtime.getRuntime().availableProcessors()));
    private ChannelFuture channelFuture;
    private ScheduledExecutorService reloadScheduler;

    public void start() {
        TokenAuthentication tokenAuthentication = new TokenAuthentication(envValue("ACCOUNTS_CONFIG_FILE", "accounts.yaml"));
        start(tokenAuthentication);

        // Schedule periodic account file reload
        int reloadIntervalSeconds = envValueAsInt("ACCOUNTS_RELOAD_INTERVAL_SECONDS", 15);
        if (reloadIntervalSeconds > 0) {
            reloadScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "accounts-reload");
                t.setDaemon(true);
                return t;
            });
            reloadScheduler.scheduleAtFixedRate(tokenAuthentication::reload,
                    reloadIntervalSeconds, reloadIntervalSeconds, TimeUnit.SECONDS);
            logger.info("Scheduled account file reload every {} seconds", reloadIntervalSeconds);
        }
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
                .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK, new WriteBufferWaterMark(32 * 1024, 64 * 1024))
                .childOption(ChannelOption.ALLOCATOR, DEFAULT);

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
        IoHandlerFactory ioHandlerFactory;

        if (isIOUringAvailable()) {
            ioHandlerFactory = IoUringIoHandler.newFactory();
        } else if (Epoll.isAvailable()) {
            ioHandlerFactory = EpollIoHandler.newFactory();
        } else {
            ioHandlerFactory = NioIoHandler.newFactory();
        }

        return new MultiThreadIoEventLoopGroup(threads, ioHandlerFactory);
    }

    private static ChannelFactory<ServerSocketChannel> channelFactory() {
        if (isIOUringAvailable()) {
            return IoUringServerSocketChannel::new;
        } else if (Epoll.isAvailable()) {
            return EpollServerSocketChannel::new;
        } else {
            return NioServerSocketChannel::new;
        }
    }

    public void stop() throws InterruptedException {
        if (reloadScheduler != null) {
            reloadScheduler.shutdown();
            reloadScheduler.awaitTermination(5, TimeUnit.SECONDS);
        }
        channelFuture.channel().close().sync();
        childGroup.shutdownGracefully();
        parentGroup.shutdownGracefully();

        logger.info("WebSocketServer stopped");
    }
}
