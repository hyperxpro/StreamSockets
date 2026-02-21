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
import io.netty.channel.IoHandlerFactory;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollDatagramChannel;
import io.netty.channel.epoll.EpollIoHandler;
import io.netty.channel.epoll.EpollServerSocketChannel;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.unix.UnixChannelOption;
import io.netty.channel.uring.IoUring;
import io.netty.channel.uring.IoUringDatagramChannel;
import io.netty.channel.uring.IoUringIoHandler;
import io.netty.channel.uring.IoUringServerSocketChannel;
import lombok.extern.log4j.Log4j2;

import javax.net.ssl.SSLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.aayushatharva.streamsockets.common.Utils.envValue;
import static com.aayushatharva.streamsockets.common.Utils.envValueAsInt;
import static com.aayushatharva.streamsockets.common.Utils.isIOUringDisabled;

@Log4j2
public final class UdpServer {

    private static boolean isIOUringAvailable() {
        return !isIOUringDisabled() && IoUring.isAvailable();
    }

    static {
        log.info("Epoll available: {}", Epoll.isAvailable());
        log.info("IoUring available: {}", IoUring.isAvailable());
        if (isIOUringDisabled()) {
            log.info("IOUring disabled via DISABLE_IOURING environment variable");
        }

        if (isIOUringAvailable()) {
            log.info("Using IOUring for high-performance I/O");
        } else if (Epoll.isAvailable()) {
            log.info("Using Epoll for high-performance I/O");
        } else {
            log.info("Using NIO (consider using Linux with Epoll for better performance)");
        }
    }

    private EventLoopGroup eventLoopGroup;
    private List<ChannelFuture> channelFutures;
    private DatagramHandler datagramHandler;

    public void start() throws SSLException {
        // Determine if we can use SO_REUSEPORT (IoUring or Epoll supports it)
        boolean canUseReusePort = isIOUringAvailable() || Epoll.isAvailable();
        int threads = envValueAsInt("THREADS", canUseReusePort ? Runtime.getRuntime().availableProcessors() * 2 : 1);
        
        eventLoopGroup = eventLoopGroup(threads);
        datagramHandler = new DatagramHandler(eventLoopGroup);

        Bootstrap bootstrap = new Bootstrap()
                .group(eventLoopGroup)
                .channelFactory(channelFactory())
                .option(ChannelOption.SO_RCVBUF, 1048576)
                .option(ChannelOption.SO_SNDBUF, 1048576)
                .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                .handler(datagramHandler);

        AtomicBoolean reusePort = new AtomicBoolean(false);
        if (isIOUringAvailable() || Epoll.isAvailable()) {
            bootstrap.option(UnixChannelOption.SO_REUSEPORT, true);
            reusePort.set(true);
        }

        String bindAddress = envValue("BIND_ADDRESS", "0.0.0.0");
        int bindPort = envValueAsInt("BIND_PORT", 9000);

        channelFutures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            ChannelFuture channelFuture = bootstrap.bind(bindAddress, bindPort).addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    if (reusePort.get()) {
                        log.info("UDP Server started on address {} with SO_REUSEPORT", future.channel().localAddress());
                    } else {
                        log.info("UDP Server started on address {}", future.channel().localAddress());
                    }
                } else {
                    log.error("UDP Server failed to start on address {}", future.channel().localAddress(), future.cause());
                }
            });

            channelFutures.add(channelFuture);
        }
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

    private static ChannelFactory<DatagramChannel> channelFactory() {
        if (isIOUringAvailable()) {
            return IoUringDatagramChannel::new;
        } else if (Epoll.isAvailable()) {
            return EpollDatagramChannel::new;
        } else {
            return NioDatagramChannel::new;
        }
    }

    public void stop() throws InterruptedException {
        for (ChannelFuture future : channelFutures) {
            future.channel().close().sync();
        }

        eventLoopGroup.shutdownGracefully();
        log.info("UDP Server stopped");
    }

    public List<ChannelFuture> channelFutures() {
        return Collections.unmodifiableList(channelFutures);
    }

    public DatagramHandler datagramHandler() {
        return datagramHandler;
    }
}
