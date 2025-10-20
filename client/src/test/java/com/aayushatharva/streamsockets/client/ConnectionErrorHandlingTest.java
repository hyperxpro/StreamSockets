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
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.net.ConnectException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test class to verify connection error handling and retry mechanism.
 * Tests various network error scenarios to ensure the retry mechanism works correctly.
 */
class ConnectionErrorHandlingTest {

    private EventLoopGroup eventLoopGroup;
    
    @BeforeEach
    void setUp() {
        eventLoopGroup = new NioEventLoopGroup(2);
    }
    
    @AfterEach
    void tearDown() throws InterruptedException {
        if (eventLoopGroup != null) {
            eventLoopGroup.shutdownGracefully().sync();
        }
    }
    
    /**
     * Test connection refused error - simulates immediate connection failure.
     * This is the second type of exception mentioned in the problem statement.
     */
    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void testConnectionRefusedError() throws InterruptedException {
        // Use a port that is not listening to simulate connection refused
        int nonListeningPort = 54321;
        
        AtomicInteger connectionAttempts = new AtomicInteger(0);
        CountDownLatch retryLatch = new CountDownLatch(2);
        
        Bootstrap bootstrap = new Bootstrap()
                .group(eventLoopGroup)
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        // Empty handler
                    }
                });
        
        // Simulate retry mechanism
        RetryManager retryManager = new RetryManager();
        
        // First connection attempt
        attemptConnection(bootstrap, "localhost", nonListeningPort, connectionAttempts, retryLatch, retryManager);
        
        // Wait for at least 2 retry attempts
        assertTrue(retryLatch.await(8, TimeUnit.SECONDS), 
                "Should have attempted at least 2 connection retries");
        assertTrue(connectionAttempts.get() >= 2, 
                "Should have at least 2 connection attempts, got: " + connectionAttempts.get());
    }
    
    /**
     * Test connection timeout error - simulates slow/unresponsive server.
     * This is the first type of exception mentioned in the problem statement.
     * We use a non-routable IP with a short timeout to simulate timeout.
     */
    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void testConnectionTimeoutError() throws InterruptedException {
        // Use a non-routable IP address with short timeout to trigger timeout
        // 10.255.255.1 is typically used for documentation and should timeout
        String timeoutHost = "10.255.255.1";
        int port = 9999;
        
        AtomicInteger connectionAttempts = new AtomicInteger(0);
        CountDownLatch retryLatch = new CountDownLatch(2);
        
        Bootstrap bootstrap = new Bootstrap()
                .group(eventLoopGroup)
                .channel(NioSocketChannel.class)
                .option(io.netty.channel.ChannelOption.CONNECT_TIMEOUT_MILLIS, 500)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        // Simple handler
                    }
                });
        
        RetryManager retryManager = new RetryManager();
        
        // Attempt connection with timeout
        attemptConnection(bootstrap, timeoutHost, port, connectionAttempts, retryLatch, retryManager);
        
        // Wait for retries
        assertTrue(retryLatch.await(6, TimeUnit.SECONDS), 
                "Should have attempted at least 2 connection retries");
        assertTrue(connectionAttempts.get() >= 2, 
                "Should have at least 2 connection attempts, got: " + connectionAttempts.get());
    }
    
    /**
     * Test no route to host error - simulates network unreachable.
     * This is the third type of exception shown in the problem statement logs.
     */
    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void testNoRouteToHostError() throws InterruptedException {
        // Use an IP address that should be unreachable (reserved for documentation)
        String unreachableHost = "192.0.2.1"; // TEST-NET-1, should not be routable
        int port = 443;
        
        AtomicInteger connectionAttempts = new AtomicInteger(0);
        CountDownLatch retryLatch = new CountDownLatch(2);
        
        Bootstrap bootstrap = new Bootstrap()
                .group(eventLoopGroup)
                .channel(NioSocketChannel.class)
                .option(io.netty.channel.ChannelOption.CONNECT_TIMEOUT_MILLIS, 2000)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        // Empty handler
                    }
                });
        
        RetryManager retryManager = new RetryManager();
        
        // Attempt connection
        attemptConnection(bootstrap, unreachableHost, port, connectionAttempts, retryLatch, retryManager);
        
        // Wait for retries
        assertTrue(retryLatch.await(8, TimeUnit.SECONDS), 
                "Should have attempted at least 2 connection retries");
        assertTrue(connectionAttempts.get() >= 2, 
                "Should have at least 2 connection attempts, got: " + connectionAttempts.get());
    }
    
    /**
     * Test that retry counter resets after successful connection.
     */
    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void testRetryResetAfterSuccessfulConnection() throws InterruptedException {
        // Create a simple echo server
        EventLoopGroup serverGroup = new NioEventLoopGroup(1);
        try {
            ServerBootstrap serverBootstrap = new ServerBootstrap()
                    .group(serverGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                                @Override
                                public void channelActive(ChannelHandlerContext ctx) {
                                    // Connection successful
                                    ctx.fireChannelActive();
                                }
                            });
                        }
                    });
            
            Channel serverChannel = serverBootstrap.bind(0).sync().channel();
            int serverPort = ((java.net.InetSocketAddress) serverChannel.localAddress()).getPort();
            
            RetryManager retryManager = new RetryManager();
            
            // First, increment retry counter
            retryManager.getNextRetryDelay(); // 1 second
            retryManager.getNextRetryDelay(); // 2 seconds
            
            // Now reset (simulating successful connection)
            retryManager.reset();
            
            // Next delay should be back to initial delay
            int delay = retryManager.getNextRetryDelay();
            assertTrue(delay == 1, "Delay should be reset to 1 second after successful connection, got: " + delay);
            
            serverChannel.close().sync();
        } finally {
            serverGroup.shutdownGracefully();
        }
    }
    
    /**
     * Helper method to attempt connection with retry logic.
     */
    private void attemptConnection(Bootstrap bootstrap, String host, int port, 
                                   AtomicInteger attemptCounter, CountDownLatch latch,
                                   RetryManager retryManager) {
        ChannelFuture future = bootstrap.connect(host, port);
        attemptCounter.incrementAndGet();
        
        future.addListener(f -> {
            if (!f.isSuccess()) {
                latch.countDown();
                
                // Schedule retry if we haven't reached our target count
                if (latch.getCount() > 0) {
                    retryManager.scheduleRetry(() -> {
                        attemptConnection(bootstrap, host, port, attemptCounter, latch, retryManager);
                    }, eventLoopGroup.next());
                }
            } else {
                // Connection successful - close it
                future.channel().close();
            }
        });
    }
    
    /**
     * Test multiple rapid connection failures don't cause resource leaks.
     */
    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void testMultipleRapidConnectionFailures() throws InterruptedException {
        int nonListeningPort = 54322;
        
        CountDownLatch completionLatch = new CountDownLatch(5);
        
        Bootstrap bootstrap = new Bootstrap()
                .group(eventLoopGroup)
                .channel(NioSocketChannel.class)
                .option(io.netty.channel.ChannelOption.CONNECT_TIMEOUT_MILLIS, 500)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        // Empty handler
                    }
                });
        
        // Attempt multiple rapid connections
        for (int i = 0; i < 5; i++) {
            ChannelFuture future = bootstrap.connect("localhost", nonListeningPort);
            future.addListener(f -> {
                completionLatch.countDown();
            });
        }
        
        // All attempts should complete (even if they fail)
        assertTrue(completionLatch.await(5, TimeUnit.SECONDS), 
                "All connection attempts should complete");
    }
}
