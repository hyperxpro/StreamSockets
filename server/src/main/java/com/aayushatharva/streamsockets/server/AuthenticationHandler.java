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

import com.aayushatharva.streamsockets.authentication.server.Accounts;
import com.aayushatharva.streamsockets.authentication.server.TokenAuthentication;
import com.aayushatharva.streamsockets.metrics.MetricsRegistry;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.util.AttributeKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

import java.net.InetSocketAddress;

import static io.netty.buffer.Unpooled.unreleasableBuffer;
import static io.netty.buffer.Unpooled.wrappedBuffer;
import static io.netty.channel.ChannelFutureListener.CLOSE;
import static io.netty.handler.codec.http.HttpResponseStatus.BAD_REQUEST;
import static io.netty.handler.codec.http.HttpResponseStatus.FORBIDDEN;
import static io.netty.handler.codec.http.HttpResponseStatus.UNAUTHORIZED;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;

@Log4j2
@RequiredArgsConstructor
final class AuthenticationHandler extends ChannelInboundHandlerAdapter {

    private final TokenAuthentication tokenAuthentication;
    
    // Cached environment variable to avoid repeated system calls
    private static final String CLIENT_IP_HEADER = System.getenv("CLIENT_IP_HEADER");
    
    // AttributeKeys for storing protocol information
    private static final AttributeKey<Boolean> NEW_PROTOCOL_KEY = AttributeKey.valueOf("newProtocol");
    private static final AttributeKey<String> ROUTE_ADDRESS_KEY = AttributeKey.valueOf("routeAddress");
    private static final AttributeKey<String> ROUTE_PORT_KEY = AttributeKey.valueOf("routePort");
    private static final AttributeKey<String> ROUTE_STRING_KEY = AttributeKey.valueOf("routeString");
    private static final AttributeKey<String> ACCOUNT_NAME_KEY = AttributeKey.valueOf("accountName");
    private static final AttributeKey<String> CLIENT_IP_KEY = AttributeKey.valueOf("clientIp");
    private static final AttributeKey<Long> CONNECTION_START_TIME_KEY = AttributeKey.valueOf("connectionStartTime");
    
    // Use Unpooled.unreleasableBuffer to prevent accidental releases of shared static content
    private static final FullHttpResponse UNAUTHORIZED_RESPONSE = new DefaultFullHttpResponse(HTTP_1_1, UNAUTHORIZED, unreleasableBuffer(wrappedBuffer("Unauthorized".getBytes())));
    private static final FullHttpResponse FORBIDDEN_RESPONSE = new DefaultFullHttpResponse(HTTP_1_1, FORBIDDEN, unreleasableBuffer(wrappedBuffer("Failed to lease account".getBytes())));
    private static final FullHttpResponse BAD_REQUEST_RESPONSE = new DefaultFullHttpResponse(HTTP_1_1, BAD_REQUEST, unreleasableBuffer(wrappedBuffer("Invalid authentication type".getBytes())));

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof FullHttpRequest request) {
            if (request.headers().contains("X-Auth-Type", "Token", true)) {
                // Cache channel reference to avoid repeated ctx.channel() calls
                Channel channel = ctx.channel();
                
                String token = request.headers().get("X-Auth-Token");
                String clientIp;

                // If CLIENT_IP_HEADER is set, use that header to get the client IP
                if (CLIENT_IP_HEADER != null) {
                    clientIp = request.headers().get(CLIENT_IP_HEADER);
                } else {
                    clientIp = ((InetSocketAddress) channel.remoteAddress()).getAddress().getHostAddress();
                }

                // Support both old and new protocol for route information
                String route;
                boolean newProtocol = request.headers().contains("X-Route-Address") && request.headers().contains("X-Route-Port");
                
                if (newProtocol) {
                    // New protocol: construct route from address and port headers
                    // Build the route string once here to avoid repeated concatenation
                    String address = request.headers().get("X-Route-Address");
                    String port = request.headers().get("X-Route-Port");
                    route = new StringBuilder(address.length() + 1 + port.length())
                            .append(address).append(':').append(port).toString();
                } else {
                    // Old protocol: use X-Auth-Route header
                    route = request.headers().get("X-Auth-Route");
                }
                
                Accounts.Account account = tokenAuthentication.authenticate(token, route, clientIp);

                // If account is null, return unauthorized
                if (account == null) {
                    ctx.writeAndFlush(UNAUTHORIZED_RESPONSE.duplicate()).addListener(CLOSE);
                    request.release();
                    return;
                }

                // If account is not leased, return forbidden
                if (!tokenAuthentication.leaseAccount(account)) {
                    ctx.writeAndFlush(FORBIDDEN_RESPONSE.duplicate()).addListener(CLOSE);
                    request.release();
                    return;
                }

                // Track connection start time and record metrics
                long connectionStartTime = System.currentTimeMillis();
                channel.attr(CONNECTION_START_TIME_KEY).set(connectionStartTime);
                MetricsRegistry.getInstance().recordConnectionStart(account.getName());

                // Release account when the channel is closed
                channel.closeFuture().addListener((ChannelFutureListener) future -> {
                    if (tokenAuthentication.releaseAccount(account)) {
                        log.info("{} disconnected from the server", account.getName());
                    }
                    
                    // Record connection end and duration
                    Long startTime = channel.attr(CONNECTION_START_TIME_KEY).get();
                    if (startTime != null) {
                        long durationSeconds = (System.currentTimeMillis() - startTime) / 1000;
                        MetricsRegistry.getInstance().recordConnectionEnd(account.getName(), durationSeconds);
                    }
                });

                // Store the protocol version, pre-built route string, account name, and client IP in channel attributes
                channel.attr(NEW_PROTOCOL_KEY).set(newProtocol);
                channel.attr(ROUTE_STRING_KEY).set(route);
                channel.attr(ACCOUNT_NAME_KEY).set(account.getName());
                channel.attr(CLIENT_IP_KEY).set(clientIp);
                if (newProtocol) {
                    channel.attr(ROUTE_ADDRESS_KEY).set(request.headers().get("X-Route-Address"));
                    channel.attr(ROUTE_PORT_KEY).set(request.headers().get("X-Route-Port"));
                }

                ctx.pipeline().remove(this);
                ctx.fireChannelRead(msg);
            } else {
                ctx.writeAndFlush(BAD_REQUEST_RESPONSE.duplicate()).addListener(CLOSE);
                request.release();
            }
        }
    }
}
