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
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.util.AttributeKey;
import lombok.extern.log4j.Log4j2;

import java.net.InetSocketAddress;

import static io.netty.channel.ChannelFutureListener.CLOSE;
import static io.netty.handler.codec.http.HttpResponseStatus.BAD_REQUEST;
import static io.netty.handler.codec.http.HttpResponseStatus.FORBIDDEN;
import static io.netty.handler.codec.http.HttpResponseStatus.UNAUTHORIZED;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;

@Log4j2
final class AuthenticationHandler extends ChannelInboundHandlerAdapter {

    private final TokenAuthentication tokenAuthentication;
    
    // AttributeKeys for storing protocol information
    private static final AttributeKey<Boolean> NEW_PROTOCOL_KEY = AttributeKey.valueOf("newProtocol");
    private static final AttributeKey<String> ROUTE_ADDRESS_KEY = AttributeKey.valueOf("routeAddress");
    private static final AttributeKey<String> ROUTE_PORT_KEY = AttributeKey.valueOf("routePort");
    
    // Use Unpooled.unreleasableBuffer to prevent accidental releases of shared static content
    private static final FullHttpResponse UNAUTHORIZED_RESPONSE = new DefaultFullHttpResponse(
            HTTP_1_1, UNAUTHORIZED, Unpooled.unreleasableBuffer(Unpooled.wrappedBuffer("Unauthorized".getBytes())));
    private static final FullHttpResponse FORBIDDEN_RESPONSE = new DefaultFullHttpResponse(
            HTTP_1_1, FORBIDDEN, Unpooled.unreleasableBuffer(Unpooled.wrappedBuffer("Failed to lease account".getBytes())));
    private static final FullHttpResponse BAD_REQUEST_RESPONSE = new DefaultFullHttpResponse(
            HTTP_1_1, BAD_REQUEST, Unpooled.unreleasableBuffer(Unpooled.wrappedBuffer("Invalid authentication type".getBytes())));

    AuthenticationHandler(TokenAuthentication tokenAuthentication) {
        this.tokenAuthentication = tokenAuthentication;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof FullHttpRequest request) {
            if (request.headers().contains("X-Auth-Type", "Token", true)) {
                String token = request.headers().get("X-Auth-Token");
                String clientIp;

                // If CLIENT_IP_HEADER is set, use that header to get the client IP
                if (System.getenv("CLIENT_IP_HEADER") != null) {
                    clientIp = request.headers().get(System.getenv("CLIENT_IP_HEADER"));
                } else {
                    clientIp = ((InetSocketAddress) ctx.channel().remoteAddress()).getAddress().getHostAddress();
                }

                // Support both old and new protocol for route information
                String route;
                boolean newProtocol = request.headers().contains("X-Route-Address") && request.headers().contains("X-Route-Port");
                
                if (newProtocol) {
                    // New protocol: construct route from address and port headers
                    route = request.headers().get("X-Route-Address") + ":" + request.headers().get("X-Route-Port");
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

                // Release account when the channel is closed
                ctx.channel().closeFuture().addListener((ChannelFutureListener) future -> {
                    if (tokenAuthentication.releaseAccount(account)) {
                        log.info("{} disconnected from the server", account.getName());
                    }
                });

                // Store the protocol version in channel attributes for use by WebSocketServerHandler
                ctx.channel().attr(NEW_PROTOCOL_KEY).set(newProtocol);
                if (newProtocol) {
                    ctx.channel().attr(ROUTE_ADDRESS_KEY).set(request.headers().get("X-Route-Address"));
                    ctx.channel().attr(ROUTE_PORT_KEY).set(request.headers().get("X-Route-Port"));
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
