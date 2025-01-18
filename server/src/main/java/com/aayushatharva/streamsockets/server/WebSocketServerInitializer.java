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
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;
import io.netty.handler.stream.ChunkedWriteHandler;

import static com.aayushatharva.streamsockets.common.Utils.envValue;
import static com.aayushatharva.streamsockets.common.Utils.envValueAsInt;

final class WebSocketServerInitializer extends ChannelInitializer<SocketChannel> {

    private final TokenAuthentication tokenAuthentication;

    WebSocketServerInitializer(TokenAuthentication tokenAuthentication) {
        this.tokenAuthentication = tokenAuthentication;
    }

    @Override
    protected void initChannel(SocketChannel channel) {
        channel.pipeline().addLast(new HttpServerCodec());
        channel.pipeline().addLast(new HttpObjectAggregator(envValueAsInt("HTTP_MAX_CONTENT_LENGTH", 65536)));
        channel.pipeline().addLast(new AuthenticationHandler(tokenAuthentication));
        channel.pipeline().addLast(new WebSocketServerProtocolHandler(envValue("WS_PATH", "/tunnel")));
        channel.pipeline().addLast(new WebSocketServerHandler());
    }
}
