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

import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.websocketx.WebSocketClientHandshaker;
import io.netty.handler.codec.http.websocketx.WebSocketClientHandshakerFactory;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler;

import java.net.URI;

import static com.aayushatharva.streamsockets.common.Utils.envValue;
import static io.netty.handler.codec.http.websocketx.WebSocketVersion.V13;

final class WebSocketClientInitializer extends ChannelInitializer<SocketChannel> {

    private final DatagramHandler datagramHandler;
    private final URI uri;

    WebSocketClientInitializer(DatagramHandler datagramHandler, URI uri) {
        this.datagramHandler = datagramHandler;
        this.uri = uri;
    }

    @Override
    protected void initChannel(SocketChannel channel) {
        HttpHeaders headers = new DefaultHttpHeaders();
        headers.add("X-Auth-Type", "Token");
        headers.add("X-Auth-Token", envValue("AUTH_TOKEN", ""));
        headers.add("X-Auth-Route", envValue("ROUTE", "127.0.0.1:8888"));

        WebSocketClientHandshaker handshaker = WebSocketClientHandshakerFactory.newHandshaker(uri, V13, null, false, headers);

        channel.pipeline().addLast(new HttpClientCodec());
        channel.pipeline().addLast(new HttpObjectAggregator(8192));
        channel.pipeline().addLast(new WebSocketClientProtocolHandler(handshaker));
        channel.pipeline().addLast(new WebSocketClientHandler(datagramHandler));
    }
}
