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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler.ClientHandshakeStateEvent;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.util.ReferenceCounted;
import lombok.extern.log4j.Log4j2;

import java.util.concurrent.ScheduledFuture;

import static com.aayushatharva.streamsockets.common.Utils.envValue;
import static io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler.ClientHandshakeStateEvent.HANDSHAKE_COMPLETE;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * This class receives {@link WebSocketFrame} from the WebSocket server and sends them to the UDP client.
 */
@Log4j2
public final class WebSocketClientHandler extends ChannelInboundHandlerAdapter {

    private static final ByteBuf PING = Unpooled.wrappedBuffer("PING".getBytes());
    private final DatagramHandler datagramHandler;

    private ChannelPromise websocketHandshakeFuture;
    private ChannelPromise authenticationFuture;
    private ChannelHandlerContext ctx;

    private ScheduledFuture<?> pingFuture;

    WebSocketClientHandler(DatagramHandler datagramHandler) {
        this.datagramHandler = datagramHandler;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        websocketHandshakeFuture = ctx.newPromise();
        authenticationFuture = ctx.newPromise();
        this.ctx = ctx;
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof ClientHandshakeStateEvent event && event == HANDSHAKE_COMPLETE) {
            newUdpConnection();
            websocketHandshakeFuture.setSuccess();
            return;
        }
        super.userEventTriggered(ctx, evt);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof TextWebSocketFrame textWebSocketFrame) {
            JsonObject requestJson = JsonParser.parseString(textWebSocketFrame.text()).getAsJsonObject();
            // Check if the connection was successful
            if (requestJson.get("success").getAsBoolean() && requestJson.get("message").getAsString().equalsIgnoreCase("connected")) {
                log.info("Connected to remote server: {}", ctx.channel().remoteAddress());
                authenticationFuture.setSuccess();

                // Send a ping every 5 seconds
                pingFuture = ctx.channel().eventLoop().schedule(() -> {
                    ctx.writeAndFlush(new PingWebSocketFrame(PING.retainedDuplicate()));
                }, 5, SECONDS);

                // Stop the ping when the channel is closed
                ctx.channel().closeFuture().addListener(future -> {
                    if (pingFuture != null) {
                        pingFuture.cancel(true);
                    }
                });
            } else {
                log.error("Failed to connect to remote server: {}", requestJson.get("message").getAsString());
                authenticationFuture.setFailure(new Exception(requestJson.get("message").getAsString()));
                System.exit(1);
            }
        } else if (msg instanceof BinaryWebSocketFrame binaryWebSocketFrame) {
            datagramHandler.writeToClient(binaryWebSocketFrame.content());
        } else {
            log.error("Unknown frame type: {}", msg.getClass().getName());

            // Release the message if it is a reference counted object
            if (msg instanceof ReferenceCounted referenceCounted) {
                referenceCounted.release();
            }
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.error("WebSocketClientHandler exception", cause);

        if (!websocketHandshakeFuture.isDone()) {
            websocketHandshakeFuture.setFailure(cause);
        }
    }

    void newUdpConnection() {
        authenticationFuture = ctx.newPromise();
        String route = envValue("ROUTE", "127.0.0.1:8888");

        JsonObject requestJson = new JsonObject();
        requestJson.addProperty("address", route.split(":")[0]);
        requestJson.addProperty("port", Integer.parseInt(route.split(":")[1]));

        ctx.writeAndFlush(new TextWebSocketFrame(requestJson.toString()));
    }

    boolean isReadyForWrite() {
        return websocketHandshakeFuture.isSuccess() && authenticationFuture.isSuccess();
    }

    public ChannelFuture websocketHandshakeFuture() {
        return websocketHandshakeFuture;
    }

    public ChannelFuture authenticationFuture() {
        return authenticationFuture;
    }
}
