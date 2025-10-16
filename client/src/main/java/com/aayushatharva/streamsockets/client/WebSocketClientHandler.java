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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PongWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler.ClientHandshakeStateEvent;
import io.netty.util.ReferenceCounted;
import lombok.extern.log4j.Log4j2;

import static com.aayushatharva.streamsockets.common.Utils.envValueAsInt;
import static io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler.ClientHandshakeStateEvent.HANDSHAKE_COMPLETE;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

/**
 * This class receives {@link WebSocketFrame} from the WebSocket server and sends them to the UDP client.
 */
@Log4j2
public final class WebSocketClientHandler extends ChannelInboundHandlerAdapter {

    private static final ByteBuf PING = Unpooled.wrappedBuffer("PING".getBytes());
    private static final int PING_TIMEOUT_MILLIS = envValueAsInt("PING_TIMEOUT_MILLIS", 10_000);
    private static final int PING_INTERVAL_MILLIS = envValueAsInt("PING_INTERVAL_MILLIS", 1_000);
    
    private final DatagramHandler datagramHandler;

    private ChannelPromise handshakeFuture;
    private ChannelHandlerContext ctx;

    private long lastPongTime;

    WebSocketClientHandler(DatagramHandler datagramHandler) {
        this.datagramHandler = datagramHandler;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        this.ctx = ctx;
        handshakeFuture = ctx.newPromise();
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        // If the handshake is complete, the server has already established the UDP connection
        if (evt instanceof ClientHandshakeStateEvent event && event == HANDSHAKE_COMPLETE) {
            log.info("Connected to remote server: {}", ctx.channel().remoteAddress());
            handshakeFuture.setSuccess();
            
            // Send a ping periodically
            ctx.channel().eventLoop().scheduleAtFixedRate(() -> {
                ctx.writeAndFlush(new PingWebSocketFrame(PING.retainedDuplicate()));
            }, 0, PING_INTERVAL_MILLIS, MILLISECONDS);

            // Monitor ping timeout
            lastPongTime = System.currentTimeMillis();
            ctx.channel().eventLoop().scheduleAtFixedRate(() -> {
                if (System.currentTimeMillis() - lastPongTime > PING_TIMEOUT_MILLIS) {
                    log.error("Ping timeout, closing connection...");
                    ctx.close();
                }
            }, 0, 1000, MILLISECONDS);
            
            return;
        }
        super.userEventTriggered(ctx, evt);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof BinaryWebSocketFrame binaryWebSocketFrame) {
            // Retain content since it will be used by DatagramPacket
            datagramHandler.writeToUdpClient(binaryWebSocketFrame.content().retain());
            binaryWebSocketFrame.release();
        } else if (msg instanceof PongWebSocketFrame pongWebSocketFrame) {
            pongWebSocketFrame.release();
            lastPongTime = System.currentTimeMillis();
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

        if (!handshakeFuture.isDone()) {
            handshakeFuture.setFailure(cause);
        }
    }

    boolean isReadyForWrite() {
        return handshakeFuture.isSuccess();
    }

    public ChannelFuture handshakeFuture() {
        return handshakeFuture;
    }
}
