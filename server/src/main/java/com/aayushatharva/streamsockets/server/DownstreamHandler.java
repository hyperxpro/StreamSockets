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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import lombok.extern.log4j.Log4j2;

@Log4j2
final class DownstreamHandler extends ChannelInboundHandlerAdapter {

    private final Channel channel;
    private final int tunnelId;
    private final boolean newProtocol;

    DownstreamHandler(Channel channel, int tunnelId, boolean newProtocol) {
        this.channel = channel;
        this.tunnelId = tunnelId;
        this.newProtocol = newProtocol;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof DatagramPacket packet) {
            if (newProtocol) {
                // New protocol: prepend tunnel ID byte
                ByteBuf content = packet.content();
                ByteBuf frame = Unpooled.buffer(1 + content.readableBytes());
                frame.writeByte(tunnelId);
                frame.writeBytes(content);
                channel.writeAndFlush(new BinaryWebSocketFrame(frame));
                packet.release();
            } else {
                // Old protocol: no tunnel ID
                channel.writeAndFlush(new BinaryWebSocketFrame(packet.content().retain()));
                packet.release();
            }
        } else {
            log.error("Unknown frame type: {}", msg.getClass().getName());
            
            // Release the message if it is a reference counted object
            if (msg instanceof io.netty.util.ReferenceCounted referenceCounted) {
                referenceCounted.release();
            }
        }
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        // Flush pending writes for better batching
        ctx.flush();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.error("DownstreamHandler exception", cause);
    }
}
