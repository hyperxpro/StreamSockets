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

package com.aayushatharva.streamsockets.metrics;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufOutputStream;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.prometheus.client.exporter.common.TextFormat;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

final class MetricsServerHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LogManager.getLogger();
    private final String metricsPath;

    MetricsServerHandler(String metricsPath) {
        this.metricsPath = metricsPath;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();

        if (metricsPath.equals(uri)) {
            ByteBuf buffer = ctx.alloc().buffer();
            try {
                ByteBufOutputStream outputStream = new ByteBufOutputStream(buffer);
                OutputStreamWriter writer = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8);
                TextFormat.write004(writer, MetricsRegistry.getInstance().getRegistry().metricFamilySamples());
                writer.flush();
                writer.close();

                FullHttpResponse response = new DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1,
                        HttpResponseStatus.OK,
                        buffer
                );

                response.headers().set(HttpHeaderNames.CONTENT_TYPE, TextFormat.CONTENT_TYPE_004);
                response.headers().set(HttpHeaderNames.CONTENT_LENGTH, buffer.readableBytes());

                ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
            } catch (Exception e) {
                logger.error("Failed to generate metrics", e);
                buffer.release();
                sendErrorResponse(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR, "Internal Server Error");
            }
        } else {
            sendErrorResponse(ctx, HttpResponseStatus.NOT_FOUND, "Not Found");
        }
    }

    private void sendErrorResponse(ChannelHandlerContext ctx, HttpResponseStatus status, String message) {
        ByteBuf buffer = ctx.alloc().buffer();
        buffer.writeCharSequence(message, StandardCharsets.UTF_8);
        
        FullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                status,
                buffer
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, buffer.readableBytes());
        ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("MetricsServerHandler exception", cause);
        ctx.close();
    }
}
