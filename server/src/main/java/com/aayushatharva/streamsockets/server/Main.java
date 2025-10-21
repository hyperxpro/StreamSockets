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

import com.aayushatharva.streamsockets.metrics.MetricsServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static com.aayushatharva.streamsockets.common.Utils.envValue;
import static com.aayushatharva.streamsockets.common.Utils.envValueAsInt;

public final class Main {

    private static final Logger logger = LogManager.getLogger();

    public static void main(String[] args) {
        WebSocketServer webSocketServer = new WebSocketServer();
        webSocketServer.start();

        boolean metricsEnabled = Boolean.parseBoolean(envValue("METRICS_ENABLED", "true"));
        if (metricsEnabled) {
            String metricsBindAddress = envValue("METRICS_BIND_ADDRESS", "0.0.0.0");
            int metricsPort = envValueAsInt("METRICS_PORT", 9090);
            String metricsPath = envValue("METRICS_PATH", "/metrics");

            MetricsServer metricsServer = new MetricsServer(
                    webSocketServer.getParentGroup(),
                    webSocketServer.getChildGroup(),
                    metricsPath
            );
            metricsServer.start(metricsBindAddress, metricsPort);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    logger.info("Shutting down servers...");
                    metricsServer.stop();
                    webSocketServer.stop();
                } catch (InterruptedException e) {
                    logger.error("Error during shutdown", e);
                }
            }));
        } else {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    logger.info("Shutting down WebSocket server...");
                    webSocketServer.stop();
                } catch (InterruptedException e) {
                    logger.error("Error during shutdown", e);
                }
            }));
        }
    }
}
