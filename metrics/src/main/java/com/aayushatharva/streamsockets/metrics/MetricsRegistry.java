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

import io.prometheus.client.CollectorRegistry;
import io.prometheus.client.Counter;
import io.prometheus.client.Gauge;
import io.prometheus.client.Histogram;

public final class MetricsRegistry {

    private static final MetricsRegistry INSTANCE = new MetricsRegistry();

    private final CollectorRegistry registry = new CollectorRegistry();

    // Connection metrics
    private final Gauge activeConnections = Gauge.build()
            .name("streamsockets_active_connections")
            .help("Number of active WebSocket connections by account")
            .labelNames("account_name")
            .register(registry);

    private final Gauge connectionStatus = Gauge.build()
            .name("streamsockets_connection_status")
            .help("Connection status by account (1 = connected, 0 = disconnected)")
            .labelNames("account_name")
            .register(registry);

    private final Counter totalConnections = Counter.build()
            .name("streamsockets_total_connections")
            .help("Total number of connections by account")
            .labelNames("account_name")
            .register(registry);

    // Data transfer metrics
    private final Counter bytesReceived = Counter.build()
            .name("streamsockets_bytes_received_total")
            .help("Total bytes received from clients by account")
            .labelNames("account_name")
            .register(registry);

    private final Counter bytesSent = Counter.build()
            .name("streamsockets_bytes_sent_total")
            .help("Total bytes sent to clients by account")
            .labelNames("account_name")
            .register(registry);

    // Connection duration metrics
    private final Histogram connectionDuration = Histogram.build()
            .name("streamsockets_connection_duration_seconds")
            .help("Connection duration in seconds by account")
            .labelNames("account_name")
            .buckets(1, 5, 10, 30, 60, 300, 600, 1800, 3600)
            .register(registry);

    private MetricsRegistry() {
    }

    public static MetricsRegistry getInstance() {
        return INSTANCE;
    }

    public CollectorRegistry getRegistry() {
        return registry;
    }

    public void recordConnectionStart(String accountName) {
        activeConnections.labels(accountName).inc();
        connectionStatus.labels(accountName).set(1);
        totalConnections.labels(accountName).inc();
    }

    public void recordConnectionEnd(String accountName, long durationSeconds) {
        activeConnections.labels(accountName).dec();
        connectionStatus.labels(accountName).set(0);
        connectionDuration.labels(accountName).observe(durationSeconds);
    }

    public void recordBytesReceived(String accountName, long bytes) {
        bytesReceived.labels(accountName).inc(bytes);
    }

    public void recordBytesSent(String accountName, long bytes) {
        bytesSent.labels(accountName).inc(bytes);
    }
}
