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

import io.prometheus.client.Collector;
import org.junit.jupiter.api.Test;

import java.util.Enumeration;

import static org.junit.jupiter.api.Assertions.*;

class MetricsRegistryTest {

    @Test
    void testConnectionMetrics() {
        MetricsRegistry registry = MetricsRegistry.getInstance();
        String accountName = "testAccount";

        // Record connection start
        registry.recordConnectionStart(accountName);

        // Verify metrics are recorded
        Enumeration<Collector.MetricFamilySamples> samples = registry.getRegistry().metricFamilySamples();
        boolean foundActiveConnections = false;
        boolean foundTotalConnections = false;

        while (samples.hasMoreElements()) {
            Collector.MetricFamilySamples sample = samples.nextElement();
            if (sample.name.equals("streamsockets_active_connections")) {
                foundActiveConnections = true;
            }
            if (sample.name.equals("streamsockets_total_connections")) {
                foundTotalConnections = true;
            }
        }

        assertTrue(foundActiveConnections, "Active connections metric should be present");
        assertTrue(foundTotalConnections, "Total connections metric should be present");

        // Record connection end
        registry.recordConnectionEnd(accountName, 10);
    }

    @Test
    void testDataTransferMetrics() {
        MetricsRegistry registry = MetricsRegistry.getInstance();
        String accountName = "testAccountDataTransfer";

        // Record data transfer
        registry.recordBytesReceived(accountName, 1024);
        registry.recordBytesSent(accountName, 2048);

        // Verify metrics are recorded by checking if the registry is not empty
        Enumeration<Collector.MetricFamilySamples> samples = registry.getRegistry().metricFamilySamples();
        assertNotNull(samples, "Metrics samples should not be null");
        
        // Just verify the registry has metrics
        boolean hasMetrics = false;
        while (samples.hasMoreElements()) {
            samples.nextElement();
            hasMetrics = true;
        }
        assertTrue(hasMetrics, "Registry should have metrics");
    }

    @Test
    void testConnectionDurationMetric() {
        MetricsRegistry registry = MetricsRegistry.getInstance();
        String accountName = "testAccountDuration";

        // Record connection duration
        registry.recordConnectionEnd(accountName, 30);

        // Verify duration histogram is present
        Enumeration<Collector.MetricFamilySamples> samples = registry.getRegistry().metricFamilySamples();
        boolean foundConnectionDuration = false;

        while (samples.hasMoreElements()) {
            Collector.MetricFamilySamples sample = samples.nextElement();
            if (sample.name.equals("streamsockets_connection_duration_seconds")) {
                foundConnectionDuration = true;
            }
        }

        assertTrue(foundConnectionDuration, "Connection duration metric should be present");
    }

    @Test
    void testSingletonInstance() {
        MetricsRegistry instance1 = MetricsRegistry.getInstance();
        MetricsRegistry instance2 = MetricsRegistry.getInstance();
        assertSame(instance1, instance2, "MetricsRegistry should be a singleton");
    }
}
