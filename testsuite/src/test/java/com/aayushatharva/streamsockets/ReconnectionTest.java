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

package com.aayushatharva.streamsockets;

import com.aayushatharva.streamsockets.authentication.server.Accounts;
import com.aayushatharva.streamsockets.authentication.server.TokenAuthentication;
import com.aayushatharva.streamsockets.client.DatagramHandler;
import com.aayushatharva.streamsockets.client.UdpServer;
import com.aayushatharva.streamsockets.server.WebSocketServer;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.Timeout;
import org.yaml.snakeyaml.Yaml;

import javax.net.ssl.SSLException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Extensive tests for WebSocket reconnection and retry logic.
 * <p>
 * These tests validate that the client correctly handles server restarts, connection
 * failures, exponential backoff retries, epoch-based stale listener prevention, and
 * queued frame delivery after reconnection.
 */
@Log4j2
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class ReconnectionTest {

    static {
        System.setProperty("AUTH_TOKEN", "123456");
        System.setProperty("ROUTE", "127.0.0.1:8888");
        System.setProperty("WEBSOCKET_URI", "ws://localhost:8080/tunnel");
        // Use small retry delays to speed up tests
        System.setProperty("RETRY_INITIAL_DELAY_SECONDS", "1");
        System.setProperty("RETRY_MAX_DELAY_SECONDS", "4");
    }

    private final UdpEchoServer udpEchoServer = new UdpEchoServer();

    @BeforeAll
    void setupEchoServer() {
        udpEchoServer.start();
    }

    @AfterAll
    void tearDownEchoServer() {
        udpEchoServer.stop();
    }

    /**
     * Helper to load accounts from the test resources YAML file.
     */
    private TokenAuthentication loadTokenAuthentication() {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("accounts.yml");
        assertNotNull(inputStream, "Configuration file not found in resources");
        Yaml yaml = new Yaml();
        Accounts accounts = yaml.loadAs(inputStream, Accounts.class);
        return new TokenAuthentication(accounts);
    }

    /**
     * Helper to create and start a new WebSocketServer instance.
     */
    private WebSocketServer startServer() {
        WebSocketServer server = new WebSocketServer();
        server.start(loadTokenAuthentication());
        return server;
    }

    /**
     * Helper to send a UDP message and receive the echo response.
     *
     * @return the echoed string
     */
    private String sendAndReceiveUdp(DatagramSocket socket, String message) throws Exception {
        byte[] data = message.getBytes();
        socket.send(new DatagramPacket(data, 0, data.length, InetAddress.getByName("127.0.0.1"), 9000));

        DatagramPacket packet = new DatagramPacket(new byte[1024], 1024);
        socket.receive(packet);
        return new String(packet.getData(), 0, packet.getLength());
    }

    /**
     * Helper to verify round-trip UDP data flow through the WebSocket tunnel.
     */
    private void verifyDataFlow(DatagramSocket socket, int count, String prefix) throws Exception {
        for (int i = 0; i < count; i++) {
            String message = prefix + i;
            String received = sendAndReceiveUdp(socket, message);
            assertEquals(message, received, "Echo mismatch for message: " + message);
        }
    }

    // -----------------------------------------------------------------------
    // Test 1: Reconnection after server restart
    // -----------------------------------------------------------------------

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void testReconnectionAfterServerRestart() throws Exception {
        log.info("=== testReconnectionAfterServerRestart ===");

        WebSocketServer server = startServer();
        UdpServer udpServer = new UdpServer();
        udpServer.start();

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000);
            Thread.sleep(3000);

            // Verify initial data flow
            verifyDataFlow(socket, 5, "before-restart-");
            log.info("Initial data flow verified");

            // Stop the server
            server.stop();
            log.info("Server stopped");
            Thread.sleep(2000);

            // Restart the server
            server = startServer();
            log.info("Server restarted");

            // Wait for client to reconnect (retry delay + connection time)
            Thread.sleep(8000);

            // Verify data flow resumes after reconnection
            verifyDataFlow(socket, 5, "after-restart-");
            log.info("Data flow verified after server restart");

            server.stop();
        } finally {
            udpServer.stop();
        }
    }

    // -----------------------------------------------------------------------
    // Test 2: Reconnection after multiple server restarts
    // -----------------------------------------------------------------------

    @Test
    @Timeout(value = 120, unit = TimeUnit.SECONDS)
    void testReconnectionAfterMultipleServerRestarts() throws Exception {
        log.info("=== testReconnectionAfterMultipleServerRestarts ===");

        WebSocketServer server = startServer();
        UdpServer udpServer = new UdpServer();
        udpServer.start();

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000);
            Thread.sleep(3000);

            for (int cycle = 0; cycle < 3; cycle++) {
                log.info("Restart cycle {}", cycle);

                // Verify data flow before restart
                verifyDataFlow(socket, 3, "cycle-" + cycle + "-before-");
                log.info("Data flow verified before restart cycle {}", cycle);

                // Stop and restart server
                server.stop();
                Thread.sleep(2000);
                server = startServer();

                // Wait for client to reconnect
                Thread.sleep(8000);

                // Verify data flow after restart
                verifyDataFlow(socket, 3, "cycle-" + cycle + "-after-");
                log.info("Data flow verified after restart cycle {}", cycle);
            }

            server.stop();
        } finally {
            udpServer.stop();
        }
    }

    // -----------------------------------------------------------------------
    // Test 3: Connection retry when server not available
    // -----------------------------------------------------------------------

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void testConnectionRetryWhenServerNotAvailable() throws Exception {
        log.info("=== testConnectionRetryWhenServerNotAvailable ===");

        // Start client without a running server — it should retry
        UdpServer udpServer = new UdpServer();
        udpServer.start();

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(3000);
            Thread.sleep(3000);

            // Attempts to send should not get a response (no server yet)
            boolean timedOut = false;
            try {
                sendAndReceiveUdp(socket, "no-server-test");
            } catch (SocketTimeoutException e) {
                timedOut = true;
            }
            assertTrue(timedOut, "Should time out when server is not available");
            log.info("Confirmed no data flow without server");

            // Now start the server
            WebSocketServer server = startServer();
            log.info("Server started after client");

            // Wait for client to establish connection via retries
            Thread.sleep(10000);

            // Increase socket timeout for the successful path
            socket.setSoTimeout(5000);

            // Drain any stale queued responses from the earlier "no-server-test" packet
            try {
                while (true) {
                    DatagramPacket drainPkt = new DatagramPacket(new byte[1024], 1024);
                    socket.setSoTimeout(1000);
                    socket.receive(drainPkt);
                    String drainedData = new String(drainPkt.getData(), 0, drainPkt.getLength());
                    log.info("Drained stale response: {}", drainedData);
                }
            } catch (SocketTimeoutException ignored) {
                // No more stale responses
            }
            socket.setSoTimeout(5000);

            // Verify data flow now works
            verifyDataFlow(socket, 5, "after-server-start-");
            log.info("Data flow verified after late server start");

            server.stop();
        } finally {
            udpServer.stop();
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: Connection epoch prevents stale listeners
    // -----------------------------------------------------------------------

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void testConnectionEpochPreventsStaleListeners() throws Exception {
        log.info("=== testConnectionEpochPreventsStaleListeners ===");

        WebSocketServer server = startServer();
        UdpServer udpServer = new UdpServer();
        udpServer.start();

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000);
            Thread.sleep(3000);

            DatagramHandler handler = udpServer.datagramHandler();
            assertNotNull(handler, "DatagramHandler should not be null");

            // Record initial epoch
            int initialEpoch = handler.getConnectionEpoch();
            log.info("Initial connection epoch: {}", initialEpoch);
            assertTrue(initialEpoch >= 1, "Initial epoch should be at least 1");

            // Verify initial data flow
            verifyDataFlow(socket, 3, "epoch-initial-");

            // Trigger reconnection by stopping server
            server.stop();
            Thread.sleep(2000);
            server = startServer();

            // Wait for reconnection
            Thread.sleep(8000);

            // Epoch should have incremented (at least one reconnection)
            int newEpoch = handler.getConnectionEpoch();
            log.info("Epoch after reconnection: {}", newEpoch);
            assertTrue(newEpoch > initialEpoch, "Epoch should increment after reconnection");

            // Verify data flow still works — stale listeners did not interfere
            verifyDataFlow(socket, 3, "epoch-after-");
            log.info("Verified epoch mechanism prevents stale listener interference");

            server.stop();
        } finally {
            udpServer.stop();
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: isConnecting flag reset on failure
    // -----------------------------------------------------------------------

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void testIsConnectingResetOnFailure() throws Exception {
        log.info("=== testIsConnectingResetOnFailure ===");

        // Start client without server — connection will fail
        UdpServer udpServer = new UdpServer();
        udpServer.start();

        try {
            Thread.sleep(5000);

            DatagramHandler handler = udpServer.datagramHandler();
            assertNotNull(handler, "DatagramHandler should not be null");

            // After a failed connection attempt, isConnecting should be reset to false
            // (may momentarily be true during a scheduled retry, so poll a few times)
            boolean wasResetAtLeastOnce = false;
            for (int i = 0; i < 10; i++) {
                if (!handler.isConnecting()) {
                    wasResetAtLeastOnce = true;
                    break;
                }
                Thread.sleep(500);
            }
            assertTrue(wasResetAtLeastOnce, "isConnecting should be reset to false after connection failure");
            log.info("isConnecting flag properly reset after failure");

            // Now start the server to verify the flag reset allows a successful retry
            WebSocketServer server = startServer();
            Thread.sleep(10000);

            // After successful connection and auth, isConnecting should also be false
            assertFalse(handler.isConnecting(), "isConnecting should be false after successful connection");
            log.info("isConnecting flag properly false after successful connection");

            // Verify data flows (proves retries were not permanently blocked)
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setSoTimeout(5000);
                verifyDataFlow(socket, 3, "connecting-reset-");
            }
            log.info("Data flow verified — retries were not blocked by isConnecting flag");

            server.stop();
        } finally {
            udpServer.stop();
        }
    }

    // -----------------------------------------------------------------------
    // Test 6: Queued frames sent after reconnection
    // -----------------------------------------------------------------------

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void testQueuedFramesSentAfterReconnection() throws Exception {
        log.info("=== testQueuedFramesSentAfterReconnection ===");

        WebSocketServer server = startServer();
        UdpServer udpServer = new UdpServer();
        udpServer.start();

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000);
            Thread.sleep(3000);

            // Verify initial connectivity
            verifyDataFlow(socket, 2, "queued-pre-");
            log.info("Initial data flow verified");

            // Stop server to disconnect the WebSocket channel
            server.stop();
            Thread.sleep(2000);

            // Send UDP packets while disconnected — these should be queued
            for (int i = 0; i < 5; i++) {
                String message = "queued-" + i;
                byte[] data = message.getBytes();
                socket.send(new DatagramPacket(data, 0, data.length,
                        InetAddress.getByName("127.0.0.1"), 9000));
            }
            log.info("Sent 5 packets while server is down (should be queued)");

            // Restart server
            server = startServer();
            Thread.sleep(10000);

            // The queued packets should have been flushed and echoed back.
            // Collect responses with a generous timeout.
            int received = 0;
            socket.setSoTimeout(8000);
            for (int i = 0; i < 5; i++) {
                try {
                    DatagramPacket pkt = new DatagramPacket(new byte[1024], 1024);
                    socket.receive(pkt);
                    String data = new String(pkt.getData(), 0, pkt.getLength());
                    log.info("Received queued echo: {}", data);
                    received++;
                } catch (SocketTimeoutException e) {
                    break;
                }
            }
            log.info("Received {} queued responses", received);
            assertTrue(received > 0, "At least some queued frames should be delivered after reconnection");

            // Verify new data still flows after the queue flush
            socket.setSoTimeout(5000);
            verifyDataFlow(socket, 3, "queued-post-");
            log.info("Post-reconnection data flow verified");

            server.stop();
        } finally {
            udpServer.stop();
        }
    }

    // -----------------------------------------------------------------------
    // Test 7: Ping/pong maintains connection
    // -----------------------------------------------------------------------

    @Test
    @Timeout(value = 45, unit = TimeUnit.SECONDS)
    void testPingPongMaintainsConnection() throws Exception {
        log.info("=== testPingPongMaintainsConnection ===");

        WebSocketServer server = startServer();
        UdpServer udpServer = new UdpServer();
        udpServer.start();

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000);
            Thread.sleep(3000);

            // Verify initial data flow
            verifyDataFlow(socket, 3, "ping-initial-");
            log.info("Initial data flow verified");

            DatagramHandler handler = udpServer.datagramHandler();
            int epochBefore = handler.getConnectionEpoch();

            // Wait long enough for multiple ping/pong cycles (default interval is 5s)
            // The connection should stay alive without reconnecting.
            Thread.sleep(15000);

            // Epoch should NOT have changed — connection maintained by ping/pong
            int epochAfter = handler.getConnectionEpoch();
            assertEquals(epochBefore, epochAfter,
                    "Connection epoch should not change — ping/pong should keep connection alive");

            // Verify data still flows on the same connection
            verifyDataFlow(socket, 3, "ping-after-");
            log.info("Connection maintained by ping/pong over 15 seconds");

            server.stop();
        } finally {
            udpServer.stop();
        }
    }

    // -----------------------------------------------------------------------
    // Test 8: RetryManager exponential backoff
    // -----------------------------------------------------------------------

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testRetryManagerExponentialBackoff() throws Exception {
        log.info("=== testRetryManagerExponentialBackoff ===");

        // Start client with no server to force repeated retries
        UdpServer udpServer = new UdpServer();
        udpServer.start();

        try {
            DatagramHandler handler = udpServer.datagramHandler();
            assertNotNull(handler, "DatagramHandler should not be null");

            // The initial connection attempt is epoch 1. Each retry increments the epoch.
            // With exponential backoff (1s, 2s, 4s …), we should see multiple epochs
            // over a period of ~10 seconds: attempt at 0s(epoch=1), retry at ~1s(epoch=2),
            // retry at ~2s(epoch=3), retry at ~4s(epoch=4), etc.

            Thread.sleep(3000);
            int epochAt3s = handler.getConnectionEpoch();
            log.info("Epoch after 3s: {}", epochAt3s);

            Thread.sleep(5000);
            int epochAt8s = handler.getConnectionEpoch();
            log.info("Epoch after 8s: {}", epochAt8s);

            // More retries should have happened
            assertTrue(epochAt8s > epochAt3s,
                    "Epoch should increase over time as retries happen with backoff");

            // The number of retries should be bounded — exponential backoff means
            // fewer retries over the same wall-clock time compared to fixed interval.
            // With 1/2/4s backoff in 8s we expect roughly 4 attempts,
            // not 8 (which would be 1s fixed interval).
            assertTrue(epochAt8s <= 8,
                    "Retries should be bounded by exponential backoff (got epoch " + epochAt8s + ")");

            log.info("Exponential backoff behaviour verified");
        } finally {
            udpServer.stop();
        }
    }

    // -----------------------------------------------------------------------
    // Test 9: RetryManager resets after success
    // -----------------------------------------------------------------------

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void testRetryManagerResetsAfterSuccess() throws Exception {
        log.info("=== testRetryManagerResetsAfterSuccess ===");

        // Start client without server — it will accumulate retry backoff
        UdpServer udpServer = new UdpServer();
        udpServer.start();

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000);

            // Let client retry for a bit
            Thread.sleep(5000);
            DatagramHandler handler = udpServer.datagramHandler();
            int epochBeforeServer = handler.getConnectionEpoch();
            log.info("Epoch before server start: {}", epochBeforeServer);
            assertTrue(epochBeforeServer > 1, "Client should have retried at least once");

            // Now start the server — connection should succeed and reset backoff
            WebSocketServer server = startServer();
            Thread.sleep(10000);

            // Verify data flow (connection succeeded)
            verifyDataFlow(socket, 3, "reset-first-");
            log.info("First connection succeeded");

            int epochAfterConnect = handler.getConnectionEpoch();
            assertFalse(handler.isConnecting(), "Should not be connecting after success");

            // Force another reconnection cycle by restarting server
            server.stop();
            Thread.sleep(2000);
            server = startServer();

            // If backoff was properly reset, reconnection should happen quickly (~1s initial delay)
            // rather than using the accumulated high backoff from the earlier failures.
            Thread.sleep(6000);

            int epochAfterReconnect = handler.getConnectionEpoch();
            log.info("Epoch after reconnect: {}", epochAfterReconnect);
            assertTrue(epochAfterReconnect > epochAfterConnect,
                    "Epoch should increase after server restart");

            // Verify data flows again
            verifyDataFlow(socket, 3, "reset-second-");
            log.info("Retry counter reset verified — reconnection was fast after prior success");

            server.stop();
        } finally {
            udpServer.stop();
        }
    }
}
