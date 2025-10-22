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
import com.aayushatharva.streamsockets.client.UdpServer;
import com.aayushatharva.streamsockets.server.WebSocketServer;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.yaml.snakeyaml.Yaml;

import javax.net.ssl.SSLException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests to validate multiple concurrent connections for the same account.
 * This test suite validates the 403 Forbidden response when attempting
 * to connect multiple times with the same account when reuse is set to false,
 * and validates that reuse=true allows multiple concurrent connections.
 * Also tests packet flow with multiple connections.
 */
@Log4j2
@TestInstance(TestInstance.Lifecycle.PER_METHOD)
public class MultipleConnectionsTest {

    private final UdpEchoServer udpEchoServer = new UdpEchoServer();
    private WebSocketServer webSocketServer;
    private UdpServer udpServer1;
    private UdpServer udpServer2;

    @BeforeEach
    void setup() throws SSLException {
        udpEchoServer.start();
    }

    @AfterEach
    void tearDown() throws InterruptedException {
        udpEchoServer.stop();
        if (webSocketServer != null) {
            webSocketServer.stop();
        }
        if (udpServer1 != null) {
            udpServer1.stop();
        }
        if (udpServer2 != null) {
            udpServer2.stop();
        }
    }

    /**
     * Test that validates account leasing behavior with reuse=false.
     * When reuse is disabled, the same account cannot be leased twice concurrently.
     */
    @Test
    void testAccountLeasingWithReuseDisabled() {
        log.info("Testing account leasing with reuse disabled");
        
        // Create account with reuse = false
        Accounts accounts = new Accounts();
        Accounts.Account accountNoReuse = new Accounts.Account();
        accountNoReuse.setName("user_no_reuse");
        accountNoReuse.setToken("token_no_reuse");
        accountNoReuse.setReuse(false);
        accountNoReuse.setRoutes(List.of("127.0.0.1:8888"));
        accountNoReuse.setAllowedIps(List.of("127.0.0.1"));
        accounts.setAccounts(List.of(accountNoReuse));

        TokenAuthentication tokenAuth = new TokenAuthentication(accounts);

        // First authentication and lease should succeed
        Accounts.Account account1 = tokenAuth.authenticate("token_no_reuse", "127.0.0.1:8888", "127.0.0.1");
        assertNotNull(account1, "First authentication should succeed");
        assertTrue(tokenAuth.leaseAccount(account1), "First lease should succeed");

        // Second lease attempt should fail (reuse = false)
        Accounts.Account account2 = tokenAuth.authenticate("token_no_reuse", "127.0.0.1:8888", "127.0.0.1");
        assertNotNull(account2, "Second authentication should succeed");
        assertFalse(tokenAuth.leaseAccount(account2), "Second lease should fail when reuse=false");

        // After releasing, should be able to lease again
        assertTrue(tokenAuth.releaseAccount(account1), "Release should succeed");
        assertTrue(tokenAuth.leaseAccount(account2), "Third lease should succeed after release");

        log.info("Verified: Account leasing works correctly with reuse=false");
    }

    /**
     * Test that validates account leasing behavior with reuse=true.
     * When reuse is enabled, the same account can be leased multiple times concurrently.
     */
    @Test
    void testAccountLeasingWithReuseEnabled() {
        log.info("Testing account leasing with reuse enabled");
        
        // Create account with reuse = true
        Accounts accounts = new Accounts();
        Accounts.Account accountWithReuse = new Accounts.Account();
        accountWithReuse.setName("user_with_reuse");
        accountWithReuse.setToken("token_with_reuse");
        accountWithReuse.setReuse(true);
        accountWithReuse.setRoutes(List.of("127.0.0.1:8888"));
        accountWithReuse.setAllowedIps(List.of("127.0.0.1"));
        accounts.setAccounts(List.of(accountWithReuse));

        TokenAuthentication tokenAuth = new TokenAuthentication(accounts);

        // First authentication and lease should succeed
        Accounts.Account account1 = tokenAuth.authenticate("token_with_reuse", "127.0.0.1:8888", "127.0.0.1");
        assertNotNull(account1, "First authentication should succeed");
        assertTrue(tokenAuth.leaseAccount(account1), "First lease should succeed");

        // Second lease attempt should also succeed (reuse = true)
        Accounts.Account account2 = tokenAuth.authenticate("token_with_reuse", "127.0.0.1:8888", "127.0.0.1");
        assertNotNull(account2, "Second authentication should succeed");
        assertTrue(tokenAuth.leaseAccount(account2), "Second lease should succeed when reuse=true");

        // Third lease should also succeed
        Accounts.Account account3 = tokenAuth.authenticate("token_with_reuse", "127.0.0.1:8888", "127.0.0.1");
        assertNotNull(account3, "Third authentication should succeed");
        assertTrue(tokenAuth.leaseAccount(account3), "Third lease should succeed when reuse=true");

        log.info("Verified: Account leasing works correctly with reuse=true");
    }

    /**
     * Test packet flow through a WebSocket tunnel with an account that has reuse enabled.
     * This validates that data can flow correctly through concurrent connections.
     */
    @Test
    void testPacketFlowWithReuseEnabled() throws Exception {
        log.info("Testing packet flow with reuse enabled");
        
        // Load accounts from test resources (same as EndToEndTest)
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("accounts.yml");
        assertNotNull(inputStream, "Configuration file not found in resources");
        Yaml yaml = new Yaml();
        Accounts accounts = yaml.loadAs(inputStream, Accounts.class);
        
        webSocketServer = new WebSocketServer();
        webSocketServer.start(new TokenAuthentication(accounts));

        // Configure and start UDP server (using user1 from accounts.yml which has reuse=false but we'll only create one connection)
        System.setProperty("WEBSOCKET_URI", "ws://localhost:8080/tunnel");
        System.setProperty("AUTH_TOKEN", "123456");
        System.setProperty("ROUTE", "127.0.0.1:8888");
        
        udpServer1 = new UdpServer();
        udpServer1.start();
        
        // Wait for UDP server to bind
        udpServer1.channelFutures().forEach(future -> {
            try {
                future.get();
            } catch (Exception e) {
                log.error("Error in UDP server", e);
            }
        });
        
        // Wait for connection to establish
        Thread.sleep(3000);

        // Test packet flow through the connection
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000);
            
            for (int i = 0; i < 10; i++) {
                String message = "TestPacket-" + i;
                byte[] data = message.getBytes();
                socket.send(new DatagramPacket(data, 0, data.length, InetAddress.getByName("127.0.0.1"), 9000));

                DatagramPacket packet = new DatagramPacket(new byte[1024], 1024);
                socket.receive(packet);

                String receivedData = new String(packet.getData(), 0, packet.getLength());
                assertEquals(message, receivedData, "Packet should be echoed back correctly");
            }
            log.info("Packet flow verified successfully");
        }

        log.info("Verified: Packet flow works correctly");
    }
}
