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
import com.aayushatharva.streamsockets.server.WebSocketServer;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.yaml.snakeyaml.Yaml;

import javax.net.ssl.SSLException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@Log4j2
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class DomainResolutionTest {

    static {
        System.setProperty("AUTH_TOKEN", "123456");
    }

    private final UdpEchoServer udpEchoServer = new UdpEchoServer();
    private WebSocketServer webSocketServer;

    @BeforeAll
    void setup() throws SSLException {
        udpEchoServer.start();

        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("accounts-domain.yml");
        assertNotNull(inputStream, "Configuration file not found in resources");
        Yaml yaml = new Yaml();
        Accounts accounts = yaml.loadAs(inputStream, Accounts.class);
        webSocketServer = new WebSocketServer();
        webSocketServer.start(new TokenAuthentication(accounts));
    }

    @AfterAll
    void tearDown() throws InterruptedException {
        udpEchoServer.stop();
        webSocketServer.stop();
    }

    @Test
    void testDomainResolution() throws Exception {
        // Test that localhost domain resolves correctly
        HttpClient client = HttpClient.newHttpClient();
        CompletableFuture<WebSocket> wsFuture = new CompletableFuture<>();
        AtomicReference<String> receivedMessage = new AtomicReference<>();
        CompletableFuture<Void> messageFuture = new CompletableFuture<>();

        WebSocket.Listener listener = new WebSocket.Listener() {
            @Override
            public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                receivedMessage.set(data.toString());
                messageFuture.complete(null);
                return CompletableFuture.completedFuture(null);
            }

            @Override
            public void onError(WebSocket webSocket, Throwable error) {
                log.error("WebSocket error", error);
                messageFuture.completeExceptionally(error);
            }
        };

        // Connect using domain name "localhost" instead of IP
        client.newWebSocketBuilder()
                .header("X-Auth-Type", "Token")
                .header("X-Auth-Token", "123456")
                .header("X-Route-Address", "localhost")
                .header("X-Route-Port", "8888")
                .connectTimeout(Duration.ofSeconds(5))
                .buildAsync(URI.create("ws://localhost:8080/tunnel"), listener)
                .whenComplete((ws, error) -> {
                    if (error != null) {
                        wsFuture.completeExceptionally(error);
                    } else {
                        wsFuture.complete(ws);
                    }
                });

        // Wait for WebSocket connection
        WebSocket ws = wsFuture.get(10, TimeUnit.SECONDS);
        assertNotNull(ws);

        // Give some time for the connection to be fully established
        Thread.sleep(2000);

        // Test that the connection is working by sending data
        // (This would require more setup with actual UDP communication)
        
        ws.sendClose(WebSocket.NORMAL_CLOSURE, "Test complete").get(5, TimeUnit.SECONDS);
    }

    @Test
    void testInvalidDomainResolution() throws Exception {
        // Test that an invalid domain fails gracefully
        HttpClient client = HttpClient.newHttpClient();
        CompletableFuture<WebSocket> wsFuture = new CompletableFuture<>();
        AtomicReference<Throwable> errorRef = new AtomicReference<>();

        WebSocket.Listener listener = new WebSocket.Listener() {
            @Override
            public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                log.info("WebSocket closed: {} - {}", statusCode, reason);
                return CompletableFuture.completedFuture(null);
            }

            @Override
            public void onError(WebSocket webSocket, Throwable error) {
                log.info("WebSocket error (expected for invalid domain)", error);
                errorRef.set(error);
            }
        };

        // Connect using invalid domain name
        try {
            client.newWebSocketBuilder()
                    .header("X-Auth-Type", "Token")
                    .header("X-Auth-Token", "123456")
                    .header("X-Route-Address", "invalid-domain-that-does-not-exist.local")
                    .header("X-Route-Port", "8888")
                    .connectTimeout(Duration.ofSeconds(5))
                    .buildAsync(URI.create("ws://localhost:8080/tunnel"), listener)
                    .whenComplete((ws, error) -> {
                        if (error != null) {
                            wsFuture.completeExceptionally(error);
                        } else {
                            wsFuture.complete(ws);
                        }
                    });

            WebSocket ws = wsFuture.get(10, TimeUnit.SECONDS);
            
            // If we get here, the connection was established but should close shortly
            // due to DNS resolution failure
            Thread.sleep(3000);
            
            // The WebSocket should be closed
            assertTrue(ws.isInputClosed() || ws.isOutputClosed(), 
                    "WebSocket should be closed due to DNS resolution failure");
        } catch (Exception e) {
            // Connection failure is also acceptable - it means the server closed the connection
            // due to DNS resolution failure
            log.info("Connection failed as expected: {}", e.getMessage());
        }
    }

    @Test
    void testIPAddressStillWorks() throws Exception {
        // Test backwards compatibility - IP addresses should still work
        HttpClient client = HttpClient.newHttpClient();
        CompletableFuture<WebSocket> wsFuture = new CompletableFuture<>();

        WebSocket.Listener listener = new WebSocket.Listener() {
            @Override
            public void onError(WebSocket webSocket, Throwable error) {
                log.error("WebSocket error", error);
                wsFuture.completeExceptionally(error);
            }
        };

        // Connect using IP address
        client.newWebSocketBuilder()
                .header("X-Auth-Type", "Token")
                .header("X-Auth-Token", "123456")
                .header("X-Route-Address", "127.0.0.1")
                .header("X-Route-Port", "8888")
                .connectTimeout(Duration.ofSeconds(5))
                .buildAsync(URI.create("ws://localhost:8080/tunnel"), listener)
                .whenComplete((ws, error) -> {
                    if (error != null) {
                        wsFuture.completeExceptionally(error);
                    } else {
                        wsFuture.complete(ws);
                    }
                });

        // Wait for WebSocket connection
        WebSocket ws = wsFuture.get(10, TimeUnit.SECONDS);
        assertNotNull(ws);

        // Give some time for the connection to be fully established
        Thread.sleep(2000);

        ws.sendClose(WebSocket.NORMAL_CLOSURE, "Test complete").get(5, TimeUnit.SECONDS);
    }
}
