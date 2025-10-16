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

import com.aayushatharva.streamsockets.authentication.server.Accounts;
import com.aayushatharva.streamsockets.authentication.server.TokenAuthentication;
import com.aayushatharva.streamsockets.client.UdpServer;
import com.aayushatharva.streamsockets.client.WebSocketClientHandler;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.yaml.snakeyaml.Yaml;

import javax.net.ssl.SSLException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Log4j2
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class AuthenticationHandlerTest {

    private WebSocketServer webSocketServer;
    private UdpServer udpServer;

    @BeforeAll
    void setup() throws SSLException {

        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("accounts.yml");
        assertNotNull(inputStream, "Configuration file not found in resources");
        Yaml yaml = new Yaml();
        Accounts accounts = yaml.loadAs(inputStream, Accounts.class);
        webSocketServer = new WebSocketServer();
        webSocketServer.start(new TokenAuthentication(accounts));

        System.setProperty("WEBSOCKET_URI", "ws://localhost:8080/tunnel");
        System.setProperty("AUTH_TOKEN", "123456");
        System.setProperty("ROUTE", "127.0.0.1:8888");

        udpServer = new UdpServer();
        udpServer.start();

        // Wait for all futures to complete
        udpServer.channelFutures().forEach(future -> {
            try {
                future.get();
            } catch (Exception e) {
                log.error("Error in UDP server", e);
            }
        });
    }

    @AfterAll
    void tearDown() throws InterruptedException {
        webSocketServer.stop();
        udpServer.stop();
    }

    @Test
    void connectToServerAndAuthSuccess() throws InterruptedException {
        WebSocketClientHandler webSocketClientHandler = udpServer.datagramHandler().webSocketClientFuture().sync().channel().pipeline().get(WebSocketClientHandler.class);

        boolean handshakeSuccess = webSocketClientHandler.handshakeFuture().awaitUninterruptibly().isSuccess();
        assertTrue(handshakeSuccess);

        // With the new approach, handshake completion means authentication is done
        assertTrue(webSocketClientHandler.handshakeFuture().isSuccess());
    }
}
