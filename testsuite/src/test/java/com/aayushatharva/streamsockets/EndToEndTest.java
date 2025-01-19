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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.yaml.snakeyaml.Yaml;

import javax.net.ssl.SSLException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Log4j2
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EndToEndTest {

    static {
        System.setProperty("AUTH_TOKEN", "123456");
    }

    private final UdpEchoServer udpEchoServer = new UdpEchoServer();

    private WebSocketServer webSocketServer;
    private UdpServer udpServer;

    @BeforeAll
    void setup() throws SSLException {
        udpEchoServer.start();

        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("accounts.yml");
        assertNotNull(inputStream, "Configuration file not found in resources");
        Yaml yaml = new Yaml();
        Accounts accounts = yaml.loadAs(inputStream, Accounts.class);
        webSocketServer = new WebSocketServer();
        webSocketServer.start(new TokenAuthentication(accounts));

        udpServer = new UdpServer();
        udpServer.start();
    }

    @AfterAll
    void tearDown() throws InterruptedException {
        udpEchoServer.stop();
        webSocketServer.stop();
        udpServer.stop();
    }

    @Test
    void proxyUdpToWebSocket() {
        try (DatagramSocket socket = new DatagramSocket()) {
            Thread.sleep(2000);

            for (int i = 0; i < 100; i++) {
                String message = "Hello, World! - " + i;
                byte[] data = message.getBytes();
                socket.send(new DatagramPacket(data, 0, data.length, InetAddress.getByName("127.0.0.1"), 9000));

                DatagramPacket packet = new DatagramPacket(new byte[1024], 1024);
                socket.receive(packet);

                String receivedData = new String(packet.getData(), 0, packet.getLength());
                assertEquals(message, receivedData);
            }
        } catch (Exception e) {
            log.error("Failed to send data to UDP server", e);
        }
    }
}
