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

import lombok.extern.log4j.Log4j2;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;

@Log4j2
final class UdpEchoServer {

    private DatagramSocket socket;

    void start() {
        new Thread(() -> {
            byte[] buffer = new byte[1024];

            try {
                socket = new DatagramSocket(new InetSocketAddress("127.0.0.1", 8888));

                log.info("UDP Echo Server started on address {}", socket.getLocalSocketAddress());

                while (!socket.isClosed()) {
                    DatagramPacket requestPacket = new DatagramPacket(buffer, buffer.length);

                    if (socket.isClosed()) {
                        break;
                    }

                    socket.receive(requestPacket);

                    InetAddress clientAddress = requestPacket.getAddress();
                    int clientPort = requestPacket.getPort();
                    String receivedData = new String(requestPacket.getData(), 0, requestPacket.getLength());

                    log.info("Received data {} from {}:{}", receivedData, clientAddress, clientPort);

                    DatagramPacket responsePacket = new DatagramPacket(
                            requestPacket.getData(),
                            requestPacket.getLength(),
                            clientAddress,
                            clientPort
                    );
                    socket.send(responsePacket);
                }

                log.info("UDP Echo Server stopped");
            } catch (IOException e) {
                log.error("UDP Echo Server failed to start", e);
            }
        }).start();
    }

    void stop() {
        if (socket != null) {
            socket.close();
        }
    }
}
