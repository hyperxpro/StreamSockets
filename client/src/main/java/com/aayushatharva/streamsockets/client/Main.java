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

package com.aayushatharva.streamsockets.client;

import lombok.extern.log4j.Log4j2;

import javax.net.ssl.SSLException;

import static com.aayushatharva.streamsockets.common.Utils.envValue;

@Log4j2
public final class Main {

    private static final boolean EXIT_ON_FAILURE = "true".equalsIgnoreCase(envValue("EXIT_ON_FAILURE", "false"));

    public static void main(String[] args) throws SSLException {
        if (EXIT_ON_FAILURE) {
            log.info("EXIT_ON_FAILURE is enabled - JVM will exit on connection failure/disconnect for systemd management");
        }
        
        UdpServer udpServer = new UdpServer();
        udpServer.start();
    }
    
    public static boolean isExitOnFailure() {
        return EXIT_ON_FAILURE;
    }
}
