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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for WebSocketClientHandler to verify protocol detection
 */
class WebSocketClientHandlerTest {

    @Test
    void testNewProtocolFlag() {
        // Create handler with new protocol
        WebSocketClientHandler handlerNewProtocol = new WebSocketClientHandler(null, true);
        assertTrue(handlerNewProtocol.isUsingNewProtocol(), "Handler should report using new protocol");
        
        // Create handler with old protocol
        WebSocketClientHandler handlerOldProtocol = new WebSocketClientHandler(null, false);
        assertFalse(handlerOldProtocol.isUsingNewProtocol(), "Handler should report using old protocol");
    }
}
