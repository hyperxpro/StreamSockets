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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test class to verify EXIT_ON_FAILURE functionality.
 * Tests that the EXIT_ON_FAILURE environment variable is read correctly.
 */
class ExitOnFailureTest {

    /**
     * Test that EXIT_ON_FAILURE returns a boolean value based on environment variable.
     * By default (when not set or set to anything other than "true"), it should be false.
     */
    @Test
    void testExitOnFailureReturnsValue() {
        // Test that the method returns the expected value based on environment
        String exitOnFailureEnv = System.getenv("EXIT_ON_FAILURE");
        boolean expected = "true".equalsIgnoreCase(exitOnFailureEnv);
        
        // Verify the Main.isExitOnFailure() method matches the environment variable
        boolean actual = Main.isExitOnFailure();
        
        if (expected) {
            assertTrue(actual, "EXIT_ON_FAILURE should be true when env var is set to 'true'");
        } else {
            assertFalse(actual, "EXIT_ON_FAILURE should be false when env var is not set or not 'true'");
        }
    }
}
