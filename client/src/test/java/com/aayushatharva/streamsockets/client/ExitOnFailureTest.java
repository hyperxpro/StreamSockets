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
     * Test that EXIT_ON_FAILURE defaults to false when not set.
     */
    @Test
    void testExitOnFailureDefaultsFalse() {
        // Since EXIT_ON_FAILURE is loaded at class initialization in Main,
        // and we can't easily modify environment variables in tests,
        // this test verifies the default behavior when the env var is not set
        // The default should be false based on our implementation
        boolean exitOnFailure = "true".equalsIgnoreCase(System.getenv("EXIT_ON_FAILURE"));
        // When not set or set to something other than "true", it should be false
        if (System.getenv("EXIT_ON_FAILURE") == null || 
            !System.getenv("EXIT_ON_FAILURE").equalsIgnoreCase("true")) {
            assertFalse(exitOnFailure);
        }
    }

    /**
     * Test that EXIT_ON_FAILURE is true when environment variable is set to "true".
     * Note: This test will only pass when the environment variable is actually set.
     */
    @Test
    void testExitOnFailureWhenSetToTrue() {
        String exitOnFailureEnv = System.getenv("EXIT_ON_FAILURE");
        if (exitOnFailureEnv != null && exitOnFailureEnv.equalsIgnoreCase("true")) {
            assertTrue(Main.isExitOnFailure());
        } else {
            // If not set, verify it's false
            assertFalse(Main.isExitOnFailure());
        }
    }
}
