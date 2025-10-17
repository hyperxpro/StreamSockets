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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RetryManagerTest {

    @Test
    void testExponentialBackoff() {
        RetryManager retryManager = new RetryManager();
        
        // First retry should be 1 second
        int delay1 = retryManager.getNextRetryDelay();
        assertEquals(1, delay1);
        
        // Second retry should be 2 seconds (1 * 2^1)
        int delay2 = retryManager.getNextRetryDelay();
        assertEquals(2, delay2);
        
        // Third retry should be 4 seconds (1 * 2^2)
        int delay3 = retryManager.getNextRetryDelay();
        assertEquals(4, delay3);
        
        // Fourth retry should be 8 seconds (1 * 2^3)
        int delay4 = retryManager.getNextRetryDelay();
        assertEquals(8, delay4);
        
        // Fifth retry should be 16 seconds (1 * 2^4)
        int delay5 = retryManager.getNextRetryDelay();
        assertEquals(16, delay5);
    }
    
    @Test
    void testMaxDelayAndReset() {
        RetryManager retryManager = new RetryManager();
        
        // Keep retrying until we hit the max delay of 30 seconds
        int delay;
        int maxDelayCount = 0;
        
        for (int i = 0; i < 10; i++) {
            delay = retryManager.getNextRetryDelay();
            if (delay == 30) {
                maxDelayCount++;
            }
            // Delay should never exceed 30 seconds
            assertTrue(delay <= 30, "Delay should not exceed 30 seconds, got: " + delay);
        }
        
        // We should hit the max delay at least once
        assertTrue(maxDelayCount > 0, "Should have hit max delay at least once");
    }
    
    @Test
    void testReset() {
        RetryManager retryManager = new RetryManager();
        
        // First retry
        int delay1 = retryManager.getNextRetryDelay();
        assertEquals(1, delay1);
        
        // Second retry
        int delay2 = retryManager.getNextRetryDelay();
        assertEquals(2, delay2);
        
        // Reset the counter
        retryManager.reset();
        
        // After reset, should start from 1 second again
        int delay3 = retryManager.getNextRetryDelay();
        assertEquals(1, delay3);
    }
}
