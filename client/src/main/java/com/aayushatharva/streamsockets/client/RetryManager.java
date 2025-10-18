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

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.aayushatharva.streamsockets.common.Utils.envValueAsInt;

/**
 * Manages retry logic with exponential back-off.
 * The delay increases exponentially up to a maximum of 30 seconds, then resets.
 */
@Log4j2
final class RetryManager {

    private static final int INITIAL_DELAY_SECONDS = envValueAsInt("RETRY_INITIAL_DELAY_SECONDS", 1);
    private static final int MAX_DELAY_SECONDS = envValueAsInt("RETRY_MAX_DELAY_SECONDS", 30);
    
    private final AtomicInteger retryCount = new AtomicInteger(0);
    
    /**
     * Calculate the next retry delay using exponential back-off.
     * @return delay in seconds
     */
    int getNextRetryDelay() {
        int count = retryCount.getAndIncrement();
        
        // Calculate exponential delay: initialDelay * 2^count
        int delay = INITIAL_DELAY_SECONDS * (1 << count);
        
        // Cap at MAX_DELAY_SECONDS
        if (delay > MAX_DELAY_SECONDS) {
            delay = MAX_DELAY_SECONDS;
            // Reset counter after reaching max delay to prevent integer overflow
            retryCount.set(0);
        }
        
        log.info("Retry attempt {}, waiting {} seconds before reconnecting", count + 1, delay);
        return delay;
    }
    
    /**
     * Reset the retry counter.
     */
    void reset() {
        retryCount.set(0);
        if (log.isDebugEnabled()) {
            log.debug("Retry counter reset");
        }
    }
    
    /**
     * Schedule a retry attempt.
     * @param runnable the task to execute after the delay
     * @param eventLoop the event loop to schedule on
     */
    void scheduleRetry(Runnable runnable, io.netty.channel.EventLoop eventLoop) {
        int delay = getNextRetryDelay();
        eventLoop.schedule(runnable, delay, TimeUnit.SECONDS);
    }
}
