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

package com.aayushatharva.streamsockets.common;

public final class Utils {

    private Utils() {
        // Prevent instantiation
    }

    public static int envValueAsInt(String key, int defaultValue) {
        String value = System.getenv(key);
        if (value == null) {
            value = System.getProperty(key);
            if (value == null) {
                return defaultValue;
            }
        }
        return Integer.parseInt(value);
    }

    public static String envValue(String key, String defaultValue) {
        String value = System.getenv(key);
        if (value == null) {
            value = System.getProperty(key);
            if (value == null) {
                return defaultValue;
            }
        }
        return value;
    }
}
