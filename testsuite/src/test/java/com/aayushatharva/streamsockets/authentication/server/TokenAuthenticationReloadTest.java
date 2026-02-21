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

package com.aayushatharva.streamsockets.authentication.server;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenAuthenticationReloadTest {

    @Test
    void testReloadAddsNewAccount(@TempDir Path tempDir) throws IOException {
        Path configFile = tempDir.resolve("accounts.yml");
        Files.writeString(configFile, """
                accounts:
                -   name: user1
                    allowedIps:
                    - '127.0.0.1'
                    reuse: false
                    routes:
                    - '127.0.0.1:5050'
                    token: 'token1'
                """);

        TokenAuthentication auth = new TokenAuthentication(configFile.toString());

        // Initial state: user1 exists, user2 does not
        assertNotNull(auth.authenticate("token1", "127.0.0.1:5050", "127.0.0.1"));
        assertNull(auth.authenticate("token2", "127.0.0.1:6060", "127.0.0.1"));

        // Update file to add user2
        Files.writeString(configFile, """
                accounts:
                -   name: user1
                    allowedIps:
                    - '127.0.0.1'
                    reuse: false
                    routes:
                    - '127.0.0.1:5050'
                    token: 'token1'
                -   name: user2
                    allowedIps:
                    - '127.0.0.1'
                    reuse: false
                    routes:
                    - '127.0.0.1:6060'
                    token: 'token2'
                """);

        auth.reload();

        // After reload: both users exist
        assertNotNull(auth.authenticate("token1", "127.0.0.1:5050", "127.0.0.1"));
        assertNotNull(auth.authenticate("token2", "127.0.0.1:6060", "127.0.0.1"));
    }

    @Test
    void testReloadRemovesAccount(@TempDir Path tempDir) throws IOException {
        Path configFile = tempDir.resolve("accounts.yml");
        Files.writeString(configFile, """
                accounts:
                -   name: user1
                    allowedIps:
                    - '127.0.0.1'
                    reuse: false
                    routes:
                    - '127.0.0.1:5050'
                    token: 'token1'
                -   name: user2
                    allowedIps:
                    - '127.0.0.1'
                    reuse: false
                    routes:
                    - '127.0.0.1:6060'
                    token: 'token2'
                """);

        TokenAuthentication auth = new TokenAuthentication(configFile.toString());

        // Initial state: both users exist
        assertNotNull(auth.authenticate("token1", "127.0.0.1:5050", "127.0.0.1"));
        assertNotNull(auth.authenticate("token2", "127.0.0.1:6060", "127.0.0.1"));

        // Update file to remove user2
        Files.writeString(configFile, """
                accounts:
                -   name: user1
                    allowedIps:
                    - '127.0.0.1'
                    reuse: false
                    routes:
                    - '127.0.0.1:5050'
                    token: 'token1'
                """);

        auth.reload();

        // After reload: user1 exists, user2 is removed
        assertNotNull(auth.authenticate("token1", "127.0.0.1:5050", "127.0.0.1"));
        assertNull(auth.authenticate("token2", "127.0.0.1:6060", "127.0.0.1"));
    }

    @Test
    void testReloadPreservesStateOnInvalidFile(@TempDir Path tempDir) throws IOException {
        Path configFile = tempDir.resolve("accounts.yml");
        Files.writeString(configFile, """
                accounts:
                -   name: user1
                    allowedIps:
                    - '127.0.0.1'
                    reuse: false
                    routes:
                    - '127.0.0.1:5050'
                    token: 'token1'
                """);

        TokenAuthentication auth = new TokenAuthentication(configFile.toString());
        assertNotNull(auth.authenticate("token1", "127.0.0.1:5050", "127.0.0.1"));

        // Delete the file to simulate missing file
        Files.delete(configFile);

        // Reload should fail gracefully
        auth.reload();

        // Original state should be preserved
        assertNotNull(auth.authenticate("token1", "127.0.0.1:5050", "127.0.0.1"));
    }

    @Test
    void testReloadPreservesStateOnDuplicateTokens(@TempDir Path tempDir) throws IOException {
        Path configFile = tempDir.resolve("accounts.yml");
        Files.writeString(configFile, """
                accounts:
                -   name: user1
                    allowedIps:
                    - '127.0.0.1'
                    reuse: false
                    routes:
                    - '127.0.0.1:5050'
                    token: 'token1'
                """);

        TokenAuthentication auth = new TokenAuthentication(configFile.toString());
        assertNotNull(auth.authenticate("token1", "127.0.0.1:5050", "127.0.0.1"));

        // Write file with duplicate tokens
        Files.writeString(configFile, """
                accounts:
                -   name: user1
                    allowedIps:
                    - '127.0.0.1'
                    reuse: false
                    routes:
                    - '127.0.0.1:5050'
                    token: 'same_token'
                -   name: user2
                    allowedIps:
                    - '127.0.0.1'
                    reuse: false
                    routes:
                    - '127.0.0.1:6060'
                    token: 'same_token'
                """);

        // Reload should reject duplicate tokens
        auth.reload();

        // Original state should be preserved
        assertNotNull(auth.authenticate("token1", "127.0.0.1:5050", "127.0.0.1"));
    }

    @Test
    void testReloadNoOpWithoutConfigFile() {
        Accounts accounts = new Accounts();
        Accounts.Account account = new Accounts.Account();
        account.setName("user1");
        account.setToken("token1");
        account.setReuse(false);
        account.setRoutes(List.of("127.0.0.1:5050"));
        account.setAllowedIps(List.of("127.0.0.1"));
        accounts.setAccounts(List.of(account));

        TokenAuthentication auth = new TokenAuthentication(accounts);
        assertNotNull(auth.authenticate("token1", "127.0.0.1:5050", "127.0.0.1"));

        // Reload without config file should be a no-op
        auth.reload();

        // State should be preserved
        assertNotNull(auth.authenticate("token1", "127.0.0.1:5050", "127.0.0.1"));
    }

    @Test
    void testReloadUpdatesRoutes(@TempDir Path tempDir) throws IOException {
        Path configFile = tempDir.resolve("accounts.yml");
        Files.writeString(configFile, """
                accounts:
                -   name: user1
                    allowedIps:
                    - '127.0.0.1'
                    reuse: false
                    routes:
                    - '127.0.0.1:5050'
                    token: 'token1'
                """);

        TokenAuthentication auth = new TokenAuthentication(configFile.toString());

        // Initial: route 5050 works, route 6060 does not
        assertNotNull(auth.authenticate("token1", "127.0.0.1:5050", "127.0.0.1"));
        assertNull(auth.authenticate("token1", "127.0.0.1:6060", "127.0.0.1"));
        assertTrue(auth.containsRoute("127.0.0.1:5050"));

        // Update file to change routes
        Files.writeString(configFile, """
                accounts:
                -   name: user1
                    allowedIps:
                    - '127.0.0.1'
                    reuse: false
                    routes:
                    - '127.0.0.1:6060'
                    token: 'token1'
                """);

        auth.reload();

        // After reload: route 6060 works, route 5050 does not
        assertNull(auth.authenticate("token1", "127.0.0.1:5050", "127.0.0.1"));
        assertNotNull(auth.authenticate("token1", "127.0.0.1:6060", "127.0.0.1"));
        assertTrue(auth.containsRoute("127.0.0.1:6060"));
    }
}
