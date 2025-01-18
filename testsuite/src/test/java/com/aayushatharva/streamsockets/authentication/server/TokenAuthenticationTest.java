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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenAuthenticationTest {

    private TokenAuthentication tokenAuthentication;

    @BeforeEach
    void setUp() {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("accounts.yml");
        assertNotNull(inputStream, "Configuration file not found in resources");

        Yaml yaml = new Yaml();
        Accounts accounts = yaml.loadAs(inputStream, Accounts.class);

        tokenAuthentication = new TokenAuthentication(accounts);
    }

    @Test
    void testAuthenticateValidTokenAndIp() {
        Accounts.Account account = tokenAuthentication.authenticate("123456", "192.168.1.2:5050", "192.168.1.1");
        assertNotNull(account, "Account should be authenticated");
        assertEquals("user1", account.getName(), "Account name should be 'user1'");
    }

    @Test
    void testAuthenticateInvalidToken() {
        Accounts.Account account = tokenAuthentication.authenticate("invalid_token", "192.168.1.2:5050", "192.168.1.1");
        assertNull(account, "Account should not be authenticated with an invalid token");
    }

    @Test
    void testAuthenticateInvalidIp() {
        Accounts.Account account = tokenAuthentication.authenticate("123456", "192.168.1.2:5050", "10.0.0.1");
        assertNull(account, "Account should not be authenticated with an invalid IP");
    }

    @Test
    void testLeaseAccount() {
        Accounts.Account account = tokenAuthentication.authenticate("123456", "192.168.1.2:5050", "192.168.1.1");
        assertNotNull(account, "Account should be authenticated");
        boolean leased = tokenAuthentication.leaseAccount(account);
        assertTrue(leased, "Account should be leased successfully");
    }

    @Test
    void testLeaseAccountReuseFalse() {
        Accounts.Account account = tokenAuthentication.authenticate("123456", "192.168.1.2:5050", "192.168.1.1");
        assertNotNull(account, "Account should be authenticated");
        tokenAuthentication.leaseAccount(account);
        boolean leasedAgain = tokenAuthentication.leaseAccount(account);
        assertFalse(leasedAgain, "Account should not be leased again if reuse is false");
    }

    @Test
    void testIpInCidr() {
        Accounts.Account account = tokenAuthentication.authenticate("abcdef", "192.168.1.2:5050", "172.16.1.100");
        assertNull(account, "Account should not be authenticated with an invalid IP");
        boolean leased = tokenAuthentication.leaseAccount(account);
        assertFalse(leased, "Account should not be leased");
    }

    @Test
    void testDuplicateTokens() {
        Accounts accounts = new Accounts();
        Accounts.Account account1 = new Accounts.Account();
        account1.setName("user1");
        account1.setToken("duplicate_token");
        account1.setReuse(false);
        account1.setRoutes(List.of("192.168.1.2:5050"));
        account1.setAllowedIps(List.of("192.168.1.1"));

        Accounts.Account account2 = new Accounts.Account();
        account2.setName("user2");
        account2.setToken("duplicate_token");
        account2.setReuse(false);
        account2.setRoutes(List.of("192.168.1.2:5050"));
        account2.setAllowedIps(List.of("192.168.1.1"));

        accounts.setAccounts(List.of(account1, account2));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new TokenAuthentication(accounts);
        });

        assertEquals("Each account must have a unique token", exception.getMessage());
    }
}
