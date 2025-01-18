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

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

public final class TokenAuthentication {

    private static final Logger log = LogManager.getLogger(TokenAuthentication.class);
    private final List<Accounts.Account> activeAccounts = new CopyOnWriteArrayList<>();
    private final Accounts accounts;

    public TokenAuthentication(String accountConfigFile) {
        Yaml yaml = new Yaml();
        try (FileInputStream inputStream = new FileInputStream(accountConfigFile)) {
            accounts = yaml.loadAs(inputStream, Accounts.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load configuration file: " + accountConfigFile, e);
        }
    }

    public TokenAuthentication(Accounts accounts) {
        this.accounts = accounts;

        if (hasDuplicateTokens(accounts.getAccounts())) {
            throw new IllegalArgumentException("Each account must have a unique token");
        }
    }

    /**
     * Authenticate a token for a route and client IP.
     *
     * @param token    The token to authenticate.
     * @param route    The route to which client wants to connect to.
     * @param clientIp The client IP from which the request is coming.
     * @return {@link Accounts.Account} if the token is valid and the client IP is allowed, otherwise null.
     */
    public Accounts.Account authenticate(String token, String route, String clientIp) {
        for (Accounts.Account account : accounts.getAccounts()) {
            if (account.getToken().equals(token)) {
                if (account.getRoutes().contains(route)) {
                    for (String allowedIp : account.getAllowedIps()) {
                        if (isIpInCidr(clientIp, allowedIp)) {
                            return account;
                        }
                    }
                    log.debug("Client IP: {} is not allowed for the token: {}", clientIp, token);
                } else {
                    log.debug("Route does not match for Client IP: {}", clientIp);
                }
            } else {
                log.debug("Token does not match for Client IP: {}", clientIp);
            }
        }
        return null;
    }

    public boolean leaseAccount(Accounts.Account account) {
        if (account == null) {
            return false;
        } else if (activeAccounts.contains(account) && !account.isReuse()) {
            return false;
        } else {
            activeAccounts.add(account);
            return true;
        }
    }

    private static boolean isIpInCidr(String ip, String cidr) {
        IPAddressString ipAddressString = new IPAddressString(ip);
        IPAddressString cidrAddressString = new IPAddressString(cidr);
        IPAddress ipAddress = ipAddressString.getAddress();
        IPAddress cidrAddress = cidrAddressString.getAddress();
        return cidrAddress.contains(ipAddress);
    }

    private static boolean hasDuplicateTokens(List<Accounts.Account> accounts) {
        // Use a Set to track tokens and identify duplicates
        Set<String> uniqueTokens = new HashSet<>();

        return accounts.stream()
                .map(Accounts.Account::getToken) // Extract tokens
                .anyMatch(token -> !uniqueTokens.add(token)); // Check if already exists in the Set
    }
}
