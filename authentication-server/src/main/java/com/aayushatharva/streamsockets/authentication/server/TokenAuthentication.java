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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public final class TokenAuthentication {

    private static final Logger log = LogManager.getLogger(TokenAuthentication.class);
    private final List<Accounts.Account> activeAccounts = new CopyOnWriteArrayList<>();
    private final String accountConfigFile;
    private volatile Accounts accounts;
    
    // Performance optimization: O(1) token lookup instead of O(n) linear search
    private volatile Map<String, AccountCache> tokenToAccountCache;
    
    /**
     * Cache structure to avoid repeated lookups and parsing
     */
    private static final class AccountCache {
        final Accounts.Account account;
        final Set<String> routeSet;
        final List<IPAddressString> parsedAllowedIps;
        
        AccountCache(Accounts.Account account) {
            this.account = account;
            // Pre-compute route set for O(1) lookup
            this.routeSet = new HashSet<>(account.getRoutes());
            // Pre-parse IP CIDR ranges to avoid repeated parsing
            this.parsedAllowedIps = account.getAllowedIps().stream()
                    .map(IPAddressString::new)
                    .toList();
        }
    }

    public TokenAuthentication(String accountConfigFile) {
        this.accountConfigFile = accountConfigFile;
        Yaml yaml = new Yaml();
        try (FileInputStream inputStream = new FileInputStream(accountConfigFile)) {
            accounts = yaml.loadAs(inputStream, Accounts.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load configuration file: " + accountConfigFile, e);
        }
        
        if (hasDuplicateTokens(accounts.getAccounts())) {
            throw new IllegalArgumentException("Each account must have a unique token");
        }
        
        // Build token lookup cache for performance
        this.tokenToAccountCache = buildTokenCache(accounts.getAccounts());
    }

    public TokenAuthentication(Accounts accounts) {
        this.accountConfigFile = null;
        this.accounts = accounts;

        if (hasDuplicateTokens(accounts.getAccounts())) {
            throw new IllegalArgumentException("Each account must have a unique token");
        }
        
        // Build token lookup cache for performance
        this.tokenToAccountCache = buildTokenCache(accounts.getAccounts());
    }

    /**
     * Reload accounts from the config file specified at construction time.
     * If no config file was provided, this method does nothing.
     * Thread-safe: uses volatile write to atomically replace the cache.
     */
    public void reload() {
        if (accountConfigFile == null) {
            log.warn("Cannot reload: no config file path was provided");
            return;
        }
        reload(accountConfigFile);
    }

    /**
     * Reload accounts from the specified config file.
     * On failure, the existing accounts are preserved.
     *
     * @param configFile The path to the configuration file.
     */
    public void reload(String configFile) {
        try {
            Yaml yaml = new Yaml();
            Accounts newAccounts;
            try (FileInputStream inputStream = new FileInputStream(configFile)) {
                newAccounts = yaml.loadAs(inputStream, Accounts.class);
            }

            if (hasDuplicateTokens(newAccounts.getAccounts())) {
                log.error("Reload failed: duplicate tokens found in config file: {}", configFile);
                return;
            }

            Map<String, AccountCache> newCache = buildTokenCache(newAccounts.getAccounts());

            // Volatile write ensures visibility to all threads
            this.accounts = newAccounts;
            this.tokenToAccountCache = newCache;
        } catch (Exception e) {
            log.error("Failed to reload configuration file: {}", configFile, e);
        }
    }
    
    /**
     * Build a HashMap for O(1) token lookup with pre-computed route sets and parsed IPs.
     * This significantly improves authentication performance, especially with many accounts.
     */
    private static Map<String, AccountCache> buildTokenCache(List<Accounts.Account> accounts) {
        Map<String, AccountCache> cache = new HashMap<>(accounts.size());
        for (Accounts.Account account : accounts) {
            cache.put(account.getToken(), new AccountCache(account));
        }
        log.info("Built authentication cache for {} accounts", cache.size());
        return cache;
    }

    /**
     * Authenticate a token for a route and client IP.
     * Optimized with O(1) token lookup and pre-parsed CIDR ranges.
     *
     * @param token    The token to authenticate.
     * @param route    The route to which client wants to connect to.
     * @param clientIp The client IP from which the request is coming.
     * @return {@link Accounts.Account} if the token is valid and the client IP is allowed, otherwise null.
     */
    public Accounts.Account authenticate(String token, String route, String clientIp) {
        // O(1) token lookup instead of O(n) linear search
        AccountCache accountCache = tokenToAccountCache.get(token);
        
        if (accountCache == null) {
            if (log.isDebugEnabled()) {
                log.debug("Token does not match for Client IP: {}", clientIp);
            }
            return null;
        }
        
        // O(1) route lookup using HashSet instead of List.contains()
        if (!accountCache.routeSet.contains(route)) {
            if (log.isDebugEnabled()) {
                log.debug("Route {} does not match for Client IP: {}", route, clientIp);
            }
            return null;
        }
        
        // Check IP with pre-parsed CIDR ranges
        IPAddressString clientIpAddress = new IPAddressString(clientIp);
        IPAddress clientIpParsed = clientIpAddress.getAddress();
        
        for (IPAddressString allowedIpCidr : accountCache.parsedAllowedIps) {
            IPAddress allowedRange = allowedIpCidr.getAddress();
            if (allowedRange.contains(clientIpParsed)) {
                return accountCache.account;
            }
        }
        
        if (log.isDebugEnabled()) {
            log.debug("Client IP: {} is not allowed for the token: {}", clientIp, token);
        }
        return null;
    }

    /**
     * Check if the accounts contain a route.
     * Optimized with cached route sets for faster lookup.
     *
     * @param route    The route to check.
     * @return true if the accounts contain the route, false otherwise.
     */
    public boolean containsRoute(String route) {
        // Use cached route sets for O(1) lookup per account instead of List.contains()
        return tokenToAccountCache.values().stream()
                .anyMatch(cache -> cache.routeSet.contains(route));
    }

    /**
     * Lease an account.
     *
     * @param account The account to lease.
     * @return true if the account was leased, false otherwise.
     */
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

    /**
     * Release an account.
     *
     * @param account The account to release.
     * @return true if the account was released, false otherwise.
     */
    public boolean releaseAccount(Accounts.Account account) {
        return activeAccounts.remove(account);
    }

    private static boolean hasDuplicateTokens(List<Accounts.Account> accounts) {
        // Use a Set to track tokens and identify duplicates
        Set<String> uniqueTokens = new HashSet<>();

        return accounts.stream()
                .map(Accounts.Account::getToken) // Extract tokens
                .anyMatch(token -> !uniqueTokens.add(token)); // Check if already exists in the Set
    }
}
