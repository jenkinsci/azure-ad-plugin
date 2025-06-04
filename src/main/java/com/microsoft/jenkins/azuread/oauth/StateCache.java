package com.microsoft.jenkins.azuread.oauth;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.microsoft.jenkins.azuread.AzureSecurityRealm;
import jakarta.servlet.http.HttpSession;

import java.time.Duration;
import java.util.UUID;

public class StateCache {

    public static final Cache<String, CacheHolder> CACHE = Caffeine.newBuilder().maximumSize(10_000)
            .expireAfterWrite(Duration.ofMinutes(30))
            .build();

    public String generateValue(HttpSession session) {
        final String referer = session.getAttribute(AzureSecurityRealm.REFERER_ATTRIBUTE).toString();
        final Long beginTime = (Long) session.getAttribute(AzureSecurityRealm.TIMESTAMP_ATTRIBUTE);
        final String nonce = session.getAttribute(AzureSecurityRealm.NONCE_ATTRIBUTE).toString();

        final String state = UUID.randomUUID().toString();
        CACHE.put(state, new CacheHolder(referer, beginTime, nonce));
        return state;
    }

    public record CacheHolder(String referrer, Long beginTime, String nonce) {

    }

}
