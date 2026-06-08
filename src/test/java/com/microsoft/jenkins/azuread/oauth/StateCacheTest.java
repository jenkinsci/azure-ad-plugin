package com.microsoft.jenkins.azuread.oauth;

import com.microsoft.jenkins.azuread.AzureSecurityRealm;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class StateCacheTest {

    @AfterEach
    void clearCache() {
        StateCache.CACHE.invalidateAll();
    }

    @Test
    void generateValueAllowsMissingReferer() {
        HttpSession session = sessionWith(null, 123L, "nonce");

        String state = new StateCache().generateValue(session);

        StateCache.CacheHolder holder = StateCache.CACHE.getIfPresent(state);
        assertNotNull(holder);
        assertNull(holder.referrer());
        assertEquals(123L, holder.beginTime());
        assertEquals("nonce", holder.nonce());
    }

    @Test
    void generateValueStoresRefererWhenPresent() {
        HttpSession session = sessionWith("https://jenkins.example/job/example/", 456L, "other-nonce");

        String state = new StateCache().generateValue(session);

        StateCache.CacheHolder holder = StateCache.CACHE.getIfPresent(state);
        assertNotNull(holder);
        assertEquals("https://jenkins.example/job/example/", holder.referrer());
        assertEquals(456L, holder.beginTime());
        assertEquals("other-nonce", holder.nonce());
    }

    private static HttpSession sessionWith(String referer, long beginTime, String nonce) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(AzureSecurityRealm.REFERER_ATTRIBUTE, referer);
        attributes.put(AzureSecurityRealm.TIMESTAMP_ATTRIBUTE, beginTime);
        attributes.put(AzureSecurityRealm.NONCE_ATTRIBUTE, nonce);

        return (HttpSession) Proxy.newProxyInstance(
                HttpSession.class.getClassLoader(),
                new Class<?>[]{HttpSession.class},
                (proxy, method, args) -> {
                    return switch (method.getName()) {
                        case "getAttribute" -> attributes.get(args[0]);
                        case "toString" -> "StateCacheTestHttpSession";
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "equals" -> proxy == args[0];
                        default -> throw new UnsupportedOperationException(method.getName());
                    };
                });
    }
}
