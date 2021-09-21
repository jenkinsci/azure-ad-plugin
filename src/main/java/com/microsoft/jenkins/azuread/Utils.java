/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import hudson.Functions;
import hudson.ProxyConfiguration;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import org.jose4j.http.Get;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public final class Utils {

    private Utils() {
    }

    public static FormValidation undecidableResponse(String value) {
        final String v = value.substring(1, value.length() - 1);
        String ev = Functions.escape(v);

        return FormValidation.respond(FormValidation.Kind.OK, ev);
    }

    public static class UUIDUtil {
        private static final Pattern UUID_PATTERN = Pattern
                .compile("(?i)^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-5][0-9a-f]{3}-?[089ab][0-9a-f]{3}-?[0-9a-f]{12}$");

        public static final boolean isValidUuid(final String uuid) {
            return ((uuid != null)) && UUID_PATTERN.matcher(uuid).matches();
        }
    }

    public static class JsonUtil {
        private static ObjectMapper mapper = new ObjectMapper();

        static {
            mapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        }

        public static <T> T fromJson(String json, Class<T> klazz) {
            try {
                return mapper.readValue(json, klazz);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public static <T> String toJson(T obj) {
            try {
                return mapper.writeValueAsString(obj);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static class JwtUtil {
        public static final long DEFAULT_CACHE_DURATION = TimeUnit.HOURS.toSeconds(24);
        public static final String KEYSTORE_URL = "https://login.microsoftonline.com/common/discovery/keys";

        public static JwtConsumer jwt(final String clientId, final String tenantId) {
            final String expectedIssuer = String.format("https://login.microsoftonline.com/%s/v2.0", tenantId);
            HttpsJwks httpsJwks = new HttpsJwks(KEYSTORE_URL);
            httpsJwks.setDefaultCacheDuration(DEFAULT_CACHE_DURATION);
            ProxyConfiguration proxy = Jenkins.get().getProxy();
            if (proxy != null) {
                Get get = new Get();
                get.setHttpProxy(proxy.createProxy("login.microsoftonline.com"));
                httpsJwks.setSimpleHttpGet(get);
            }

            HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJwks);
            return new JwtConsumerBuilder()
                    .setVerificationKeyResolver(httpsJwksKeyResolver)
                    .setExpectedIssuer(expectedIssuer)
                    .setExpectedAudience(clientId)
                    .setRequireNotBefore()
                    .setRequireExpirationTime()
                    .build();
        }
    }
}

