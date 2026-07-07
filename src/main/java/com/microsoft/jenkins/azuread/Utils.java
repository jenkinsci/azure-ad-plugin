/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import hudson.Functions;
import hudson.ProxyConfiguration;
import hudson.util.FormValidation;
import java.net.URI;
import java.net.URISyntaxException;
import jenkins.model.Jenkins;
import org.jose4j.http.Get;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;

import java.util.concurrent.TimeUnit;

public final class Utils {

    private Utils() {
    }

    public static FormValidation undecidableResponse(String value) {
        final String v = value.substring(1, value.length() - 1);
        String ev = Functions.escape(v);

        return FormValidation.respond(FormValidation.Kind.OK, ev);
    }

    public static class JwtUtil {
        public static final long DEFAULT_CACHE_DURATION = TimeUnit.HOURS.toSeconds(24);
        public static JwtConsumer jwt(final String authorityHost, final String clientId, final String tenantId) {
            String keyDiscoveryUrl = String.format(
                    "%s%s/discovery/keys?appId=%s", authorityHost, tenantId, clientId
            );
            final String expectedIssuer = String.format("%s%s/v2.0", authorityHost, tenantId);
            HttpsJwks httpsJwks = new HttpsJwks(keyDiscoveryUrl);
            httpsJwks.setDefaultCacheDuration(DEFAULT_CACHE_DURATION);
            ProxyConfiguration proxy = Jenkins.get().getProxy();
            if (proxy != null) {
                Get get = new Get();
                try {
                    get.setHttpProxy(proxy.createProxy(new URI(authorityHost).getHost()));
                } catch (URISyntaxException e) {
                    throw new RuntimeException(e);
                }
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

