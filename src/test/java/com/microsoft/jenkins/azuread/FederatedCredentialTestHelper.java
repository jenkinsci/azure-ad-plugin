/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;

/**
 * Shared helpers for federated credential tests.
 * Provides JWT generation, key pair utilities, JWKS/OIDC document builders,
 * and WireMock stub factories.
 */
public final class FederatedCredentialTestHelper {

    public static final String DEFAULT_ISSUER = "https://storage.blob.core.windows.net/oidc";
    public static final String DEFAULT_SUBJECT = "dev-local-jenkins-addon";
    public static final String DEFAULT_AUDIENCE = "api://AzureADTokenExchange";
    public static final String DEFAULT_KID = "local-dev-key-1";
    public static final String DEFAULT_TENANT_ID = "test-tenant-id";
    public static final String DEFAULT_CLIENT_ID = "test-client-id";
    public static final String DUMMY_ACCESS_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.dummy.access_token";

    private FederatedCredentialTestHelper() {
    }

    /**
     * Generate a signed JWT with the given claims.
     *
     * @param issuer       the iss claim
     * @param subject      the sub claim
     * @param audience     the aud claim
     * @param expirySeconds seconds from now until expiry (negative = expired)
     * @param kid          the key ID for the JWT header
     * @param privateKey   the RSA private key to sign with
     * @return the compact serialized JWT string
     * @throws Exception if signing fails
     */
    public static String generateTestJwt(String issuer, String subject, String audience,
                                         int expirySeconds, String kid, PrivateKey privateKey) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setExpirationTimeMinutesInTheFuture(expirySeconds / 60.0f);
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(0);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(privateKey);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue(kid);

        return jws.getCompactSerialization();
    }

    /**
     * Generate an RSA-2048 key pair for test JWT signing.
     */
    public static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    /**
     * Build a JWKS JSON document containing the given public key.
     *
     * @param publicKey the RSA public key
     * @param kid       the key ID
     * @return JSON string
     */
    public static String buildJwksJson(PublicKey publicKey, String kid) throws Exception {
        RsaJsonWebKey jwk = new RsaJsonWebKey((RSAPublicKey) publicKey);
        jwk.setKeyId(kid);
        jwk.setUse("sig");
        jwk.setAlgorithm(AlgorithmIdentifiers.RSA_USING_SHA256);

        JsonWebKeySet jwks = new JsonWebKeySet(jwk);
        return jwks.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    /**
     * Build an OpenID Connect discovery document.
     *
     * @param issuerUrl the issuer URL
     * @param jwksUrl   the JWKS URI
     * @return JSON string
     */
    public static String buildOpenIdConfigJson(String issuerUrl, String jwksUrl) {
        return "{"
                + "\"issuer\":\"" + issuerUrl + "\","
                + "\"jwks_uri\":\"" + jwksUrl + "\","
                + "\"authorization_endpoint\":\"" + issuerUrl + "/authorize\","
                + "\"token_endpoint\":\"" + issuerUrl + "/token\","
                + "\"response_types_supported\":[\"code\"],"
                + "\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"]"
                + "}";
    }

    /**
     * Stub the Entra ID token endpoint on WireMock to return a successful token response.
     */
    public static void mockTokenEndpointSuccess(WireMockServer server, String tenantId) {
        server.stubFor(post(urlPathEqualTo("/" + tenantId + "/oauth2/v2.0/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{"
                                + "\"token_type\":\"Bearer\","
                                + "\"expires_in\":3600,"
                                + "\"access_token\":\"" + DUMMY_ACCESS_TOKEN + "\""
                                + "}")));
    }

    /**
     * Stub the Entra ID token endpoint on WireMock to return an error response.
     */
    public static void mockTokenEndpointError(WireMockServer server, String tenantId,
                                              String error, String errorDescription) {
        server.stubFor(post(urlPathEqualTo("/" + tenantId + "/oauth2/v2.0/token"))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{"
                                + "\"error\":\"" + error + "\","
                                + "\"error_description\":\"" + errorDescription + "\""
                                + "}")));
    }

    /**
     * Stub a successful Graph API user lookup.
     */
    public static void mockGraphUserSuccess(WireMockServer server, String upn) {
        server.stubFor(get(urlPathEqualTo("/v1.0/users/" + upn))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{"
                                + "\"@odata.context\":\"https://graph.microsoft.com/v1.0/$metadata#users/$entity\","
                                + "\"id\":\"test-user-id\","
                                + "\"displayName\":\"Test User\","
                                + "\"userPrincipalName\":\"" + upn + "\","
                                + "\"mail\":\"" + upn + "\""
                                + "}")));
    }

    /**
     * Stub the Graph API user lookup to return a 403 Forbidden response.
     */
    public static void mockGraphUser403(WireMockServer server, String upn) {
        server.stubFor(get(urlPathEqualTo("/v1.0/users/" + upn))
                .willReturn(aResponse()
                        .withStatus(403)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{"
                                + "\"error\":{"
                                + "\"code\":\"Authorization_RequestDenied\","
                                + "\"message\":\"Insufficient privileges to complete the operation.\""
                                + "}"
                                + "}")));
    }

    /**
     * Stub the Graph API users list endpoint to return a successful response.
     */
    public static void mockGraphUsersListSuccess(WireMockServer server) {
        server.stubFor(get(urlPathMatching("/v1.0/users.*"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{"
                                + "\"@odata.context\":\"https://graph.microsoft.com/v1.0/$metadata#users\","
                                + "\"value\":[{"
                                + "\"displayName\":\"Test User\","
                                + "\"userPrincipalName\":\"test@example.com\""
                                + "}]"
                                + "}")));
    }

    /**
     * Stub the OIDC discovery endpoint on WireMock.
     */
    public static void mockOidcDiscovery(WireMockServer server, String issuerUrl, String jwksUrl) {
        server.stubFor(get(urlPathEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(buildOpenIdConfigJson(issuerUrl, jwksUrl))));
    }

    /**
     * Stub the JWKS endpoint on WireMock.
     */
    public static void mockJwksEndpoint(WireMockServer server, String jwksJson) {
        server.stubFor(get(urlPathEqualTo("/jwks.json"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(jwksJson)));
    }
}
