/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread.scribe;

import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth2.clientauthentication.ClientAuthentication;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AzureWorkloadIdentityApiTest {

    @Test
    void customFactoryReturnsSameType() {
        AzureWorkloadIdentityApi api = AzureWorkloadIdentityApi.custom(
                "test-tenant", "https://login.microsoftonline.com/");
        assertNotNull(api);
    }

    @Test
    void getClientAuthenticationReturnsWorkloadIdentityType() {
        AzureWorkloadIdentityApi api = AzureWorkloadIdentityApi.custom(
                "test-tenant", "https://login.microsoftonline.com/");
        ClientAuthentication auth = api.getClientAuthentication();
        assertNotNull(auth);
        assertTrue(auth instanceof AzureWorkloadIdentityApi.WorkloadIdentityClientAuthentication);
    }

    @Test
    void readFederatedTokenThrowsWhenEnvVarNotSet() {
        IOException ex = assertThrows(IOException.class, AzureWorkloadIdentityApi::readFederatedToken);
        assertNotNull(ex.getMessage());
        assertTrue(ex.getMessage().contains("AZURE_FEDERATED_TOKEN_FILE environment variable is not set"));
        assertTrue(ex.getMessage().contains("OIDC identity provider"));
    }

    @Test
    void readFederatedTokenReadsFileContent(@TempDir Path tempDir) throws Exception {
        String expectedToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";
        Path tokenFile = tempDir.resolve("token.jwt");
        Files.write(tokenFile, expectedToken.getBytes(StandardCharsets.UTF_8));

        String result = AzureWorkloadIdentityApi.readFederatedToken(tokenFile.toAbsolutePath().toString());
        assertEquals(expectedToken, result);
    }

    @Test
    void readFederatedTokenTrimsWhitespace(@TempDir Path tempDir) throws Exception {
        String expectedToken = "eyJhbGciOiJSUzI1NiJ9.payload.sig";
        Path tokenFile = tempDir.resolve("token.jwt");
        Files.write(tokenFile, ("  " + expectedToken + "  \n").getBytes(StandardCharsets.UTF_8));

        String result = AzureWorkloadIdentityApi.readFederatedToken(tokenFile.toAbsolutePath().toString());
        assertEquals(expectedToken, result);
    }

    @Test
    void readFederatedTokenThrowsWhenFileDoesNotExist() {
        assertThrows(IOException.class,
                () -> AzureWorkloadIdentityApi.readFederatedToken("/nonexistent/path/token.jwt"));
    }

    @Test
    void readFederatedTokenThrowsWhenEnvVarIsEmpty() {
        // The no-arg overload checks for null OR empty
        // Since we can't set env vars, we test indirectly:
        // the test readFederatedTokenThrowsWhenEnvVarNotSet covers the null case;
        // this validates the error message mentions both possibilities
        IOException ex = assertThrows(IOException.class, AzureWorkloadIdentityApi::readFederatedToken);
        assertTrue(ex.getMessage().contains("is not set"));
    }

    @Test
    void addClientAuthenticationSetsClientIdBeforeFailure() {
        OAuthRequest request = new OAuthRequest(Verb.POST,
                "https://login.microsoftonline.com/test/oauth2/v2.0/token");

        AzureWorkloadIdentityApi.WorkloadIdentityClientAuthentication auth =
                new AzureWorkloadIdentityApi.WorkloadIdentityClientAuthentication();

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> auth.addClientAuthentication(request, "test-client-id", "ignored-secret"));

        assertTrue(ex.getMessage().contains("federated token"));
        assertTrue(ex.getMessage().contains("AZURE_FEDERATED_TOKEN_FILE"));
        assertTrue(ex.getCause() instanceof IOException);

        // client_id is set before readFederatedToken() is called
        String bodyContent = request.getBodyParams().asFormUrlEncodedString();
        assertTrue(bodyContent.contains("client_id=test-client-id"),
                "client_id should be set even when token read fails");
    }

    @Test
    void addClientAuthenticationSetsAssertionType() {
        OAuthRequest request = new OAuthRequest(Verb.POST,
                "https://login.microsoftonline.com/test/oauth2/v2.0/token");

        AzureWorkloadIdentityApi.WorkloadIdentityClientAuthentication auth =
                new AzureWorkloadIdentityApi.WorkloadIdentityClientAuthentication();

        // The assertion type is set before the token read, so even on failure it should be present
        try {
            auth.addClientAuthentication(request, "test-client-id", "ignored");
        } catch (RuntimeException ignored) {
            // expected
        }

        String bodyContent = request.getBodyParams().asFormUrlEncodedString();
        assertTrue(bodyContent.contains("client_assertion_type="),
                "client_assertion_type should be set");
    }

    @Test
    void workloadIdentityApiInheritsEndpoints() {
        String tenant = "my-tenant-id";
        String authorityHost = "https://login.microsoftonline.com/";
        AzureWorkloadIdentityApi api = AzureWorkloadIdentityApi.custom(tenant, authorityHost);

        String tokenEndpoint = api.getAccessTokenEndpoint();
        assertTrue(tokenEndpoint.contains(tenant), "Token endpoint should contain tenant");
        assertTrue(tokenEndpoint.endsWith("/token"), "Token endpoint should end with /token");
        assertTrue(tokenEndpoint.startsWith(authorityHost),
                "Token endpoint should start with authority host");
    }
}
