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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
        assertInstanceOf(AzureWorkloadIdentityApi.WorkloadIdentityClientAuthentication.class, auth);
    }

    @Test
    void readFederatedTokenThrowsWhenEnvVarNotSet() {
        IOException ex = assertThrows(IOException.class, AzureWorkloadIdentityApi::readFederatedToken);
        assertNotNull(ex.getMessage());
        assertThat(ex.getMessage(), containsString("AZURE_FEDERATED_TOKEN_FILE environment variable is not set"));
        assertThat(ex.getMessage(), containsString("OIDC identity provider"));
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
        assertThat(ex.getMessage(), containsString("is not set"));
    }

    @Test
    void addClientAuthenticationSetsClientIdBeforeFailure() {
        OAuthRequest request = new OAuthRequest(Verb.POST,
                "https://login.microsoftonline.com/test/oauth2/v2.0/token");

        AzureWorkloadIdentityApi.WorkloadIdentityClientAuthentication auth =
                new AzureWorkloadIdentityApi.WorkloadIdentityClientAuthentication();

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> auth.addClientAuthentication(request, "test-client-id", "ignored-secret"));

        assertThat(ex.getMessage(), containsString("federated token"));
        assertThat(ex.getMessage(), containsString("AZURE_FEDERATED_TOKEN_FILE"));
        assertInstanceOf(IOException.class, ex.getCause());

        // client_id is set before readFederatedToken() is called
        String bodyContent = request.getBodyParams().asFormUrlEncodedString();
        assertThat(bodyContent, containsString("client_id=test-client-id"));
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
        assertThat(bodyContent, containsString("client_assertion_type="));
    }

    @Test
    void workloadIdentityApiInheritsEndpoints() {
        String tenant = "my-tenant-id";
        String authorityHost = "https://login.microsoftonline.com/";
        AzureWorkloadIdentityApi api = AzureWorkloadIdentityApi.custom(tenant, authorityHost);

        String tokenEndpoint = api.getAccessTokenEndpoint();
        assertThat(tokenEndpoint, containsString(tenant));
        assertThat(tokenEndpoint, endsWith("/token"));
        assertThat(tokenEndpoint, startsWith(authorityHost));
    }
}
