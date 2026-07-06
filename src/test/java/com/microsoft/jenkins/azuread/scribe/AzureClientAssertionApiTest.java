package com.microsoft.jenkins.azuread.scribe;

import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth2.clientauthentication.ClientAuthentication;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AzureClientAssertionApiTest {

    private static final String AUTHORITY_HOST = "https://login.microsoftonline.com/";

    @Test
    void customFactoryReturnsSameType() {
        AzureClientAssertionApi api = AzureClientAssertionApi.custom(
                "test-tenant", AUTHORITY_HOST, tokenEndpoint -> "assertion");
        assertNotNull(api);
    }

    @Test
    void addClientAuthenticationSetsAssertionParameters() {
        AzureClientAssertionApi api = AzureClientAssertionApi.custom(
                "test-tenant", AUTHORITY_HOST, tokenEndpoint -> "assertion-for-" + tokenEndpoint);
        OAuthRequest request = new OAuthRequest(Verb.POST, api.getAccessTokenEndpoint());

        ClientAuthentication auth = api.getClientAuthentication();
        assertNotNull(auth);
        auth.addClientAuthentication(request, "test-client-id", null);

        String bodyContent = request.getBodyParams().asFormUrlEncodedString();
        assertThat(bodyContent, containsString("client_id=test-client-id"));
        assertThat(bodyContent, containsString(
                "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"));
        // the factory receives the token endpoint, needed as the `aud` claim of certificate-signed assertions
        assertThat(bodyContent, containsString("client_assertion=assertion-for-https%3A%2F%2Flogin.microsoftonline.com"));
    }

    @Test
    void clientAssertionApiInheritsEndpoints() {
        String tenant = "my-tenant-id";
        AzureClientAssertionApi api = AzureClientAssertionApi.custom(tenant, AUTHORITY_HOST, tokenEndpoint -> "assertion");

        String tokenEndpoint = api.getAccessTokenEndpoint();
        assertThat(tokenEndpoint, containsString(tenant));
        assertThat(tokenEndpoint, endsWith("/token"));
        assertThat(tokenEndpoint, startsWith(AUTHORITY_HOST));
    }
}
