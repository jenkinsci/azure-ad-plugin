package com.microsoft.jenkins.azuread.scribe;

import com.github.scribejava.core.oauth2.clientauthentication.ClientAuthentication;

import java.util.function.Function;

/**
 * Custom ScribeJava API for flows authenticating with a client assertion,
 * i.e. certificate-based authentication and Workload Identity Federation.
 *
 * <p>When authenticating to Entra ID, this class replaces the normal
 * {@code client_secret} parameter with a {@code client_assertion} and
 * {@code client_assertion_type}. The assertion is produced by the given
 * factory, which receives the token endpoint (the required {@code aud}
 * claim for certificate-signed assertions).</p>
 */
public class AzureClientAssertionApi extends AzureAdApi {

    private static final String CLIENT_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /**
     * Maps the token endpoint to a signed client assertion (JWT).
     */
    private final Function<String, String> clientAssertionFactory;

    AzureClientAssertionApi(String tenant, String authorityHost, Function<String, String> clientAssertionFactory) {
        super(tenant, authorityHost);
        this.clientAssertionFactory = clientAssertionFactory;
    }

    public static AzureClientAssertionApi custom(
            String tenant, String authorityHost, Function<String, String> clientAssertionFactory) {
        return new AzureClientAssertionApi(tenant, authorityHost, clientAssertionFactory);
    }

    @Override
    public ClientAuthentication getClientAuthentication() {
        return (request, apiKey, apiSecret) -> {
            request.addBodyParameter("client_id", apiKey);
            request.addBodyParameter("client_assertion_type", CLIENT_ASSERTION_TYPE);
            request.addBodyParameter("client_assertion", clientAssertionFactory.apply(getAccessTokenEndpoint()));
        };
    }
}
