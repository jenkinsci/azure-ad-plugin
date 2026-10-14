package com.microsoft.jenkins.azuread;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.microsoft.graph.core.authentication.AzureIdentityAuthenticationProvider;
import io.jenkins.plugins.microsoftgraph.GraphServiceClient;
import io.jenkins.plugins.microsoftgraph.models.User;
import io.jenkins.plugins.microsoftgraph.models.odataerrors.ODataError;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.Supplier;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CaeRecoveringTokenCredentialTest {

    private static final String CLAIMS = "{\"access_token\":{\"nbf\":{\"essential\":true,\"value\":\"1700000000\"}}}";

    /**
     * Mimics an azure-identity credential whose cache keeps returning the token issued before revocation.
     */
    private static final class CachingCredential implements TokenCredential {
        private final String token;

        CachingCredential(String token) {
            this.token = token;
        }

        @Override
        public Mono<AccessToken> getToken(TokenRequestContext request) {
            return Mono.just(getTokenSync(request));
        }

        @Override
        public AccessToken getTokenSync(TokenRequestContext request) {
            return new AccessToken(token, OffsetDateTime.now().plusHours(1));
        }
    }

    /**
     * Issues "stale-token" from the first credential and "fresh-token" from any recreated one.
     */
    private static final class CountingFactory implements Supplier<TokenCredential> {
        private final List<TokenCredential> created = new ArrayList<>();

        @Override
        public TokenCredential get() {
            TokenCredential credential = new CachingCredential(created.isEmpty() ? "stale-token" : "fresh-token");
            created.add(credential);
            return credential;
        }
    }

    private static TokenRequestContext request(String claims) {
        TokenRequestContext context = new TokenRequestContext().addScopes("https://graph.microsoft.com/.default");
        context.setCaeEnabled(true);
        context.setClaims(claims);
        return context;
    }

    @Test
    void reusesCredentialUntilClaimsChallenge() {
        CountingFactory factory = new CountingFactory();
        CaeRecoveringTokenCredential credential = new CaeRecoveringTokenCredential(factory);

        assertEquals("stale-token", credential.getTokenSync(request(null)).getToken());
        assertEquals("stale-token", credential.getToken(request(null)).block().getToken());
        assertEquals(1, factory.created.size());

        assertEquals("fresh-token", credential.getTokenSync(request(CLAIMS)).getToken());
        assertEquals(2, factory.created.size());

        assertEquals("fresh-token", credential.getTokenSync(request(null)).getToken());
        assertEquals("fresh-token", credential.getToken(request(null)).block().getToken());
        assertEquals(2, factory.created.size());
    }

    @Test
    void recreatesCredentialOnAsyncClaimsChallenge() {
        CountingFactory factory = new CountingFactory();
        CaeRecoveringTokenCredential credential = new CaeRecoveringTokenCredential(factory);

        assertEquals("fresh-token", credential.getToken(request(CLAIMS)).block().getToken());
        assertEquals(2, factory.created.size());
    }

    @Test
    void graphRequestRecoversFromCaeChallenge() {
        CountingFactory factory = new CountingFactory();
        GraphServiceClient client = graphClient(new CaeRecoveringTokenCredential(factory));

        User user = client.users().byUserId("user-id").get();

        assertEquals("Fresh User", user.getDisplayName());
        assertEquals(2, factory.created.size());
    }

    @Test
    void graphRequestFailsWithoutRecovery() {
        GraphServiceClient client = graphClient(new CountingFactory().get());

        ODataError error = assertThrows(ODataError.class, () -> client.users().byUserId("user-id").get());
        assertEquals("TokenCreatedWithOutdatedPolicies", error.getError().getCode());
    }

    /**
     * A Graph client whose HTTP layer rejects every token except "fresh-token" with a CAE claims challenge.
     */
    private static GraphServiceClient graphClient(TokenCredential credential) {
        OkHttpClient httpClient = new OkHttpClient.Builder()
                .addInterceptor(chain -> {
                    Request request = chain.request();
                    if ("Bearer fresh-token".equals(request.header("Authorization"))) {
                        return jsonResponse(request, 200, "{\"id\":\"user-id\",\"displayName\":\"Fresh User\"}")
                                .build();
                    }
                    String claims = Base64.getEncoder().encodeToString(CLAIMS.getBytes(StandardCharsets.UTF_8));
                    return jsonResponse(request, 401, "{\"error\":{\"code\":\"TokenCreatedWithOutdatedPolicies\","
                            + "\"message\":\"Continuous access evaluation resulted in challenge with result: "
                            + "InteractionRequired and code: TokenCreatedWithOutdatedPolicies\"}}")
                            .header("WWW-Authenticate", "Bearer realm=\"\", authorization_uri=\""
                                    + "https://login.microsoftonline.com/common/oauth2/authorize\", "
                                    + "error=\"insufficient_claims\", claims=\"" + claims + "\"")
                            .build();
                })
                .build();
        AzureIdentityAuthenticationProvider authProvider = new AzureIdentityAuthenticationProvider(
                credential, new String[]{"graph.microsoft.com"}, "https://graph.microsoft.com/.default");
        return new GraphServiceClient(authProvider, httpClient);
    }

    private static Response.Builder jsonResponse(Request request, int code, String body) {
        return new Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(code)
                .message(code == 200 ? "OK" : "Unauthorized")
                .body(ResponseBody.create(body, MediaType.get("application/json")));
    }
}
