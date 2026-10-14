package com.microsoft.jenkins.azuread;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import hudson.Util;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import reactor.core.publisher.Mono;

/**
 * Recreates the underlying credential when a continuous access evaluation (CAE) claims challenge is received.
 * <p>
 * When Microsoft Graph revokes a CAE token it responds with a claims challenge, which the Graph SDK retries
 * once with the claims attached. The azure-identity credentials can keep returning the revoked token from
 * their in-memory cache, leaving the client failing with {@code TokenCreatedWithOutdatedPolicies} until it is
 * rebuilt. Swapping in a fresh credential, with an empty token cache, forces a new token to be issued.
 *
 * @see <a href="https://github.com/microsoftgraph/msgraph-sdk-java/issues/2306">msgraph-sdk-java#2306</a>
 */
final class CaeRecoveringTokenCredential implements TokenCredential {

    private static final Logger LOGGER = Logger.getLogger(CaeRecoveringTokenCredential.class.getName());

    private final Supplier<TokenCredential> factory;
    private volatile TokenCredential delegate;

    CaeRecoveringTokenCredential(Supplier<TokenCredential> factory) {
        this.factory = factory;
        this.delegate = factory.get();
    }

    @Override
    public Mono<AccessToken> getToken(TokenRequestContext request) {
        return delegateFor(request).getToken(request);
    }

    @Override
    public AccessToken getTokenSync(TokenRequestContext request) {
        return delegateFor(request).getTokenSync(request);
    }

    private TokenCredential delegateFor(TokenRequestContext request) {
        if (Util.fixEmpty(request.getClaims()) != null) {
            LOGGER.log(Level.INFO, "Received a continuous access evaluation claims challenge, recreating credential");
            TokenCredential fresh = factory.get();
            delegate = fresh;
            return fresh;
        }
        return delegate;
    }
}
