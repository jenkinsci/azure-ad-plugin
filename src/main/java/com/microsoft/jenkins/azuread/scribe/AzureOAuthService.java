/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread.scribe;

import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthConfig;
import com.github.scribejava.core.model.OAuthConstants;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.oauth.OAuth20Service;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

public class AzureOAuthService extends OAuth20Service {

    public AzureOAuthService(AzureApi api, OAuthConfig config) {
        super(api, config);
    }

    @Override
    protected OAuthRequest createAccessTokenRequest(String code) {
        OAuthRequest request = super.createAccessTokenRequest(code);
        request.addParameter("resource", getApi().getResource());
        return request;
    }

    protected OAuthRequest createAccessTokenCredentialGrantRequest() {
        final OAuthRequest request = new OAuthRequest(getApi().getAccessTokenVerb(), getApi().getAccessTokenEndpoint());
        final OAuthConfig config = getConfig();
        request.addParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
        request.addParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
        request.addParameter(OAuthConstants.SCOPE, config.getScope());
        request.addParameter(OAuthConstants.GRANT_TYPE, "client_credentials");
        return request;
    }

    public OAuth2AccessToken getAccessTokenCredentialGrant()
            throws InterruptedException, ExecutionException, IOException {
        final OAuthRequest request = createAccessTokenCredentialGrantRequest();
        return sendAccessTokenRequestSync(request);
    }

    @Override
    public AzureApi getApi() {
        return (AzureApi) super.getApi();
    }

    public final String getLogoutUrl() {
        return getLogoutUrl(null);
    }

    public String getLogoutUrl(String postLogoutUrl) {
        return getApi().getLogoutUrl(postLogoutUrl);
    }
}
