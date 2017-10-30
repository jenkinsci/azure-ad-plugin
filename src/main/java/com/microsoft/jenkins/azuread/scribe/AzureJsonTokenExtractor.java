/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread.scribe;

import com.github.scribejava.core.exceptions.OAuthException;
import com.github.scribejava.core.extractors.TokenExtractor;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.utils.Preconditions;
import com.microsoft.jenkins.azuread.Utils;

import java.io.IOException;

public class AzureJsonTokenExtractor implements TokenExtractor<OAuth2AccessToken> {

    private static class InstanceHolder {
        private static final AzureJsonTokenExtractor INSTANCE = new AzureJsonTokenExtractor();
    }

    public static AzureJsonTokenExtractor instance() {
        return InstanceHolder.INSTANCE;
    }

    protected AzureJsonTokenExtractor() {
    }

    @Override
    public OAuth2AccessToken extract(Response response) throws IOException, OAuthException {
        Preconditions.checkEmptyString(response.getBody(),
                "Response body is incorrect. Can't extract a token from an empty string");
        return Utils.JsonUtil.fromJson(response.getBody(), AzureToken.class);
    }
}
