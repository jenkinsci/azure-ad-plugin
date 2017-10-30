/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread.scribe;

import com.github.scribejava.core.extractors.TokenExtractor;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthConfig;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.microsoft.jenkins.azuread.Constants;
import org.apache.commons.lang.StringUtils;
import com.github.scribejava.core.builder.api.DefaultApi20;

public class AzureApi extends DefaultApi20 {

    public static final String DEFAULT_TENANT = "common";

    private String tenant;

    private String resource;

    protected AzureApi(String resource, String tenant) {
        this.resource = resource;
        this.tenant = tenant;
    }

    public static AzureApi instance(String resource) {
        return instance(resource, DEFAULT_TENANT);
    }

    public static AzureApi instance(String resource, String tenant) {
        return new AzureApi(resource, tenant);
    }

    private String getBaseEndpoint() {
        StringBuilder url = new StringBuilder();
        url.append(Constants.DEFAULT_AUTHENTICATION_ENDPOINT);
        if (StringUtils.isNotEmpty(tenant)) {
            url.append(tenant);
        } else {
            url.append(DEFAULT_TENANT);
        }
        url.append("/oauth2");
        return url.toString();
    }

    @Override
    public String getAccessTokenEndpoint() {
        return getBaseEndpoint() + "/token";
    }
    @Override
    protected String getAuthorizationBaseUrl() {
        return getBaseEndpoint() + "/authorize";
    }

    @Override
    public TokenExtractor<OAuth2AccessToken> getAccessTokenExtractor() {
        return AzureJsonTokenExtractor.instance();
    }

    @Override
    public OAuth20Service createService(OAuthConfig config) {
        return new AzureOAuthServiceImpl(this, config);
    }

    public String getTenant() {
        return tenant;
    }

    public String getResource() {
        return resource;
    }
}
