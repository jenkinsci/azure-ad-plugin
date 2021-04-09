/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread.scribe;

import com.azure.identity.AzureAuthorityHosts;
import com.github.scribejava.core.extractors.TokenExtractor;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthConfig;
import com.github.scribejava.core.model.ParameterList;
import org.apache.commons.lang.StringUtils;
import com.github.scribejava.core.builder.api.DefaultApi20;

public class AzureApi extends DefaultApi20 {

    public static final String DEFAULT_TENANT = "common";

    private String tenant;
    private final String loginEndpoint;

    private String resource;

    protected AzureApi(String resource, String tenant, String loginEndpoint) {
        this.resource = resource;
        this.tenant = tenant;
        this.loginEndpoint = loginEndpoint;
    }

    public static AzureApi instance(String resource) {
        return instance(resource, DEFAULT_TENANT, AzureAuthorityHosts.AZURE_PUBLIC_CLOUD);
    }

    public static AzureApi instance(String resource, String tenant, String loginEndpoint) {
        return new AzureApi(resource, tenant, loginEndpoint);
    }

    private String getBaseEndpoint() {
        StringBuilder url = new StringBuilder();
        url.append(loginEndpoint);
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
        return getBaseEndpoint() + "/v2.0/token";
    }
    @Override
    protected String getAuthorizationBaseUrl() {
        return getBaseEndpoint() + "/v2.0/authorize";
    }

    @Override
    public TokenExtractor<OAuth2AccessToken> getAccessTokenExtractor() {
        return AzureJsonTokenExtractor.instance();
    }

    @Override
    public AzureOAuthService createService(OAuthConfig config) {
        return new AzureOAuthService(this, config);
    }

    public String getTenant() {
        return tenant;
    }

    public String getResource() {
        return resource;
    }

    protected String getLogoutBaseUrl() {
        return getBaseEndpoint() + "/logout";
    }

    public String getLogoutUrl(String postLogoutUrl) {
        final ParameterList parameters = new ParameterList();
        if (postLogoutUrl != null) {
            parameters.add("post_logout_redirect_uri", postLogoutUrl);
        }
        return parameters.appendTo(getLogoutBaseUrl());
    }
}
