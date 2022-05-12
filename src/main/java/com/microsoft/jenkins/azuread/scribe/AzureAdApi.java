package com.microsoft.jenkins.azuread.scribe;

import com.github.scribejava.apis.MicrosoftAzureActiveDirectory20Api;

public class AzureAdApi extends MicrosoftAzureActiveDirectory20Api {

    private final String tenant;
    private String authorityHost;
    private static final String OAUTH_2 = "/oauth2";

    AzureAdApi(String tenant, String authorityHost) {
        super(tenant);
        this.authorityHost = authorityHost;
        this.tenant = tenant;
    }

    public static AzureAdApi custom(String tenant, String authorityHost) {
        return new AzureAdApi(tenant, authorityHost);
    }

    @Override
    public String getAccessTokenEndpoint() {
        return authorityHost + tenant + OAUTH_2 + getEndpointVersionPath() + "/token";
    }

    @Override
    protected String getAuthorizationBaseUrl() {
        return authorityHost + tenant + OAUTH_2 + getEndpointVersionPath() + "/authorize";
    }

    public String getLogoutUrl() {
        return authorityHost + tenant + OAUTH_2 + "/logout";
    }
}
