/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.microsoft.jenkins.azuread.scribe.AzureToken;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.commons.lang.StringUtils;

import java.util.logging.Logger;

public class AzureAuthenticationToken implements Authentication {

    private static final long serialVersionUID = 2L;

    private AzureAdUser azureAdUser;
    private static final Logger LOGGER = Logger.getLogger(AbstractAuthenticationToken.class.getName());

    public AzureAuthenticationToken(AzureToken token) {
        this.azureAdUser = AzureAdUser.createFromJwt(token.getIdToken());
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return this.azureAdUser != null ? this.azureAdUser.getAuthorities() : new GrantedAuthority[0];
    }

    @Override
    public Object getCredentials() {
        return StringUtils.EMPTY;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return azureAdUser.getObjectID();
    }

    @Override
    public boolean isAuthenticated() {
        return azureAdUser != null;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    }

    @Override
    public String getName() {
        return (azureAdUser != null ? azureAdUser.getUsername() : null);
    }

    public AzureAdUser getAzureAdUser() {
        return azureAdUser;
    }
}
