/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import org.apache.commons.lang.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

public class AzureAuthenticationToken implements Authentication {

    private static final long serialVersionUID = 2L;

    private final AzureAdUser azureAdUser;

    public AzureAuthenticationToken(AzureAdUser user) {
        this.azureAdUser = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.azureAdUser != null ? this.azureAdUser.getAuthorities() : Collections.emptyList();
    }

    @Override
    public Object getCredentials() {
        return StringUtils.EMPTY;
    }

    @Override
    public Object getDetails() {
        return null;
    }


    private String getObjectId() {
        return azureAdUser != null ? azureAdUser.getObjectID() : null;
    }

    private String getDisplayName() {
        return azureAdUser != null ? azureAdUser.getName() : null;
    }

    @Override
    public Object getPrincipal() {
        return getObjectId();
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
        return (azureAdUser != null ? azureAdUser.getObjectID() : null);
    }

    public AzureAdUser getAzureAdUser() {
        return azureAdUser;
    }

    @Override
    public String toString() {
        return "AzureAuthenticationToken{"
                + "azureAdUser=" + azureAdUser
                + '}';
    }
}
