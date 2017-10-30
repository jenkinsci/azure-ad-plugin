/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread.scribe;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.scribejava.core.model.OAuth2AccessToken;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class AzureToken extends OAuth2AccessToken {

    private Long expiryOn;

    private String idToken;

    @JsonCreator
    public AzureToken(@JsonProperty("access_token") String accessToken,
                      @JsonProperty("token_type") String tokenType,
                      @JsonProperty("expires_in") Integer expiresIn,
                      @JsonProperty("expiry_on") Long expiryOn,
                      @JsonProperty("refresh_token") String refreshToken,
                      @JsonProperty("scope") String scope,
                      @JsonProperty("id_token") String idToken) {
        super(accessToken, tokenType, expiresIn, refreshToken, scope, null);
        this.expiryOn = expiryOn;
        this.idToken = idToken;
    }

    @SuppressWarnings({"checkstyle:magicnumber"})
    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = 41 * hash + Objects.hashCode(idToken);
        hash = 41 * hash + Objects.hashCode(expiryOn);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        if (!super.equals(obj)) {
            return false;
        }

        final AzureToken other = (AzureToken) obj;
        if (!Objects.equals(expiryOn, other.getExpiryOn())) {
            return false;
        }
        return Objects.equals(idToken, other.getIdToken());
    }

    public Long getExpiryOn() {
        return expiryOn;
    }

    public void setExpiryOn(Long expiryOn) {
        this.expiryOn = expiryOn;
    }

    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }

    public boolean isExpired() {
        return expiryOn < TimeUnit.SECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);
    }

    @Override
    public String toString() {
        return "AzureToken{"
                + "access_token=" + getAccessToken()
                + ", token_type=" + getTokenType()
                + ", expires_in=" + getExpiresIn()
                + ", refresh_token=" + getRefreshToken()
                + ", scope=" + getScope()
                + ", open_id_token=" + idToken + '}';
    }
}
