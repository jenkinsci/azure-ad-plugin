/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import hudson.security.SecurityRealm;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.lang.StringUtils;

public final class AzureAdUser implements UserDetails {

    private String userName;

    private String givenName;

    private String familyName;

    private String uniqueName;

    private String tenantID;

    private String objectID;

    private transient volatile GrantedAuthority[] authorities;

    private AzureAdUser() {
        authorities = new GrantedAuthority[]{SecurityRealm.AUTHENTICATED_AUTHORITY};
    }

    public static AzureAdUser createFromJwt(String jwt) {
        if (StringUtils.isEmpty(jwt)) {
            return null;
        }

        DecodedJWT decoded = JWT.decode(jwt);
        AzureAdUser user = new AzureAdUser();
        user.userName = decoded.getClaim("name").asString();
        user.givenName = decoded.getClaim("given_name").asString();
        user.familyName = decoded.getClaim("family_name").asString();
        user.uniqueName = decoded.getClaim("unique_name").asString();
        user.tenantID = decoded.getClaim("tid").asString();
        user.objectID = decoded.getClaim("oid").asString();
        if (user.objectID == null || user.userName == null) {
            throw new RuntimeException("Invalid id token: " + decoded.getPayload());
        }
        return user;
    }

    @SuppressWarnings({"checkstyle:needbraces"})
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AzureAdUser that = (AzureAdUser) o;

        if (userName != null ? !userName.equals(that.userName) : that.userName != null) return false;
        if (givenName != null ? !givenName.equals(that.givenName) : that.givenName != null) return false;
        if (familyName != null ? !familyName.equals(that.familyName) : that.familyName != null) return false;
        if (uniqueName != null ? !uniqueName.equals(that.uniqueName) : that.uniqueName != null) return false;
        if (tenantID != null ? !tenantID.equals(that.tenantID) : that.tenantID != null) return false;
        return objectID.equals(that.objectID);
    }

    @SuppressWarnings({"checkstyle:magicnumber"})
    @Override
    public int hashCode() {
        int result = userName != null ? userName.hashCode() : 0;
        result = 31 * result + (givenName != null ? givenName.hashCode() : 0);
        result = 31 * result + (familyName != null ? familyName.hashCode() : 0);
        result = 31 * result + (uniqueName != null ? uniqueName.hashCode() : 0);
        result = 31 * result + (tenantID != null ? tenantID.hashCode() : 0);
        result = 31 * result + objectID.hashCode();
        return result;
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return authorities.clone();
    }

    public void setAuthorities(GrantedAuthority[] authorities) {
        this.authorities = authorities;
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return this.userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public String getTenantID() {
        return tenantID;
    }

    public String getObjectID() {
        return objectID;
    }

    public String getUniqueName() {
        return uniqueName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public String getGivenName() {
        return givenName;
    }
}

