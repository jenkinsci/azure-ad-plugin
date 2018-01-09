/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import hudson.security.SecurityRealm;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.jose4j.jwt.JwtClaims;

import java.util.Collection;

public final class AzureAdUser implements UserDetails {

    private String userName;

    private String givenName;

    private String familyName;

    private String uniqueName;

    private String tenantID;

    private String objectID;

    private String email;

    private transient volatile GrantedAuthority[] authorities;

    private AzureAdUser() {
        authorities = new GrantedAuthority[]{SecurityRealm.AUTHENTICATED_AUTHORITY};
    }

    public static AzureAdUser createFromJwt(JwtClaims claims) {
        if (claims == null) {
            return null;
        }

        AzureAdUser user = new AzureAdUser();
        user.userName = (String) claims.getClaimValue("name");
        user.givenName = (String) claims.getClaimValue("given_name");
        user.familyName = (String) claims.getClaimValue("family_name");
        user.uniqueName = (String) claims.getClaimValue("unique_name");
        user.tenantID = (String) claims.getClaimValue("tid");
        user.objectID = (String) claims.getClaimValue("oid");
        user.email = (String) claims.getClaimValue("email");
        if (user.objectID == null || user.userName == null) {
            throw new BadCredentialsException("Invalid id token: " + claims.toJson());
        }

        Collection<String> groups = AzureCachePool.getBelongingGroupsByOid(user.objectID);
        GrantedAuthority[] authorities = new GrantedAuthority[groups.size()];
        int i = 0;
        for (String objectId : groups) {
            authorities[i++] = new AzureAdGroup(objectId);
        }
        user.authorities = authorities;
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

    public String getEmail() {
        return email;
    }
}

