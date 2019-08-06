/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.microsoft.azure.management.graphrbac.ActiveDirectoryGroup;
import hudson.security.SecurityRealm;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.lang.StringUtils;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AzureAdUser implements UserDetails {
    private static final long serialVersionUID = 1779209037664572820L;

    private String name;

    private String givenName;

    private String familyName;

    private String uniqueName;

    private String tenantID;

    private String objectID;

    private String email;

    private List<String> groupOIDs;

    private transient volatile GrantedAuthority[] authorities;

    private AzureAdUser() {
        authorities = new GrantedAuthority[]{SecurityRealm.AUTHENTICATED_AUTHORITY};
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        authorities = new GrantedAuthority[]{SecurityRealm.AUTHENTICATED_AUTHORITY};
    }

    public static AzureAdUser createFromJwt(JwtClaims claims) throws MalformedClaimException {
        if (claims == null) {
            return null;
        }

        AzureAdUser user = new AzureAdUser();
        user.name = (String) claims.getClaimValue("name");
        user.givenName = (String) claims.getClaimValue("given_name");
        user.familyName = (String) claims.getClaimValue("family_name");
        user.uniqueName = (String) claims.getClaimValue("upn");
        if (StringUtils.isEmpty(user.uniqueName)) {
            user.uniqueName = (String) claims.getClaimValue("preferred_username");
        }
        user.tenantID = (String) claims.getClaimValue("tid");
        user.objectID = (String) claims.getClaimValue("oid");
        user.email = (String) claims.getClaimValue("email");
        user.groupOIDs = claims.getStringListClaimValue("groups");
        if (user.groupOIDs == null) {
            user.groupOIDs = new LinkedList<>();
        }

        if (user.objectID == null || user.name == null) {
            throw new BadCredentialsException("Invalid id token: " + claims.toJson());
        }

        if (user.email == null || user.email.isEmpty()) {
            String emailRegEx = "^(.*#)?([A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6})$";
            Pattern r = Pattern.compile(emailRegEx, Pattern.CASE_INSENSITIVE);
            Matcher m = r.matcher(user.uniqueName);

            if (m.find()) {
                user.email = m.group(2);
            }
        }

        return user;
    }

    public void setAuthorities(Collection<ActiveDirectoryGroup> groups) {
        GrantedAuthority[] newAuthorities;
        int i = 0;
        if (!groups.isEmpty()) {
            newAuthorities = new GrantedAuthority[groups.size() * 2 + 2];
            for (ActiveDirectoryGroup group : groups) {
                newAuthorities[i++] = new AzureAdGroup(group.id(), group.name());
                newAuthorities[i++] = new GrantedAuthorityImpl(group.id());
            }
        } else {
            newAuthorities = new GrantedAuthority[groupOIDs.size() * 2 + 2];
            for (String groupOID : groupOIDs) {
                newAuthorities[i++] = new AzureAdGroup(groupOID, groupOID);
                newAuthorities[i++] = new GrantedAuthorityImpl(groupOID);
            }
        }
        newAuthorities[i++] = SecurityRealm.AUTHENTICATED_AUTHORITY;
        newAuthorities[i] = new GrantedAuthorityImpl(objectID);
        this.authorities = newAuthorities;
    }

    @SuppressWarnings({"checkstyle:needbraces"})
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AzureAdUser that = (AzureAdUser) o;

        if (name != null ? !name.equals(that.name) : that.name != null) return false;
        if (givenName != null ? !givenName.equals(that.givenName) : that.givenName != null) return false;
        if (familyName != null ? !familyName.equals(that.familyName) : that.familyName != null) return false;
        if (uniqueName != null ? !uniqueName.equals(that.uniqueName) : that.uniqueName != null) return false;
        if (tenantID != null ? !tenantID.equals(that.tenantID) : that.tenantID != null) return false;
        if (groupOIDs != null ? !groupOIDs.equals(that.groupOIDs) : that.groupOIDs != null) return false;
        return objectID.equals(that.objectID);
    }

    @SuppressWarnings({"checkstyle:magicnumber"})
    @Override
    public int hashCode() {
        int result = name != null ? name.hashCode() : 0;
        result = 31 * result + (givenName != null ? givenName.hashCode() : 0);
        result = 31 * result + (familyName != null ? familyName.hashCode() : 0);
        result = 31 * result + (uniqueName != null ? uniqueName.hashCode() : 0);
        result = 31 * result + (tenantID != null ? tenantID.hashCode() : 0);
        result = 31 * result + (groupOIDs != null ? groupOIDs.hashCode() : 0);
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
        return getUniqueName();
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

    public String getName() {
        return this.name;
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

    public List<String> getGroupOIDs() {
        return groupOIDs;
    }

    @Override
    public String toString() {
        return "AzureAdUser{"
                + "name='" + name + '\''
                + ", givenName='" + givenName + '\''
                + ", familyName='" + familyName + '\''
                + ", uniqueName='" + uniqueName + '\''
                + ", tenantID='" + tenantID + '\''
                + ", objectID='" + objectID + '\''
                + ", email='" + email + '\''
                + ", groups='" + groupOIDs.toString() + '\''
                + ", authorities=" + Arrays.toString(authorities)
                + '}';
    }
}

