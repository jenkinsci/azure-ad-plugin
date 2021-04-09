/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import hudson.security.SecurityRealm;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AzureAdUser implements UserDetails {
    private static final long serialVersionUID = 1779209037664572820L;

    private String name;

    private String uniqueName;

    private String tenantID;

    private String objectID;

    private String email;

    private List<String> groupOIDs;

    private transient volatile List<GrantedAuthority> authorities;

    private AzureAdUser() {
        authorities = Arrays.asList(SecurityRealm.AUTHENTICATED_AUTHORITY2);
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();

        authorities = Arrays.asList(SecurityRealm.AUTHENTICATED_AUTHORITY2);
    }

    public static AzureAdUser createFromActiveDirectoryUser(com.microsoft.graph.models.User activeDirectoryUser) {
        if (activeDirectoryUser == null) {
            return null;
        }

        AzureAdUser user = new AzureAdUser();
        user.name = activeDirectoryUser.displayName;

        // this may not match what comes in preferred_username in the id_token :(
        // https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims
        // https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-use-email-signin
        // https://stackoverflow.com/questions/67017723/get-preferred-username-with-microsoft-graph-api
        user.uniqueName = activeDirectoryUser.userPrincipalName;
        user.objectID = activeDirectoryUser.id;
        // may not be set if it is not linked as an office365 user
        // even if it will be set via the id_token
        user.email = activeDirectoryUser.mail;
        user.groupOIDs = new LinkedList<>();

        return user;
    }

    public static AzureAdUser createFromJwt(JwtClaims claims) throws MalformedClaimException {
        if (claims == null) {
            return null;
        }

        AzureAdUser user = new AzureAdUser();
        user.name = (String) claims.getClaimValue("name");
        user.uniqueName = (String) claims.getClaimValue("upn");
        if (StringUtils.isEmpty(user.uniqueName)) {
            user.uniqueName = (String) claims.getClaimValue("preferred_username");
        }
        user.tenantID = (String) claims.getClaimValue("tid");
        user.objectID = (String) claims.getClaimValue("oid");
        user.email = (String) claims.getClaimValue("email");
        if (user.email == null && user.uniqueName.contains("@")) {
            user.email = user.uniqueName;
        }
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

    public void setAuthorities(List<AzureAdGroup> groups) {
        List<GrantedAuthority> newAuthorities = new ArrayList<>();
        int i = 0;
        if (!groups.isEmpty()) {
            for (AzureAdGroup group : groups) {
                newAuthorities.add(group);
                newAuthorities.add(new SimpleGrantedAuthority(group.getObjectId()));
            }
        } else {
            for (String groupOID : groupOIDs) {
                newAuthorities.add(new AzureAdGroup(groupOID, groupOID));
                newAuthorities.add(new SimpleGrantedAuthority(groupOID));
            }
        }
        newAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
        newAuthorities.add(new SimpleGrantedAuthority(objectID));
        this.authorities = newAuthorities;
    }

    @SuppressWarnings({"checkstyle:needbraces"})
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        AzureAdUser that = (AzureAdUser) o;

        if (!Objects.equals(name, that.name)) {
            return false;
        }
        if (!Objects.equals(uniqueName, that.uniqueName)) {
            return false;
        }
        if (!Objects.equals(tenantID, that.tenantID)) {
            return false;
        }
        if (groupOIDs != null && that.groupOIDs != null) {
                if (!CollectionUtils.isEqualCollection(groupOIDs, that.groupOIDs)) {
                    return false;
                }
        } else if (groupOIDs != null || that.groupOIDs != null) {
            return false;
        }
        return objectID.equals(that.objectID);
    }

    @Override
    @SuppressWarnings("checkstyle:magicnumber")
    public int hashCode() {
        int result = name != null ? name.hashCode() : 0;
        result = 31 * result + (uniqueName != null ? uniqueName.hashCode() : 0);
        result = 31 * result + (tenantID != null ? tenantID.hashCode() : 0);
        result = 31 * result + (groupOIDs != null ? groupOIDs.hashCode() : 0);
        result = 31 * result + objectID.hashCode();
        return result;
    }

    @Override
    public List<GrantedAuthority> getAuthorities() {
        return authorities;
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
                + ", uniqueName='" + uniqueName + '\''
                + ", tenantID='" + tenantID + '\''
                + ", objectID='" + objectID + '\''
                + ", email='" + email + '\''
                + ", groups='" + groupOIDs.toString() + '\''
                + ", authorities=" + authorities
                + '}';
    }
}
