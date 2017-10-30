/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.microsoft.azure.PagedList;
import com.microsoft.azure.credentials.AzureTokenCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.graphrbac.implementation.ADGroupInner;
import com.microsoft.azure.management.graphrbac.implementation.UserInner;
import hudson.Extension;
import hudson.model.AutoCompletionCandidates;
import hudson.model.Descriptor;
import hudson.security.AuthorizationStrategy;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AzureAdMatrixAuthorizationStategy extends GlobalMatrixAuthorizationStrategy {

    private static final Pattern LONGNAME_PATTERN = Pattern.compile("(.*) \\((.*)\\)");

    private final transient Map<String, String> objId2LongNameMap = new HashMap<>();

    @Override
    public void add(Permission p, String sid) {
        super.add(p, sid);
        String objectId = extractObjectId(sid);
        if (objectId != null) {
            objId2LongNameMap.put(objectId, sid);
        }
    }

    protected static String extractObjectId(String sid) {
        Matcher matcher = LONGNAME_PATTERN.matcher(sid);
        if (matcher.matches()) {
            String displayName = matcher.group(1);
            String objectId = matcher.group(2);
            return objectId;
        } else {
            return null;
        }
    }

    protected static String generateLongName(final String displayName, final String objectId) {
        return String.format("%s (%s)", displayName, objectId);
    }

    protected String getLongName(final String sid) {
        if (objId2LongNameMap.containsKey(sid)) {
            return objId2LongNameMap.get(sid);
        } else {
            return sid;
        }
    }

    @Override
    public boolean hasExplicitPermission(String sid, Permission p) {
        return super.hasExplicitPermission(getLongName(sid), p);
    }

    @Override
    public boolean hasPermission(String sid, Permission p) {
        return super.hasPermission(getLongName(sid), p);
    }

    @Override
    public boolean hasPermission(String sid, Permission p, boolean principal) {
        return super.hasPermission(getLongName(sid), p, principal);
    }

    @Extension
    public static final Descriptor<AuthorizationStrategy> DESCRIPTOR = new DescriptorImpl();

    public static class DescriptorImpl extends GlobalMatrixAuthorizationStrategy.DescriptorImpl {
        @Override
        protected GlobalMatrixAuthorizationStrategy create() {
            return new AzureAdMatrixAuthorizationStategy();
        }

        @Override
        @Nonnull
        public String getDisplayName() {
            return "Azure Active Directory Matrix-based security";
        }

        public AutoCompletionCandidates doAutoCompleteUserOrGroup(@QueryParameter String value)
                throws ExecutionException, IOException, InterruptedException {
            final int maxCandidates = 20;
            if (StringUtils.isEmpty(value)) {
                return null;
            }
            AutoCompletionCandidates c = new AutoCompletionCandidates();

            SecurityRealm realm = Jenkins.getActiveInstance().getSecurityRealm();
            if (!(realm instanceof AzureSecurityRealm)) {
                return null;
            }
            AzureTokenCredentials cred = ((AzureSecurityRealm) realm).getAzureCredential();

            List<AzureObject> candidates = new ArrayList<>();
            System.out.println("search users with prefix: " + value);
            Azure.Authenticated authenticated = Azure.authenticate(cred);
            PagedList<UserInner> matchedUsers = authenticated.activeDirectoryUsers()
                    .inner().list("startswith(displayName,'" + value + "')");
            for (UserInner user : matchedUsers.currentPage().items()) {
                candidates.add(new AzureObject(user.objectId(), user.displayName()));
                if (candidates.size() > maxCandidates) {
                    break;
                }
            }

            if (!matchedUsers.hasNextPage()) {
                System.out.println("search groups with prefix " + value);
                PagedList<ADGroupInner> matchedGroups = authenticated.activeDirectoryGroups()
                        .inner().list("startswith(displayName,'" + value + "')");
                for (ADGroupInner group : matchedGroups.currentPage().items()) {
                    candidates.add(new AzureObject(group.objectId(), group.displayName()));
                    if (candidates.size() > maxCandidates) {
                        break;
                    }
                }
            }

            for (AzureObject obj : candidates) {
                String candadateText = generateLongName(obj.getDisplayName(), obj.getObjectId());
                if (StringUtils.startsWithIgnoreCase(candadateText, value)) {
                    c.add(candadateText);
                }
            }

            return c;
        }
    };

    @Restricted(DoNotUse.class)
    public static class ConverterImpl extends GlobalMatrixAuthorizationStrategy.ConverterImpl {

        @Override
        public GlobalMatrixAuthorizationStrategy create() {
            return new AzureAdMatrixAuthorizationStategy();
        }

        @Override
        @SuppressWarnings("rawtypes")
        public boolean canConvert(Class type) {
            return type == AzureAdMatrixAuthorizationStategy.class;
        }
    }
}
