/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.microsoft.azure.PagedList;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.graphrbac.implementation.ADGroupInner;
import com.microsoft.azure.management.graphrbac.implementation.UserInner;
import com.thoughtworks.xstream.mapper.Mapper;
import hudson.Extension;
import hudson.model.AutoCompletionCandidates;
import hudson.model.Descriptor;
import hudson.security.AuthorizationStrategy;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class AzureAdMatrixAuthorizationStategy extends ProjectMatrixAuthorizationStrategy {

    private final transient ObjId2FullSidMap objId2FullSidMap = new ObjId2FullSidMap();

    @Override
    public void add(Permission p, String sid) {
        super.add(p, sid);
        objId2FullSidMap.putFullSid(sid);
    }

    @Override
    public boolean hasExplicitPermission(String sid, Permission p) {
        // Jenkins will pass in the object Id as sid
        final String objectId = sid;
        if (objectId == null) {
            return false;
        }
        return super.hasExplicitPermission(objId2FullSidMap.getOrOriginal(objectId), p);
    }

    @Override
    public boolean hasPermission(String sid, Permission p) {
        // Jenkins will pass in the object Id as sid
        final String objectId = sid;
        return super.hasPermission(objId2FullSidMap.getOrOriginal(objectId), p);
    }

    @Override
    public boolean hasPermission(String sid, Permission p, boolean principal) {
        // Jenkins will pass in the object Id as sid
        final String objectId = sid;
        return super.hasPermission(objId2FullSidMap.getOrOriginal(objectId), p, principal);
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
            Azure.Authenticated authenticated = ((AzureSecurityRealm) realm).getAzureClient();

            List<AzureObject> candidates = new ArrayList<>();
            System.out.println("search users with prefix: " + value);
            PagedList<UserInner> matchedUsers = authenticated.activeDirectoryUsers().inner()
                    .list(String.format("startswith(displayName,'%s') or startswith(mail, '%s')", value, value));
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
                String candidateText = ObjId2FullSidMap.generateFullSid(obj.getDisplayName(), obj.getObjectId());
                c.add(candidateText);
            }

            return c;
        }
    }

    @Restricted(DoNotUse.class)
    public static class ConverterImpl extends ProjectMatrixAuthorizationStrategy.ConverterImpl {

        public ConverterImpl(Mapper m) {
            super(m);
        }

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
