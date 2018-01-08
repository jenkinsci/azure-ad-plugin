/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.microsoft.azure.PagedList;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.graphrbac.implementation.ADGroupInner;
import com.microsoft.azure.management.graphrbac.implementation.UserInner;
import com.thoughtworks.xstream.mapper.Mapper;
import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.AbstractItem;
import hudson.model.AutoCompletionCandidates;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.Job;
import hudson.security.ACL;
import hudson.security.AuthorizationMatrixProperty;
import hudson.security.AuthorizationStrategy;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import hudson.security.SecurityRealm;
import hudson.security.SidACL;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutionException;

public class AzureAdMatrixAuthorizationStrategy extends GlobalMatrixAuthorizationStrategy {

    private final transient ObjId2FullSidMap objId2FullSidMap = new ObjId2FullSidMap();

    //
    // Inheriting from ProjectMatrixAuthorizationStrategy will lead to conflict
    // of AzureAdAuthorizationMatrixProperty and AuthorizationMatrixProperty.
    // Copy codes instead.
    //
    @Override
    public ACL getACL(Job<?, ?> project) {
        AuthorizationMatrixProperty amp = project.getProperty(AuthorizationMatrixProperty.class);
        if (amp != null) {
            SidACL projectAcl = amp.getACL();

            if (!amp.isBlocksInheritance()) {
                final ACL parentAcl = getACL(project.getParent());
                return inheritingACL(parentAcl, projectAcl);
            } else {
                return projectAcl;
            }
        } else {
            return getACL(project.getParent());
        }
    }

    private static ACL inheritingACL(final ACL parent, final ACL child) {
        if (parent instanceof SidACL && child instanceof SidACL) {
            return ((SidACL) child).newInheritingACL((SidACL) parent);
        }
        return new ACL() {
            @Override
            public boolean hasPermission(Authentication a, Permission permission) {
                return child.hasPermission(a, permission) || parent.hasPermission(a, permission);
            }
        };
    }

    public ACL getACL(ItemGroup g) {
        if (g instanceof Item) {
            Item item = (Item) g;
            return item.getACL();
        }
        return getRootACL();
    }

    @Override
    public ACL getACL(AbstractItem item) {
        if (Jenkins.getActiveInstance().getPlugin("cloudbees-folder") != null) { // optional dependency
            if (item instanceof AbstractFolder) {
                AzureAdAuthorizationMatrixFolderProperty p =
                        (AzureAdAuthorizationMatrixFolderProperty) ((AbstractFolder) item).getProperties()
                                .get(AzureAdAuthorizationMatrixFolderProperty.class);
                if (p != null) {
                    SidACL folderAcl = p.getACL();

                    if (!p.isBlocksInheritance()) {
                        final ACL parentAcl = getACL(item.getParent());
                        return inheritingACL(parentAcl, folderAcl);
                    } else {
                        return folderAcl;
                    }
                }
            }
        }
        return getACL(item.getParent());
    }

    @Override
    public Set<String> getGroups() {
        Set<String> r = new TreeSet<>();
        r.addAll(super.getGroups());
        for (Job<?, ?> j : Jenkins.getActiveInstance().getItems(Job.class)) {
            AuthorizationMatrixProperty amp = j.getProperty(AuthorizationMatrixProperty.class);
            if (amp != null) {
                r.addAll(amp.getGroups());
            }
        }
        return r;
    }

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


    static AutoCompletionCandidates searchAndGenerateCandidates(String prefix) throws IOException {
        final int maxCandidates = 20;
        if (StringUtils.isEmpty(prefix)) {
            return null;
        }

        SecurityRealm realm = Jenkins.getActiveInstance().getSecurityRealm();
        if (!(realm instanceof AzureSecurityRealm)) {
            return null;
        }
        Azure.Authenticated authenticated = ((AzureSecurityRealm) realm).getAzureClient();

        List<AzureObject> candidates = new ArrayList<>();
        System.out.println("search users with prefix: " + prefix);
        PagedList<UserInner> matchedUsers = authenticated.activeDirectoryUsers().inner()
                .list(String.format("startswith(displayName,'%s') or startswith(mail, '%s')", prefix, prefix));
        for (UserInner user : matchedUsers.currentPage().items()) {
            candidates.add(new AzureObject(user.objectId(), user.displayName()));
            if (candidates.size() > maxCandidates) {
                break;
            }
        }

        if (!matchedUsers.hasNextPage()) {
            System.out.println("search groups with prefix " + prefix);
            PagedList<ADGroupInner> matchedGroups = authenticated.activeDirectoryGroups()
                    .inner().list("startswith(displayName,'" + prefix + "')");
            for (ADGroupInner group : matchedGroups.currentPage().items()) {
                candidates.add(new AzureObject(group.objectId(), group.displayName()));
                if (candidates.size() > maxCandidates) {
                    break;
                }
            }
        }

        AutoCompletionCandidates c = new AutoCompletionCandidates();
        for (AzureObject obj : candidates) {
            String candidateText = ObjId2FullSidMap.generateFullSid(obj.getDisplayName(), obj.getObjectId());
            c.add(candidateText);
        }
        return c;
    }

    public static class DescriptorImpl extends GlobalMatrixAuthorizationStrategy.DescriptorImpl {
        @Override
        protected GlobalMatrixAuthorizationStrategy create() {
            return new AzureAdMatrixAuthorizationStrategy();
        }

        @Override
        @Nonnull
        public String getDisplayName() {
            return "Azure Active Directory Matrix-based security";
        }

        public AutoCompletionCandidates doAutoCompleteUserOrGroup(@QueryParameter String value)
                throws ExecutionException, IOException, InterruptedException {
            return searchAndGenerateCandidates(value);
        }
    }

    @Restricted(DoNotUse.class)
    public static class ConverterImpl extends ProjectMatrixAuthorizationStrategy.ConverterImpl {

        public ConverterImpl(Mapper m) {
            super(m);
        }

        @Override
        public GlobalMatrixAuthorizationStrategy create() {
            return new AzureAdMatrixAuthorizationStrategy();
        }

        @Override
        @SuppressWarnings("rawtypes")
        public boolean canConvert(Class type) {
            return type == AzureAdMatrixAuthorizationStrategy.class;
        }
    }

    @Initializer(before = InitMilestone.PLUGINS_STARTED)
    public static void fixClassNameTypo() {
        // before 0.2.0
        Jenkins.XSTREAM2.addCompatibilityAlias(
                "com.microsoft.jenkins.azuread.AzureAdMatrixAuthorizationStategy",
                AzureAdMatrixAuthorizationStrategy.class);
    }
}
