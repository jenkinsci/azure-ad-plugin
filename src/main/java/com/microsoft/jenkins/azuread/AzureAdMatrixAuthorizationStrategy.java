/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.models.User;
import com.microsoft.graph.options.HeaderOption;
import com.microsoft.graph.options.Option;
import com.microsoft.graph.options.QueryOption;
import com.microsoft.graph.requests.GraphServiceClient;
import com.microsoft.graph.requests.GroupCollectionPage;
import com.microsoft.graph.requests.UserCollectionPage;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.AbstractItem;
import hudson.model.AutoCompletionCandidates;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.Job;
import hudson.model.Node;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.SecurityRealm;
import hudson.security.SidACL;
import jenkins.model.Jenkins;
import okhttp3.Request;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainer;
import org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AzureAdMatrixAuthorizationStrategy extends GlobalMatrixAuthorizationStrategy {

    private static final Logger LOGGER = Logger.getLogger(AzureAdMatrixAuthorizationStrategy.class.getName());

    private final transient ObjId2FullSidMap objId2FullSidMap = new ObjId2FullSidMap();

    //
    // Inheriting from ProjectMatrixAuthorizationStrategy will lead to conflict
    // of AzureAdAuthorizationMatrixProperty and AuthorizationMatrixProperty.
    // Copy codes instead.
    //
    @Override
    @NonNull
    public ACL getACL(@NonNull Job<?, ?> project) {
        AzureAdAuthorizationMatrixProperty amp = project.getProperty(AzureAdAuthorizationMatrixProperty.class);
        if (amp != null) {
            return amp.getInheritanceStrategy().getEffectiveACL(amp.getACL(), project);
        } else {
            return getACL(project.getParent());
        }
    }

    @NonNull
    @Override
    public ACL getACL(@NonNull Node node) {
        AuthorizationMatrixNodeProperty property = node.getNodeProperty(AzureAdAuthorizationMatrixNodeProperty.class);
        if (property != null) {
            return property.getInheritanceStrategy().getEffectiveACL(property.getACL(), node);
        }
        return getRootACL();
    }

    @Restricted(NoExternalUse.class)
    public static ACL inheritingACL(final ACL parent, final ACL child) {
        if (parent instanceof SidACL && child instanceof SidACL) {
            return ((SidACL) child).newInheritingACL((SidACL) parent);
        }
        return new ACL() {
            @Override
            public boolean hasPermission2(@NonNull Authentication a, @NonNull Permission permission) {
                return a.equals(SYSTEM2) || child.hasPermission2(a, permission) || parent.hasPermission2(a, permission);
            }
        };
    }

    public ACL getACL(ItemGroup<?> g) {
        if (g instanceof Item) {
            Item item = (Item) g;
            return item.getACL();
        }
        return getRootACL();
    }

    @Override
    @NonNull
    public ACL getACL(@NonNull AbstractItem item) {
        if (Jenkins.get().getPlugin("cloudbees-folder") != null) { // optional dependency
            if (item instanceof AbstractFolder) {
                AzureAdAuthorizationMatrixFolderProperty p =
                        ((AbstractFolder<?>) item).getProperties().get(AzureAdAuthorizationMatrixFolderProperty.class);
                if (p != null) {
                    return p.getInheritanceStrategy().getEffectiveACL(p.getACL(), item);
                }
            }
        }
        return getACL(item.getParent());
    }

    @Override
    @NonNull
    @SuppressRestrictedWarnings(value = {IdStrategyComparator.class, AuthorizationContainer.class})
    public Set<String> getGroups() {
        Set<String> r = new TreeSet<>(new IdStrategyComparator());
        r.addAll(super.getGroups());
        for (Job<?, ?> j : Jenkins.get().getAllItems(Job.class)) {
            AzureAdAuthorizationMatrixProperty jobProperty = j.getProperty(AzureAdAuthorizationMatrixProperty.class);
            if (jobProperty != null) {
                r.addAll(jobProperty.getGroups());
            }
        }
        for (AbstractFolder<?> j : Jenkins.get().getAllItems(AbstractFolder.class)) {
            AzureAdAuthorizationMatrixFolderProperty folderProperty =
                    j.getProperties().get(AzureAdAuthorizationMatrixFolderProperty.class);
            if (folderProperty != null) {
                r.addAll(folderProperty.getGroups());
            }
        }
        return r;
    }

    // Copy ended

    @Override
    public void add(Permission p, String sid) {
        super.add(p, sid);
        objId2FullSidMap.putFullSid(sid);
    }

    @Override
    public boolean hasExplicitPermission(String objectId, Permission p) {
        // Jenkins will pass in the object Id as sid
        if (objectId == null) {
            return false;
        }
        return super.hasExplicitPermission(objId2FullSidMap.getOrOriginal(objectId), p);
    }

    @Override
    public boolean hasPermission(String objectId, Permission p) {
        // Jenkins will pass in the object Id as sid
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


    static AutoCompletionCandidates searchAndGenerateCandidates(String prefix) {
        final int maxCandidates = 20;
        if (StringUtils.isEmpty(prefix)) {
            return null;
        }

        SecurityRealm realm = Jenkins.get().getSecurityRealm();
        if (!(realm instanceof AzureSecurityRealm)) {
            return null;
        }
        GraphServiceClient<Request> graphClient = ((AzureSecurityRealm) realm).getAzureClient();

        List<AzureObject> candidates = new ArrayList<>();
        LOGGER.info("search users with prefix: " + prefix);
        try {
            UserCollectionPage users = lookupUsers(prefix, graphClient);

            for (User user : users.getCurrentPage()) {
                candidates.add(new AzureObject(user.id, user.displayName));
                if (candidates.size() > maxCandidates) {
                    break;
                }
            }

            if (candidates.size() < maxCandidates) {
                GroupCollectionPage groupCollectionPage = lookupGroups(prefix, graphClient);

                for (Group group : groupCollectionPage.getCurrentPage()) {
                    candidates.add(new AzureObject(group.id, group.displayName));
                }
            }

        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Do not have sufficient privileges to search related users or groups", e);
        }

        AutoCompletionCandidates c = new AutoCompletionCandidates();

        for (AzureObject obj : candidates) {
            String candidateText = ObjId2FullSidMap.generateFullSid(obj.getDisplayName(), obj.getObjectId());
            c.add(candidateText);
        }
        return c;
    }

    private static GroupCollectionPage lookupGroups(String prefix, GraphServiceClient<Request> graphClient) {
        LinkedList<Option> requestOptions = new LinkedList<>();
        String search = String.format("\"displayName:%s\"", prefix);
        requestOptions.add(new QueryOption("$search", search));
        requestOptions.add(new HeaderOption("ConsistencyLevel", "eventual"));

        return graphClient.groups()
                .buildRequest(requestOptions)
                .orderBy("displayName")
                .select("id,displayName")
                .get();
    }

    private static UserCollectionPage lookupUsers(String prefix, GraphServiceClient<Request> graphClient) {
        LinkedList<Option> requestOptions = new LinkedList<>();
        String search = String.format("\"displayName:%s\" OR \"userPrincipalName:%s\"", prefix, prefix);
        requestOptions.add(new QueryOption("$search", search));
        requestOptions.add(new HeaderOption("ConsistencyLevel", "eventual"));
        return graphClient.users()
                .buildRequest(requestOptions)
                .select("id,displayName")
                .orderBy("displayName")
                .get();
    }

    public static class DescriptorImpl extends GlobalMatrixAuthorizationStrategy.DescriptorImpl {
        @Override
        protected GlobalMatrixAuthorizationStrategy create() {
            return new AzureAdMatrixAuthorizationStrategy();
        }

        @Override
        @NonNull
        public String getDisplayName() {
            return "Azure Active Directory Matrix-based security";
        }


        @SuppressWarnings("unused") // called by jelly
        public boolean isDisableGraphIntegration() {
            SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
            if (securityRealm instanceof AzureSecurityRealm) {
                AzureSecurityRealm azureSecurityRealm = (AzureSecurityRealm) securityRealm;
                return azureSecurityRealm.isDisableGraphIntegration();
            }
            return true;
        }
    }

    @Restricted(DoNotUse.class)
    @SuppressRestrictedWarnings(GlobalMatrixAuthorizationStrategy.ConverterImpl.class)
    public static class ConverterImpl extends GlobalMatrixAuthorizationStrategy.ConverterImpl {
        @Override
        public GlobalMatrixAuthorizationStrategy create() {
            return new AzureAdMatrixAuthorizationStrategy();
        }

        @Override
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
