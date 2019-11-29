package com.microsoft.jenkins.azuread;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.graphrbac.ActiveDirectoryGroup;
import com.microsoft.azure.management.graphrbac.GraphErrorException;
import com.microsoft.azure.management.graphrbac.implementation.UserGetMemberGroupsParametersInner;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class AzureCachePool {
    private static final Logger LOGGER = Logger.getLogger(AzureCachePool.class.getName());
    private static Cache<String, Collection<ActiveDirectoryGroup>> belongingGroupsByOid =
            CacheBuilder.newBuilder().expireAfterAccess(1, TimeUnit.HOURS).build();
    private final Azure.Authenticated azure;

    private AzureCachePool(Azure.Authenticated azure) {
        this.azure = azure;
    }

    public static AzureCachePool get(Azure.Authenticated azure) {
        return new AzureCachePool(azure);
    }

    public Collection<ActiveDirectoryGroup> getBelongingGroupsByOid(final String oid) {
        try {
            Collection<ActiveDirectoryGroup> result = belongingGroupsByOid.get(oid,
                    new Callable<Collection<ActiveDirectoryGroup>>() {
                        @Override
                        public Collection<ActiveDirectoryGroup> call() throws Exception {
                            UserGetMemberGroupsParametersInner getMemberGroupsParam =
                                    new UserGetMemberGroupsParametersInner().withSecurityEnabledOnly(false);
                            List<ActiveDirectoryGroup> activeDirectoryGroups = new ArrayList<>();
                            List<String> groups;
                            try {

                                groups = azure.activeDirectoryUsers().inner().getMemberGroups(oid,
                                        getMemberGroupsParam);
                            } catch (GraphErrorException e) {
                                LOGGER.warning("Do not have sufficient privileges to "
                                        + "fetch your belonging groups' authorities.");
                                return activeDirectoryGroups;
                            }


                            for (String group : groups) {
                                activeDirectoryGroups.add(azure.activeDirectoryGroups().getById(group));
                            }

                            return activeDirectoryGroups;
                        }
                    });
            if (Constants.DEBUG) {
                belongingGroupsByOid.invalidate(oid);
            }
            return result;
        } catch (ExecutionException e) {
            LOGGER.log(Level.WARNING, "Failed to retrieve the belonging group of " + oid, e);
            return Collections.emptyList();
        }

    }

    public static void invalidateBelongingGroupsByOid(String userId) {
        belongingGroupsByOid.invalidate(userId);
    }

}
