package com.microsoft.jenkins.azuread;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import jenkins.model.Jenkins;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class AzureCachePool {
    private static final Logger LOGGER = Logger.getLogger(AzureCachePool.class.getName());
    private static Cache<String, Collection<String>> belongingGroupsByOid =
            CacheBuilder.newBuilder().expireAfterAccess(1, TimeUnit.HOURS).build();

    private AzureCachePool() {
    }

    public static Collection<String> getBelongingGroupsByOid(final String oid) {
        try {
            Collection<String> result = belongingGroupsByOid.get(oid, new Callable<Collection<String>>() {
                @Override
                public Collection<String> call() throws Exception {
                    AzureSecurityRealm securityRealm =
                            (AzureSecurityRealm) Jenkins.getActiveInstance().getSecurityRealm();
                    List<String> groups = securityRealm.getAzureClient()
                            .activeDirectoryUsers().inner().getMemberGroups(oid, false);
                    return groups;
                }
            });
            if (Constants.DEBUG) {
                belongingGroupsByOid.invalidate(oid);
            }
            return result;
        } catch (ExecutionException e) {
            LOGGER.log(Level.WARNING, "Failed to retrive the belonging group of " + oid, e);
            return null;
        }

    }

    public static void invalidateBelongingGroupsByOid(String userId) {
        belongingGroupsByOid.invalidate(userId);
    }

}
