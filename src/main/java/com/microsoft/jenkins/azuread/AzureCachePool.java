package com.microsoft.jenkins.azuread;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.microsoft.azure.management.Azure;

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
    private final Azure.Authenticated azure;

    private AzureCachePool(Azure.Authenticated azure) {
        this.azure = azure;
    }

    public static AzureCachePool get(Azure.Authenticated azure) {
        return new AzureCachePool(azure);
    }

    public Collection<String> getBelongingGroupsByOid(final String oid) {
        try {
            Collection<String> result = belongingGroupsByOid.get(oid, new Callable<Collection<String>>() {
                @Override
                public Collection<String> call() throws Exception {
                    List<String> groups = azure.activeDirectoryUsers().inner().getMemberGroups(oid, false);
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
