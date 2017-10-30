package com.microsoft.jenkins.azuread;


import com.google.common.base.Stopwatch;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.microsoft.azure.management.Azure;
import jenkins.model.Jenkins;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public final class AzureCachePool {
    private static final Logger LOGGER = Logger.getLogger(AzureCachePool.class.getName());
    private static Cache<String, Collection<String>> belongingGroupsByOid =
            CacheBuilder.newBuilder().expireAfterAccess(1, TimeUnit.HOURS).build();

    private AzureCachePool() {
    }

    public static Collection<String> getBelongingGroupsByOid(final String oid) throws IOException, ExecutionException {
        try {
            Collection<String> result = belongingGroupsByOid.get(oid, new Callable<Collection<String>>() {
                @Override
                public Collection<String> call() throws Exception {
                    Stopwatch stopwatch = Stopwatch.createStarted();
                    AzureSecurityRealm securityRealm =
                            (AzureSecurityRealm) Jenkins.getActiveInstance().getSecurityRealm();
                    List<String> groups = Azure.authenticate(securityRealm.getAzureCredential())
                            .activeDirectoryUsers().inner().getMemberGroups(oid, false);
                    Azure.authenticate(securityRealm.getAzureCredential()).activeDirectoryUsers().list().loadAll();

                    stopwatch.stop();
                    System.out.println("getBelongingGroupsByOid time (debug) = "
                            + stopwatch.elapsed(TimeUnit.MILLISECONDS) + "ms");
                    System.out.println("getBelongingGroupsByOid: set = " + groups);
                    return groups;
                }
            });
            if (Constants.DEBUG) {
                belongingGroupsByOid.invalidate(oid);
            }
            return result;
        } catch (ExecutionException e) {
            e.printStackTrace();
            return null;
        }

    }

    public static void invalidateBelongingGroupsByOid(String userId) {
        belongingGroupsByOid.invalidate(userId);
    }

}
