
package com.microsoft.jenkins.azuread;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import java.util.concurrent.TimeUnit;

public final class AzureAdUsersCache {
    @SuppressWarnings({"checkstyle:staticvariablename"})
    private static AzureAdUsersCache INSTANCE;

    @SuppressWarnings({"checkstyle:magicnumber"})
    private static Cache<String, AzureAdUser> users =
        CacheBuilder.newBuilder().expireAfterAccess(4, TimeUnit.HOURS).build();

    private AzureAdUsersCache() {
    }

    public static AzureAdUsersCache getinstance() {
        if (INSTANCE == null) {
            INSTANCE = new AzureAdUsersCache();
        }
        return INSTANCE;
    }

    public void put(AzureAdUser user) {
        users.put(user.getUniqueName(), user);
    }

    public AzureAdUser get(String userName) {
        return users.getIfPresent(userName);
    }
}
