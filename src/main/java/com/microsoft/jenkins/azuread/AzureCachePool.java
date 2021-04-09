package com.microsoft.jenkins.azuread;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.microsoft.graph.models.DirectoryObject;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.requests.DirectoryObjectCollectionWithReferencesPage;
import com.microsoft.graph.requests.DirectoryObjectCollectionWithReferencesRequestBuilder;
import com.microsoft.graph.requests.GraphServiceClient;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public final class AzureCachePool {
    private static final Logger LOGGER = Logger.getLogger(AzureCachePool.class.getName());
    private static Cache<String, List<AzureAdGroup>> belongingGroupsByOid =
            CacheBuilder.newBuilder().expireAfterAccess(1, TimeUnit.HOURS).build();
    private final GraphServiceClient azure;

    private AzureCachePool(GraphServiceClient azure) {
        this.azure = azure;
    }

    public static AzureCachePool get(GraphServiceClient azure) {
        return new AzureCachePool(azure);
    }

    public List<AzureAdGroup> getBelongingGroupsByOid(final String oid) {
        try {
            List<AzureAdGroup> result = belongingGroupsByOid.get(oid,
                    () -> {
                        try {
                        DirectoryObjectCollectionWithReferencesPage collection = azure
                                .users(oid)
                                .transitiveMemberOf()
                                .buildRequest()
                                .get();


                            List<AzureAdGroup> groups = new ArrayList<>();

                            while (collection != null) {
                                final List<DirectoryObject> directoryObjects = collection.getCurrentPage();

                                List<AzureAdGroup> groupsFromPage = directoryObjects.stream()
                                        .filter(group -> group instanceof Group)
                                        .map(group -> new AzureAdGroup(group.id, ((Group) group).displayName))
                                        .collect(Collectors.toList());
                                groups.addAll(groupsFromPage);

                                DirectoryObjectCollectionWithReferencesRequestBuilder nextPage = collection
                                        .getNextPage();
                                if (nextPage == null) {
                                    break;
                                } else {
                                    collection = nextPage.buildRequest().get();
                                }
                            }

                            return groups;
                        } catch (Exception e) {
                            LOGGER.log(Level.WARNING, "Do not have sufficient privileges to "
                                    + "fetch your belonging groups' authorities.", e);
                            return Collections.emptyList();
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
