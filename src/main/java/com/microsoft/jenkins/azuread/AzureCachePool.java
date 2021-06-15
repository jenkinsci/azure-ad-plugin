package com.microsoft.jenkins.azuread;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.microsoft.graph.models.DirectoryObject;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.requests.DirectoryObjectCollectionWithReferencesPage;
import com.microsoft.graph.requests.DirectoryObjectCollectionWithReferencesRequestBuilder;
import com.microsoft.graph.requests.GraphServiceClient;
import okhttp3.Request;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public final class AzureCachePool {
    private static final Logger LOGGER = Logger.getLogger(AzureCachePool.class.getName());
    private static Cache<String, List<AzureAdGroup>> belongingGroupsByOid =
            Caffeine.newBuilder().expireAfterAccess(1, TimeUnit.HOURS).build();
    private final GraphServiceClient<Request> azure;

    private AzureCachePool(GraphServiceClient<Request> azure) {
        this.azure = azure;
    }

    public static AzureCachePool get(GraphServiceClient<Request> azure) {
        return new AzureCachePool(azure);
    }

    public List<AzureAdGroup> getBelongingGroupsByOid(final String oid) {
        List<AzureAdGroup> result = belongingGroupsByOid.get(oid,
                (cacheKey) -> {
                    try {
                        DirectoryObjectCollectionWithReferencesPage collection = azure
                                .users(oid)
                                // TODO asGroup isn't working json error, and neither is $filter on securityEnabled
                                .transitiveMemberOf()
                                .buildRequest()
                                .get();


                        List<AzureAdGroup> groups = new ArrayList<>();

                        while (collection != null) {
                            final List<DirectoryObject> directoryObjects = collection.getCurrentPage();

                            List<AzureAdGroup> groupsFromPage = directoryObjects.stream()
                                    .filter(group -> group instanceof Group
                                            && Boolean.TRUE.equals(((Group) group).securityEnabled))
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

    }

    public static void invalidateBelongingGroupsByOid(String userId) {
        belongingGroupsByOid.invalidate(userId);
    }

}
