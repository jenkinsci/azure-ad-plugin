package com.microsoft.jenkins.azuread;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.jenkins.plugins.microsoftgraph.models.DirectoryObject;
import io.jenkins.plugins.microsoftgraph.models.DirectoryObjectCollectionResponse;
import io.jenkins.plugins.microsoftgraph.models.Group;
import io.jenkins.plugins.microsoftgraph.GraphServiceClient;
import com.microsoft.kiota.ApiException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.net.HttpURLConnection.HTTP_FORBIDDEN;

public final class AzureCachePool {
    private static final Logger LOGGER = Logger.getLogger(AzureCachePool.class.getName());
    private static final Cache<String, List<AzureAdGroup>> belongingGroupsByOid =
            Caffeine.newBuilder().expireAfterAccess(1, TimeUnit.HOURS).build();
    private final GraphServiceClient azure;

    private AzureCachePool(GraphServiceClient azure) {
        this.azure = azure;
    }

    public static AzureCachePool get(GraphServiceClient azure) {
        return new AzureCachePool(azure);
    }

    public List<AzureAdGroup> getBelongingGroupsByOid(final String oid) {
        LOGGER.log(Level.FINE, "getBelongingGroupsByOid: fetching groups for oid ''{0}''", oid);
        List<AzureAdGroup> result = belongingGroupsByOid.get(oid,
                (cacheKey) -> {
                    try {
                        DirectoryObjectCollectionResponse collection = azure
                                .users()
                                .byUserId(oid)
                                // TODO asGroup isn't working json error, and neither is $filter on securityEnabled
                                .transitiveMemberOf()
                                .get();

                        List<AzureAdGroup> groups = new ArrayList<>();

                        while (collection != null) {
                            final List<DirectoryObject> directoryObjects = collection.getValue();
                            if (directoryObjects == null) {
                                break;
                            }

                            List<AzureAdGroup> groupsFromPage = directoryObjects.stream()
                                    .map(group -> {
                                        if (group instanceof Group) {
                                            return new AzureAdGroup(group.getId(), ((Group) group).getDisplayName());
                                        }
                                        return null;
                                    })
                                    .filter(Objects::nonNull)
                                    .toList();
                            groups.addAll(groupsFromPage);

                            String nextLink = collection.getOdataNextLink();
                            if (nextLink == null) {
                                break;
                            } else {
                                collection = azure
                                        .users()
                                        .byUserId(oid)
                                        .transitiveMemberOf()
                                        .withUrl(nextLink)
                                        .get();
                            }
                        }

                        LOGGER.log(Level.FINE, "getBelongingGroupsByOid: found {0} groups for oid ''{1}''",
                                new Object[]{groups.size(), oid});
                        return groups;
                    } catch (ApiException e) {
                        if (e.getResponseStatusCode() == HTTP_FORBIDDEN) {
                            LOGGER.log(Level.WARNING, "Do not have sufficient privileges to "
                                    + "fetch your belonging groups' authorities.", e);
                            // cache the empty list to avoid re-checking permissions on every request
                            return Collections.emptyList();
                        }
                        LOGGER.log(Level.WARNING, "Failed to fetch the belonging groups of " + oid, e);
                        // returning null skips the cache so the next request retries
                        return null;
                    } catch (Exception e) {
                        LOGGER.log(Level.WARNING, "Failed to fetch the belonging groups of " + oid, e);
                        // returning null skips the cache so the next request retries
                        return null;
                    }
                });
        if (Constants.DEBUG) {
            belongingGroupsByOid.invalidate(oid);
        }
        return result == null ? Collections.emptyList() : result;
    }

    public static void invalidateBelongingGroupsByOid(String userId) {
        belongingGroupsByOid.invalidate(userId);
    }

}