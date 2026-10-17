package com.microsoft.jenkins.azuread;

import com.microsoft.kiota.ApiException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import io.jenkins.plugins.authcommons.Principal;
import io.jenkins.plugins.microsoftgraph.GraphServiceClient;
import io.jenkins.plugins.microsoftgraph.models.Group;
import io.jenkins.plugins.microsoftgraph.models.GroupCollectionResponse;
import io.jenkins.plugins.microsoftgraph.models.ProfilePhoto;
import io.jenkins.plugins.microsoftgraph.models.User;
import io.jenkins.plugins.microsoftgraph.models.UserCollectionResponse;
import io.jenkins.plugins.microsoftgraph.users.item.photos.item.ProfilePhotoItemRequestBuilder;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Searches users and groups using Microsoft Graph.
 */
class GraphEntraIdDirectory implements EntraIdDirectory {

    private static final int NOT_FOUND = 404;
    private static final String PHOTO_SIZE = "48x48";
    private static final int MAX_PHOTO_BYTES = 256 * 1024;
    private static final String[] USER_FIELDS = {"id", "displayName", "userPrincipalName", "mail"};
    private static final String[] GROUP_FIELDS = {"id", "displayName", "mail"};

    private final GraphServiceClient graphClient;

    GraphEntraIdDirectory(GraphServiceClient graphClient) {
        this.graphClient = graphClient;
    }

    @Override
    public List<Principal> searchUsers(String query, int limit) {
        List<Principal> result = new ArrayList<>();
        UserCollectionResponse response = lookupUsers(query, limit, graphClient);
        List<User> users = response == null ? null : response.getValue();
        if (users != null) {
            for (User user : users) {
                Principal principal = toPrincipal(user);
                if (principal != null) {
                    result.add(principal);
                }
            }
        }
        return result;
    }

    @Override
    public List<Principal> searchGroups(String query, int limit) {
        List<Principal> result = new ArrayList<>();
        GroupCollectionResponse response = lookupGroups(query, limit, graphClient);
        List<Group> groups = response == null ? null : response.getValue();
        if (groups != null) {
            for (Group group : groups) {
                Principal principal = toPrincipal(group);
                if (principal != null) {
                    result.add(principal);
                }
            }
        }
        return result;
    }

    @CheckForNull
    @Override
    public Principal getUser(String objectId) {
        try {
            User user = graphClient.users().byUserId(objectId)
                    .get(requestConfiguration -> {
                        if (requestConfiguration.queryParameters != null) {
                            requestConfiguration.queryParameters.select = USER_FIELDS;
                        }
                    });
            return user == null ? null : toPrincipal(user);
        } catch (ApiException e) {
            if (e.getResponseStatusCode() == NOT_FOUND) {
                return null;
            }
            throw e;
        }
    }

    @CheckForNull
    @Override
    public Principal getGroup(String objectId) {
        try {
            Group group = graphClient.groups().byGroupId(objectId)
                    .get(requestConfiguration -> {
                        if (requestConfiguration.queryParameters != null) {
                            requestConfiguration.queryParameters.select = GROUP_FIELDS;
                        }
                    });
            return group == null ? null : toPrincipal(group);
        } catch (ApiException e) {
            if (e.getResponseStatusCode() == NOT_FOUND) {
                return null;
            }
            throw e;
        }
    }

    @CheckForNull
    @Override
    public Photo getUserPhoto(String objectId) {
        try {
            ProfilePhotoItemRequestBuilder request = graphClient.users().byUserId(objectId)
                    .photos().byProfilePhotoId(PHOTO_SIZE);
            ProfilePhoto metadata = request.get();
            if (metadata == null) {
                return null;
            }
            Object contentType = metadata.getAdditionalData().get("@odata.mediaContentType");
            try (InputStream content = request.content().get()) {
                if (content == null) {
                    return null;
                }
                return new Photo(content.readNBytes(MAX_PHOTO_BYTES),
                        contentType instanceof String type ? type : "image/jpeg");
            }
        } catch (ApiException e) {
            if (e.getResponseStatusCode() == NOT_FOUND) {
                return null;
            }
            throw e;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static UserCollectionResponse lookupUsers(String query, int limit, GraphServiceClient graphClient) {
        String term = escapeSearchTerm(query);
        String search = String.format("\"displayName:%s\" OR \"userPrincipalName:%s\" OR \"mail:%s\"",
                term, term, term);
        return graphClient.users()
                .get(requestConfiguration -> {
                    var queryParameters = requestConfiguration.queryParameters;
                    if (queryParameters != null) {
                        queryParameters.search = search;
                        queryParameters.select = USER_FIELDS;
                        queryParameters.orderby = new String[]{"displayName"};
                        queryParameters.top = limit;
                    }
                    requestConfiguration.headers.add("ConsistencyLevel", "eventual");
                });
    }

    static GroupCollectionResponse lookupGroups(String query, int limit, GraphServiceClient graphClient) {
        String search = String.format("\"displayName:%s\"", escapeSearchTerm(query));
        return graphClient.groups()
                .get(requestConfiguration -> {
                    var queryParameters = requestConfiguration.queryParameters;
                    if (queryParameters != null) {
                        queryParameters.search = search;
                        queryParameters.select = GROUP_FIELDS;
                        queryParameters.orderby = new String[]{"displayName"};
                        queryParameters.top = limit;
                    }
                    requestConfiguration.headers.add("ConsistencyLevel", "eventual");
                });
    }

    /**
     * Search terms are wrapped in double quotes, which Graph requires to be escaped with a backslash.
     */
    static String escapeSearchTerm(String query) {
        return query.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @CheckForNull
    private static Principal toPrincipal(User user) {
        String id = user.getId();
        if (id == null) {
            return null;
        }
        String description = StringUtils.defaultIfBlank(user.getUserPrincipalName(), user.getMail());
        return Principal.user(id, user.getDisplayName(), description);
    }

    @CheckForNull
    private static Principal toPrincipal(Group group) {
        String id = group.getId();
        if (id == null) {
            return null;
        }
        return Principal.group(id, group.getDisplayName(), StringUtils.trimToNull(group.getMail()));
    }
}
