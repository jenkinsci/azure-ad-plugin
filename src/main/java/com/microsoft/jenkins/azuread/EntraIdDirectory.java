package com.microsoft.jenkins.azuread;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import io.jenkins.plugins.authcommons.Principal;

import java.util.List;

/**
 * The subset of Microsoft Graph needed to search for users and groups.
 */
interface EntraIdDirectory {

    List<Principal> searchUsers(String query, int limit);

    List<Principal> searchGroups(String query, int limit);

    /**
     * @return the user, or {@code null} if there is no user with this object id
     */
    @CheckForNull
    Principal getUser(String objectId);

    /**
     * @return the group, or {@code null} if there is no group with this object id
     */
    @CheckForNull
    Principal getGroup(String objectId);

    /**
     * @return the user's small profile photo, or {@code null} if the user has none
     */
    @CheckForNull
    Photo getUserPhoto(String objectId);

    record Photo(byte[] content, String contentType) {
    }
}
