package com.microsoft.jenkins.azuread;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.microsoft.jenkins.azuread.utils.UUIDValidator;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.AbstractItem;
import hudson.model.Computer;
import hudson.model.DescriptorByNameOwner;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.authcommons.Principal;
import io.jenkins.plugins.authcommons.PrincipalSearchProvider;
import io.jenkins.plugins.authcommons.PrincipalType;
import jenkins.model.Jenkins;
import jenkins.util.SystemProperties;
import org.kohsuke.stapler.Ancestor;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * Lets authorization strategies such as Matrix Authorization Strategy and Role-based Authorization Strategy
 * autocomplete Entra ID users and groups.
 *
 * <p>Both users and groups are identified by their object id, which is what {@link AzureAdUser} uses as its
 * username and group authorities.
 *
 * <p>Users get an avatar URL pointing to {@link EntraIdPhotoProxy} on the object the search was made from,
 * so that viewing photos requires the same permission as configuring access there.
 */
@Extension
public class EntraIdPrincipalSearchProvider extends PrincipalSearchProvider {

    private static final int MAX_CACHED_SEARCHES = 500;
    private static final int MAX_CACHED_LOOKUPS = 5000;
    private static final long MAX_CACHED_PHOTO_BYTES = 16L * 1024 * 1024;

    private final Cache<String, List<Principal>> searchCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(1))
            .maximumSize(MAX_CACHED_SEARCHES)
            .build();

    private final Cache<String, Optional<Principal>> lookupCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(10))
            .maximumSize(MAX_CACHED_LOOKUPS)
            .build();

    private final Cache<String, Optional<EntraIdDirectory.Photo>> photoCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofHours(1))
            .maximumWeight(MAX_CACHED_PHOTO_BYTES)
            .<String, Optional<EntraIdDirectory.Photo>>weigher((k, v) -> 1 + v.map(p -> p.content().length).orElse(0))
            .build();

    /** The realm the caches were populated for, so that they can be discarded when it is reconfigured. */
    private volatile SecurityRealm cachedRealm;

    private volatile Function<AzureSecurityRealm, EntraIdDirectory> directoryFactory =
            realm -> new GraphEntraIdDirectory(realm.getAzureClient());

    static EntraIdPrincipalSearchProvider get() {
        return ExtensionList.lookupSingleton(EntraIdPrincipalSearchProvider.class);
    }

    @Override
    public boolean isApplicable(@NonNull SecurityRealm realm) {
        return realm instanceof AzureSecurityRealm azureSecurityRealm
                && !azureSecurityRealm.isDisableGraphIntegration();
    }

    @NonNull
    @Override
    public List<Principal> search(@NonNull String query, @NonNull Set<PrincipalType> types, int limit) {
        EntraIdDirectory directory = directory();
        if (directory == null) {
            return List.of();
        }
        String trimmed = query.trim();
        String key = types + ":" + limit + ":" + trimmed.toLowerCase(Locale.ROOT);
        List<Principal> found = searchCache.get(key, k -> doSearch(directory, trimmed, types, limit));
        String photoBaseUrl = photoBaseUrl();
        if (photoBaseUrl == null) {
            return found;
        }
        // not cached, as it depends on where the search is made from
        List<Principal> result = new ArrayList<>(found.size());
        for (Principal principal : found) {
            result.add(principal.type() == PrincipalType.USER
                    ? principal.withAvatarUrl(photoBaseUrl + principal.sid())
                    : principal);
        }
        return result;
    }

    @CheckForNull
    @Override
    public Principal lookup(@NonNull String sid, @NonNull PrincipalType type) {
        String objectId = toObjectId(sid);
        if (objectId == null) {
            return null;
        }
        EntraIdDirectory directory = directory();
        if (directory == null) {
            return null;
        }
        return lookupCache.get(type + ":" + objectId, k -> Optional.ofNullable(
                type == PrincipalType.USER ? directory.getUser(objectId) : directory.getGroup(objectId)))
                .orElse(null);
    }

    /**
     * @return the user's profile photo, or {@code null} if there is none or photos are disabled
     */
    @CheckForNull
    EntraIdDirectory.Photo getUserPhoto(String objectId) {
        if (isPhotoDisabled() || !UUIDValidator.isValidUUID(objectId)) {
            return null;
        }
        EntraIdDirectory directory = directory();
        if (directory == null) {
            return null;
        }
        return photoCache.get(objectId.toLowerCase(Locale.ROOT),
                k -> Optional.ofNullable(directory.getUserPhoto(objectId))).orElse(null);
    }

    void setDirectoryFactory(Function<AzureSecurityRealm, EntraIdDirectory> directoryFactory) {
        this.directoryFactory = directoryFactory;
        invalidateCaches();
    }

    static boolean isPhotoDisabled() {
        return SystemProperties.getBoolean(AzureSecurityRealm.class.getName() + ".disableAvatar", false);
    }

    @CheckForNull
    private static String toObjectId(String sid) {
        String objectId = ObjId2FullSidMap.extractObjectId(sid);
        if (objectId == null) {
            objectId = sid;
        }
        return UUIDValidator.isValidUUID(objectId) ? objectId.toLowerCase(Locale.ROOT) : null;
    }

    /**
     * The URL of {@link EntraIdPhotoProxy} on the nearest item or computer the current request was made to,
     * or on the root if there is none.
     */
    @CheckForNull
    static String photoBaseUrl() {
        if (isPhotoDisabled()) {
            return null;
        }
        StaplerRequest2 req = Stapler.getCurrentRequest2();
        if (req == null) {
            return null;
        }
        String base = req.getContextPath();
        Ancestor ancestor = req.findAncestor(DescriptorByNameOwner.class);
        if (ancestor != null
                && (ancestor.getObject() instanceof AbstractItem || ancestor.getObject() instanceof Computer)) {
            base = ancestor.getUrl();
        }
        return base + "/" + EntraIdPhotoProxy.URL_NAME + "/";
    }

    private static List<Principal> doSearch(EntraIdDirectory directory, String query, Set<PrincipalType> types,
                                            int limit) {
        List<Principal> result = new ArrayList<>();
        if (UUIDValidator.isValidUUID(query)) {
            // pasted object id, Graph $search doesn't match on id
            if (types.contains(PrincipalType.USER)) {
                Optional.ofNullable(directory.getUser(query)).ifPresent(result::add);
            }
            if (types.contains(PrincipalType.GROUP)) {
                Optional.ofNullable(directory.getGroup(query)).ifPresent(result::add);
            }
            return result;
        }
        if (types.contains(PrincipalType.USER)) {
            result.addAll(directory.searchUsers(query, limit));
        }
        if (types.contains(PrincipalType.GROUP) && result.size() < limit) {
            result.addAll(directory.searchGroups(query, limit - result.size()));
        }
        return result.size() > limit ? List.copyOf(result.subList(0, limit)) : List.copyOf(result);
    }

    @CheckForNull
    private EntraIdDirectory directory() {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();
        if (!isApplicable(realm)) {
            return null;
        }
        if (realm != cachedRealm) {
            invalidateCaches();
            cachedRealm = realm;
        }
        return directoryFactory.apply((AzureSecurityRealm) realm);
    }

    private void invalidateCaches() {
        searchCache.invalidateAll();
        lookupCache.invalidateAll();
        photoCache.invalidateAll();
    }
}
