package com.microsoft.jenkins.azuread;

import hudson.util.Secret;
import io.jenkins.plugins.authcommons.Principal;
import io.jenkins.plugins.authcommons.PrincipalSearch;
import io.jenkins.plugins.authcommons.PrincipalType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

@WithJenkins
class EntraIdPrincipalSearchProviderTest {

    static final String ALICE_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    static final String ALBERT_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    static final String ADMINS_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc";

    private JenkinsRule j;
    private FakeDirectory directory;
    private EntraIdPrincipalSearchProvider provider;

    @BeforeEach
    void setUp(JenkinsRule j) {
        this.j = j;
        j.jenkins.setSecurityRealm(new AzureSecurityRealm("tenant", "clientId", Secret.fromString("secret"), 0));
        directory = new FakeDirectory();
        provider = EntraIdPrincipalSearchProvider.get();
        provider.setDirectoryFactory(realm -> directory);
    }

    @Test
    void applicability() {
        assertThat(provider.isApplicable(j.jenkins.getSecurityRealm()), is(true));
        assertThat(PrincipalSearch.isAvailable(), is(true));

        AzureSecurityRealm withoutGraph = new AzureSecurityRealm("tenant", "clientId", Secret.fromString("secret"), 0);
        withoutGraph.setDisableGraphIntegration(true);
        assertThat(provider.isApplicable(withoutGraph), is(false));
        assertThat(provider.isApplicable(j.createDummySecurityRealm()), is(false));

        j.jenkins.setSecurityRealm(withoutGraph);
        assertThat(provider.search("al", EnumSet.allOf(PrincipalType.class), 10), empty());
        assertThat(PrincipalSearch.isAvailable(), is(false));
    }

    @Test
    void searchesUsersThenGroups() {
        assertThat(sids(provider.search("al", EnumSet.allOf(PrincipalType.class), 10)),
                contains("USER:" + ALICE_ID, "USER:" + ALBERT_ID, "GROUP:" + ADMINS_ID));
        assertThat(sids(provider.search("al", EnumSet.of(PrincipalType.GROUP), 10)),
                contains("GROUP:" + ADMINS_ID));
        assertThat(sids(provider.search("al", EnumSet.allOf(PrincipalType.class), 1)),
                contains("USER:" + ALICE_ID));
    }

    @Test
    void searchesByObjectId() {
        assertThat(sids(provider.search(ADMINS_ID, EnumSet.allOf(PrincipalType.class), 10)),
                contains("GROUP:" + ADMINS_ID));
        assertThat(directory.searches, is(0));
    }

    @Test
    void cachesSearches() {
        provider.search("al", EnumSet.of(PrincipalType.USER), 10);
        provider.search(" AL ", EnumSet.of(PrincipalType.USER), 10);
        assertThat(directory.searches, is(1));

        // reconfiguring the realm discards cached results
        j.jenkins.setSecurityRealm(new AzureSecurityRealm("tenant", "clientId", Secret.fromString("secret"), 0));
        provider.search("al", EnumSet.of(PrincipalType.USER), 10);
        assertThat(directory.searches, is(2));
    }

    @Test
    void lookup() {
        assertThat(provider.lookup(ALICE_ID, PrincipalType.USER).displayName(), is("Alice"));
        assertThat(provider.lookup("Admins (" + ADMINS_ID + ")", PrincipalType.GROUP).displayName(), is("All Admins"));
        assertThat(provider.lookup(ALICE_ID, PrincipalType.GROUP), nullValue());
        assertThat(provider.lookup("alice@example.com", PrincipalType.USER), nullValue());

        provider.lookup(ALICE_ID, PrincipalType.USER);
        provider.lookup(ALICE_ID, PrincipalType.GROUP);
        assertThat(directory.lookups, is(3));
    }

    @Test
    void escapesSearchTerms() {
        assertThat(GraphEntraIdDirectory.escapeSearchTerm("a\"b\\c"), is("a\\\"b\\\\c"));
    }

    private static List<String> sids(List<Principal> principals) {
        List<String> result = new ArrayList<>();
        for (Principal principal : principals) {
            result.add(principal.type() + ":" + principal.sid());
        }
        return result;
    }

    @Test
    void noAvatarOutsideOfRequests() {
        assertThat(provider.search("alice", EnumSet.of(PrincipalType.USER), 10).get(0).avatarUrl(), nullValue());
    }

    static final class FakeDirectory implements EntraIdDirectory {
        private final List<Principal> users = List.of(
                Principal.user(ALICE_ID, "Alice", "alice@example.com"),
                Principal.user(ALBERT_ID, "Albert", "albert@example.com"));
        private final List<Principal> groups = List.of(Principal.group(ADMINS_ID, "All Admins", null));
        int searches;
        int lookups;
        int photos;

        @Override
        public List<Principal> searchUsers(String query, int limit) {
            searches++;
            return users.stream().filter(p -> p.displayName().toLowerCase().startsWith(query.toLowerCase()))
                    .limit(limit).toList();
        }

        @Override
        public List<Principal> searchGroups(String query, int limit) {
            searches++;
            // Graph searches anywhere in the display name
            return groups.stream().filter(p -> p.displayName().toLowerCase().contains(query.toLowerCase()))
                    .limit(limit).toList();
        }

        @Override
        public Principal getUser(String objectId) {
            lookups++;
            return users.stream().filter(p -> p.sid().equals(objectId)).findFirst().orElse(null);
        }

        @Override
        public Principal getGroup(String objectId) {
            lookups++;
            return groups.stream().filter(p -> p.sid().equals(objectId)).findFirst().orElse(null);
        }

        @Override
        public Photo getUserPhoto(String objectId) {
            photos++;
            return ALICE_ID.equals(objectId) ? new Photo(new byte[] {1, 2, 3}, "image/png") : null;
        }
    }
}
