package com.microsoft.jenkins.azuread;

import hudson.model.AbstractItem;
import hudson.model.Action;
import hudson.model.Computer;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.UnprotectedRootAction;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.AccessDeniedException3;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import io.jenkins.plugins.authcommons.PrincipalSearch;
import jenkins.model.Jenkins;
import jenkins.model.TransientActionFactory;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.htmlunit.Page;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.Collection;
import java.util.List;

import static com.microsoft.jenkins.azuread.EntraIdPrincipalSearchProviderTest.ADMINS_ID;
import static com.microsoft.jenkins.azuread.EntraIdPrincipalSearchProviderTest.ALBERT_ID;
import static com.microsoft.jenkins.azuread.EntraIdPrincipalSearchProviderTest.ALICE_ID;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@WithJenkins
class EntraIdPhotoProxyTest {

    private JenkinsRule j;
    private EntraIdPrincipalSearchProviderTest.FakeDirectory directory;
    private FreeStyleProject job;

    @BeforeEach
    void setUp(JenkinsRule j) throws Exception {
        this.j = j;
        j.jenkins.setSecurityRealm(new AzureSecurityRealm("tenant", "clientId", Secret.fromString("secret"), 0));
        directory = new EntraIdPrincipalSearchProviderTest.FakeDirectory();
        EntraIdPrincipalSearchProvider.get().setDirectoryFactory(realm -> directory);
        job = j.createFreeStyleProject("job");
    }

    @Test
    void servesAndCachesPhotos() throws Exception {
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER).everywhere().toEveryone());
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            Page photo = wc.goTo("EntraIdPhoto/" + ALICE_ID, "image/png");
            assertThat(photo.getWebResponse().getContentAsStream().readAllBytes().length, is(3));
            assertThat(photo.getWebResponse().getResponseHeaderValue("X-Content-Type-Options"), is("nosniff"));
            wc.goTo("job/job/EntraIdPhoto/" + ALICE_ID, "image/png");
            wc.goTo("computer/(built-in)/EntraIdPhoto/" + ALICE_ID, "image/png");
            assertThat(directory.photos, is(1));

            wc.setThrowExceptionOnFailingStatusCode(false);
            assertThat(wc.goTo("EntraIdPhoto/" + ALBERT_ID, null).getWebResponse().getStatusCode(), is(404));
            assertThat(wc.goTo("EntraIdPhoto/not-an-id", null).getWebResponse().getStatusCode(), is(404));
        }
    }

    @Test
    void requiresPermissionToConfigureAccessWhereAttached() {
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.READ).everywhere().to("bob", "carol")
                .grant(Item.READ, Item.CONFIGURE).onItems(job).to("bob")
                .grant(Computer.CONFIGURE).everywhere().to("carol"));
        Computer builtIn = j.jenkins.toComputer();

        try (ACLContext ignored = ACL.as2(authentication("bob"))) {
            assertDoesNotThrow(() -> new EntraIdPhotoProxy(job).getTarget());
            assertThrows(AccessDeniedException3.class, () -> new EntraIdPhotoProxy(builtIn).getTarget());
            assertThrows(AccessDeniedException3.class, () -> new EntraIdPhotoProxy().getTarget());
        }
        try (ACLContext ignored = ACL.as2(authentication("carol"))) {
            assertDoesNotThrow(() -> new EntraIdPhotoProxy(builtIn).getTarget());
            assertThrows(AccessDeniedException3.class, () -> new EntraIdPhotoProxy(job).getTarget());
        }
        try (ACLContext ignored = ACL.as2(Jenkins.ANONYMOUS2)) {
            assertThrows(AccessDeniedException3.class, () -> new EntraIdPhotoProxy().getTarget());
        }
    }

    @Test
    void avatarUrlsPointToTheObjectSearchedFrom() throws Exception {
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            JSONArray root = search(wc, "searchTest/search?q=al");
            assertThat(root.getJSONObject(0).getString("sid"), is(ALICE_ID));
            assertThat(root.getJSONObject(0).getString("avatarUrl"), is("/jenkins/EntraIdPhoto/" + ALICE_ID));
            // groups have no photos
            JSONObject group = root.getJSONObject(2);
            assertThat(group.getString("sid"), is(ADMINS_ID));
            assertThat(group.has("avatarUrl"), is(false));

            JSONArray fromJob = search(wc, "job/job/searchTest/search?q=al");
            assertThat(fromJob.getJSONObject(0).getString("avatarUrl"),
                    is("/jenkins/job/job/EntraIdPhoto/" + ALICE_ID));

            JSONArray fromComputer = search(wc, "computer/(built-in)/searchTest/search?q=al");
            assertThat(fromComputer.getJSONObject(0).getString("avatarUrl"),
                    is("/jenkins/computer/(built-in)/EntraIdPhoto/" + ALICE_ID));
        }
    }

    @Test
    void photosCanBeDisabled() throws Exception {
        System.setProperty(AzureSecurityRealm.class.getName() + ".disableAvatar", "true");
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            assertThat(search(wc, "searchTest/search?q=al").getJSONObject(0).has("avatarUrl"), is(false));
        } finally {
            System.clearProperty(AzureSecurityRealm.class.getName() + ".disableAvatar");
        }
    }

    private static JSONArray search(JenkinsRule.WebClient wc, String path) throws Exception {
        Page page = wc.goTo(path, "application/json");
        return JSONObject.fromObject(page.getWebResponse().getContentAsString()).getJSONArray("results");
    }

    private static UsernamePasswordAuthenticationToken authentication(String user) {
        return new UsernamePasswordAuthenticationToken(user, "", List.of(SecurityRealm.AUTHENTICATED_AUTHORITY2));
    }

    public static class SearchAction implements UnprotectedRootAction {
        @Override
        public String getIconFileName() {
            return null;
        }

        @Override
        public String getDisplayName() {
            return null;
        }

        @Override
        public String getUrlName() {
            return "searchTest";
        }

        public HttpResponse doSearch(@QueryParameter String q) {
            return PrincipalSearch.searchResponse(q, null, null);
        }
    }

    @TestExtension({"avatarUrlsPointToTheObjectSearchedFrom", "photosCanBeDisabled"})
    public static class RootSearchAction extends SearchAction {
    }

    @TestExtension("avatarUrlsPointToTheObjectSearchedFrom")
    public static class ItemSearchActionFactory extends TransientActionFactory<AbstractItem> {
        @Override
        public Class<AbstractItem> type() {
            return AbstractItem.class;
        }

        @Override
        public Collection<? extends Action> createFor(AbstractItem target) {
            return List.of(new SearchAction());
        }
    }

    @TestExtension("avatarUrlsPointToTheObjectSearchedFrom")
    public static class ComputerSearchActionFactory extends TransientActionFactory<Computer> {
        @Override
        public Class<Computer> type() {
            return Computer.class;
        }

        @Override
        public Collection<? extends Action> createFor(Computer target) {
            return List.of(new SearchAction());
        }
    }
}
