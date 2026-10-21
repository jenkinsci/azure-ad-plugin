package com.microsoft.jenkins.azuread;

import hudson.model.AbstractItem;
import hudson.model.Action;
import hudson.model.Computer;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.UnprotectedRootAction;
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

import java.util.Collection;
import java.util.List;

import static com.microsoft.jenkins.azuread.EntraIdPrincipalSearchProviderTest.ADMINS_ID;
import static com.microsoft.jenkins.azuread.EntraIdPrincipalSearchProviderTest.ALBERT_ID;
import static com.microsoft.jenkins.azuread.EntraIdPrincipalSearchProviderTest.ALICE_ID;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

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
    void requiresPermissionToConfigureAccessWhereAttached() throws Exception {
        // the dummy realm allows logging in; requests that get past the permission check then find no Entra
        // directory, so allowed is a 404 and denied a 403
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.READ).everywhere().to("bob", "carol", "dave")
                .grant(Item.READ, Item.CONFIGURE).onItems(job).to("bob")
                .grant(Item.READ).onItems(job).to("carol")
                .grant(Computer.CONFIGURE).everywhere().to("carol")
                .grant(Jenkins.SYSTEM_READ).everywhere().to("dave"));

        try (JenkinsRule.WebClient wc = j.createWebClient().login("bob")) {
            assertThat(photoStatus(wc, "job/job/"), is(404));
            assertThat(photoStatus(wc, "computer/(built-in)/"), is(403));
            assertThat(photoStatus(wc, ""), is(403));
        }
        try (JenkinsRule.WebClient wc = j.createWebClient().login("carol")) {
            assertThat(photoStatus(wc, "computer/(built-in)/"), is(404));
            assertThat(photoStatus(wc, "job/job/"), is(403));
            assertThat(photoStatus(wc, ""), is(403));
        }
        try (JenkinsRule.WebClient wc = j.createWebClient().login("dave")) {
            assertThat(photoStatus(wc, ""), is(404));
        }
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            wc.setThrowExceptionOnFailingStatusCode(false);
            Page page = wc.goTo("EntraIdPhoto/" + ALICE_ID, null);
            assertThat(page.getUrl().getPath(), is("/jenkins/login"));
        }
    }

    private static int photoStatus(JenkinsRule.WebClient wc, String prefix) throws Exception {
        wc.setThrowExceptionOnFailingStatusCode(false);
        return wc.goTo(prefix + "EntraIdPhoto/" + ALICE_ID, null).getWebResponse().getStatusCode();
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
