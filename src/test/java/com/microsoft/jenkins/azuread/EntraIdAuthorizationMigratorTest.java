package com.microsoft.jenkins.azuread;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.model.Computer;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.AuthorizationStrategy;
import hudson.slaves.DumbSlave;
import hudson.util.DescribableList;
import jenkins.model.Jenkins;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritGlobalStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

@WithJenkins
class EntraIdAuthorizationMigratorTest {

    private static final String ADMINS_ID = "11111111-1111-1111-1111-111111111111";
    private static final String DEVS_ID = "22222222-2222-2222-2222-222222222222";
    private static final String CAROL_ID = "33333333-3333-3333-3333-333333333333";

    private JenkinsRule j;
    private FreeStyleProject job;
    private Folder folder;
    private DumbSlave agent;

    @BeforeEach
    void setUp(JenkinsRule j) throws Exception {
        this.j = j;
        JenkinsRule.DummySecurityRealm realm = j.createDummySecurityRealm();
        realm.addGroups("alice", ADMINS_ID);
        realm.addGroups("dave", DEVS_ID);
        j.jenkins.setSecurityRealm(realm);

        AzureAdMatrixAuthorizationStrategy strategy = new AzureAdMatrixAuthorizationStrategy();
        strategy.add(Jenkins.ADMINISTER, PermissionEntry.group("Admins (" + ADMINS_ID + ")"));
        strategy.add(Jenkins.READ, PermissionEntry.group(DEVS_ID));
        strategy.add(Jenkins.READ, PermissionEntry.user("bob@example.com"));
        j.jenkins.setAuthorizationStrategy(strategy);

        job = j.createFreeStyleProject("job");
        AzureAdAuthorizationMatrixProperty jobProperty = new AzureAdAuthorizationMatrixProperty();
        jobProperty.add(Item.READ, PermissionEntry.group("Developers (" + DEVS_ID + ")"));
        jobProperty.add(Item.BUILD, PermissionEntry.user("Carol (" + CAROL_ID + ")"));
        jobProperty.setInheritanceStrategy(new NonInheritingStrategy());
        job.addProperty(jobProperty);

        folder = j.jenkins.createProject(Folder.class, "folder");
        AzureAdAuthorizationMatrixFolderProperty folderProperty =
                new AzureAdAuthorizationMatrixFolderProperty(Collections.emptyList());
        folderProperty.add(Item.CONFIGURE, PermissionEntry.group("Developers (" + DEVS_ID + ")"));
        folderProperty.setInheritanceStrategy(new InheritGlobalStrategy());
        folder.addProperty(folderProperty);

        agent = j.createSlave("agent", null, null);
        AzureAdAuthorizationMatrixNodeProperty nodeProperty = new AzureAdAuthorizationMatrixNodeProperty();
        nodeProperty.add(Computer.CONFIGURE, PermissionEntry.group("Developers (" + DEVS_ID + ")"));
        agent.getNodeProperties().add(nodeProperty);
        j.jenkins.updateNode(agent);
    }

    @Test
    void preview() {
        EntraIdAuthorizationMigrator.Plan plan = asUser("alice", EntraIdAuthorizationMigrator::preview);
        assertThat(plan.getErrors(), empty());
        assertThat(plan.getJobs(), is(1));
        assertThat(plan.getFolders(), is(1));
        assertThat(plan.getNodes(), is(1));
        assertThat(plan.getSidChanges(), hasEntry("Admins (" + ADMINS_ID + ")", ADMINS_ID));
        assertThat(plan.getSidChanges(), hasEntry("Developers (" + DEVS_ID + ")", DEVS_ID));
        assertThat(plan.getSidChanges(), hasEntry("Carol (" + CAROL_ID + ")", CAROL_ID));
        assertThat(plan.getSidChanges(), not(hasEntry("bob@example.com", "bob@example.com")));

        // nothing changed
        assertThat(j.jenkins.getAuthorizationStrategy(), instanceOf(AzureAdMatrixAuthorizationStrategy.class));
        assertThat(job.getProperty(hudson.security.AuthorizationMatrixProperty.class), nullValue());
    }

    @Test
    void migrate() throws Exception {
        EntraIdAuthorizationMigrator.Plan plan = asUser("alice", () -> {
            try {
                return EntraIdAuthorizationMigrator.migrate();
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        });
        assertThat(plan.getErrors(), empty());
        assertThat(plan.getWarnings(), empty());
        assertMigrated();

        // survives a restart
        j.jenkins.reload();
        job = j.jenkins.getItemByFullName("job", FreeStyleProject.class);
        folder = j.jenkins.getItemByFullName("folder", Folder.class);
        agent = (DumbSlave) j.jenkins.getNode("agent");
        assertMigrated();
    }

    private void assertMigrated() {
        AuthorizationStrategy strategy = j.jenkins.getAuthorizationStrategy();
        assertThat(strategy, instanceOf(hudson.security.ProjectMatrixAuthorizationStrategy.class));
        var matrix = (hudson.security.ProjectMatrixAuthorizationStrategy) strategy;
        assertThat(matrix.hasExplicitPermission(
                org.jenkinsci.plugins.matrixauth.PermissionEntry.group(ADMINS_ID), Jenkins.ADMINISTER), is(true));
        assertThat(matrix.hasExplicitPermission(
                org.jenkinsci.plugins.matrixauth.PermissionEntry.user("bob@example.com"), Jenkins.READ), is(true));

        var jobProperty = job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
        assertThat(jobProperty.getInheritanceStrategy(), instanceOf(NonInheritingStrategy.class));
        assertThat(jobProperty.hasExplicitPermission(
                org.jenkinsci.plugins.matrixauth.PermissionEntry.group(DEVS_ID), Item.READ), is(true));
        assertThat(jobProperty.hasExplicitPermission(
                org.jenkinsci.plugins.matrixauth.PermissionEntry.user(CAROL_ID), Item.BUILD), is(true));
        assertThat(job.getProperty(AuthorizationMatrixProperty.class), nullValue());

        var folderProperty = folder.getProperties()
                .get(com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty.class);
        assertThat(folderProperty.getInheritanceStrategy(), instanceOf(InheritGlobalStrategy.class));
        assertThat(folderProperty.hasExplicitPermission(
                org.jenkinsci.plugins.matrixauth.PermissionEntry.group(DEVS_ID), Item.CONFIGURE), is(true));
        assertThat(folder.getProperties()
                .get(com.microsoft.jenkins.azuread.folder.properties.AuthorizationMatrixProperty.class), nullValue());

        DescribableList<hudson.slaves.NodeProperty<?>, ?> nodeProperties = agent.getNodeProperties();
        var nodeProperty = nodeProperties.get(org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty.class);
        assertThat(nodeProperty.hasExplicitPermission(
                org.jenkinsci.plugins.matrixauth.PermissionEntry.group(DEVS_ID), Computer.CONFIGURE), is(true));
        assertThat(nodeProperties.get(AuthorizationMatrixNodeProperty.class), nullValue());

        // effective permissions
        assertThat(j.jenkins.getACL().hasPermission2(impersonate("alice"), Jenkins.ADMINISTER), is(true));
        assertThat(job.getACL().hasPermission2(impersonate("dave"), Item.READ), is(true));
        assertThat(job.getACL().hasPermission2(impersonate("dave"), Item.BUILD), is(false));
        assertThat(folder.getACL().hasPermission2(impersonate("dave"), Item.CONFIGURE), is(true));
        assertThat(agent.getACL().hasPermission2(impersonate("dave"), Computer.CONFIGURE), is(true));
    }

    @Test
    void refusesToLockOutCurrentUser() throws Exception {
        AuthorizationStrategy before = j.jenkins.getAuthorizationStrategy();
        EntraIdAuthorizationMigrator.Plan plan = asUser("dave", () -> {
            try {
                return EntraIdAuthorizationMigrator.migrate();
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        });
        assertThat(plan.isPossible(), is(false));
        assertThat(j.jenkins.getAuthorizationStrategy(), sameInstance(before));
        assertThat(job.getProperty(hudson.security.AuthorizationMatrixProperty.class), nullValue());
    }

    @Test
    void reportsGroupsThatCannotBeResolved() throws Exception {
        AzureAdMatrixAuthorizationStrategy strategy =
                (AzureAdMatrixAuthorizationStrategy) j.jenkins.getAuthorizationStrategy();
        strategy.add(Jenkins.READ, PermissionEntry.group("Unknown Group"));
        EntraIdAuthorizationMigrator.Plan plan = asUser("alice", EntraIdAuthorizationMigrator::preview);
        assertThat(plan.getWarnings().size(), is(1));
        assertThat(plan.getWarnings().get(0), containsString("Unknown Group"));
    }

    @Test
    void monitorPage() throws Exception {
        EntraIdAuthorizationMigrationMonitor monitor =
                AdministrativeMonitorHolder.get(EntraIdAuthorizationMigrationMonitor.class);
        assertThat(monitor.isActivated(), is(true));

        try (JenkinsRule.WebClient wc = j.createWebClient().login("alice")) {
            HtmlPage page = wc.goTo(monitor.getUrl() + "/");
            assertThat(page.asNormalizedText(), containsString("Developers (" + DEVS_ID + ")"));
            HtmlForm form = page.getFormByName("migrate");
            HtmlPage result = j.submit(form);
            assertThat(result.asNormalizedText(), containsString("no longer uses"));
        }
        assertThat(monitor.isActivated(), is(false));
        assertThat(j.jenkins.getAuthorizationStrategy(),
                instanceOf(hudson.security.ProjectMatrixAuthorizationStrategy.class));
    }

    @Test
    void deprecatedStrategiesAreHiddenUnlessActive() {
        List<String> visible = visibleStrategies();
        assertThat(visible.contains(AzureAdMatrixAuthorizationStrategy.class.getName()), is(true));
        assertThat(visible.contains(GlobalMatrixAuthorizationStrategy.class.getName()), is(false));

        j.jenkins.setAuthorizationStrategy(new hudson.security.ProjectMatrixAuthorizationStrategy());
        visible = visibleStrategies();
        assertThat(visible.contains(AzureAdMatrixAuthorizationStrategy.class.getName()), is(false));
        assertThat(visible.contains(GlobalMatrixAuthorizationStrategy.class.getName()), is(false));
        assertThat(visible.contains(hudson.security.ProjectMatrixAuthorizationStrategy.class.getName()), is(true));
    }

    private List<String> visibleStrategies() {
        return hudson.model.DescriptorVisibilityFilter.apply(j.jenkins, AuthorizationStrategy.all()).stream()
                .map(d -> d.clazz.getName()).toList();
    }

    private static Authentication impersonate(String user) {
        return User.getById(user, true).impersonate2();
    }

    private static <T> T asUser(String user, java.util.function.Supplier<T> action) {
        try (ACLContext ignored = ACL.as2(impersonate(user))) {
            return action.get();
        }
    }

    private static final class AdministrativeMonitorHolder {
        static <T extends hudson.model.AdministrativeMonitor> T get(Class<T> type) {
            return hudson.ExtensionList.lookupSingleton(type);
        }
    }
}
