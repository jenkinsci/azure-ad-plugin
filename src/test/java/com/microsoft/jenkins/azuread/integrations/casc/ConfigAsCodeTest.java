package com.microsoft.jenkins.azuread.integrations.casc;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.microsoft.jenkins.azuread.AzureAdAuthorizationMatrixFolderProperty;
import com.microsoft.jenkins.azuread.AzureAdAuthorizationMatrixNodeProperty;
import com.microsoft.jenkins.azuread.AzureAdMatrixAuthorizationStrategy;
import com.microsoft.jenkins.azuread.AzureSecurityRealm;
import com.microsoft.jenkins.azuread.PermissionEntry;
import hudson.model.Computer;
import hudson.model.Item;
import hudson.model.Node;
import hudson.security.AuthorizationStrategy;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.model.CNode;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.LoggerRule;

import java.util.logging.Level;

import static io.jenkins.plugins.casc.misc.Util.getJenkinsRoot;
import static io.jenkins.plugins.casc.misc.Util.toStringFromYamlFile;
import static io.jenkins.plugins.casc.misc.Util.toYamlString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ConfigAsCodeTest {
    private static final String TEST_UPN = "abc@jenkins.com";

    @ClassRule
    @ConfiguredWithCode("configuration-as-code.yml")
    public static JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @Rule
    public LoggerRule l = new LoggerRule().record(MatrixAuthorizationStrategyConfigurator.class, Level.WARNING).capture(20);

    @Test
    public void should_support_configuration_as_code() {
        SecurityRealm securityRealm = j.jenkins.getSecurityRealm();
        assertTrue("security realm", securityRealm instanceof AzureSecurityRealm);
        AzureSecurityRealm azureSecurityRealm = (AzureSecurityRealm) securityRealm;
        assertNotEquals("clientId", azureSecurityRealm.getClientIdSecret());
        assertNotEquals("clientSecret", azureSecurityRealm.getClientSecretSecret());
        assertNotEquals("clientCertificate", azureSecurityRealm.getClientCertificateSecret());
        assertNotEquals("tenantId", azureSecurityRealm.getTenantSecret());
        assertEquals("clientId", azureSecurityRealm.getClientId());
        assertEquals("credentialType", azureSecurityRealm.getCredentialType());
        assertEquals("clientSecret", azureSecurityRealm.getClientSecret().getPlainText());
        assertEquals("clientCertificate", azureSecurityRealm.getClientCertificate().getPlainText());
        assertEquals("tenantId", azureSecurityRealm.getTenant());
        assertEquals(0, azureSecurityRealm.getCacheDuration());
        assertTrue(azureSecurityRealm.isFromRequest());

        AuthorizationStrategy authorizationStrategy = j.jenkins.getAuthorizationStrategy();
        assertTrue("authorization strategy", authorizationStrategy instanceof AzureAdMatrixAuthorizationStrategy);
        AzureAdMatrixAuthorizationStrategy azureAdMatrixAuthorizationStrategy = (AzureAdMatrixAuthorizationStrategy) authorizationStrategy;

        assertEquals("one real user sid", 2, azureAdMatrixAuthorizationStrategy.getAllPermissionEntries().size());
        assertTrue("anon can read", azureAdMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.user("anonymous"), Jenkins.READ));
        assertTrue("authenticated can read", azureAdMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.user(TEST_UPN), Jenkins.READ));
        assertTrue("authenticated can build", azureAdMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.BUILD));
        assertTrue("authenticated can delete jobs", azureAdMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.user(TEST_UPN), Item.DELETE));
        assertTrue("authenticated can administer", azureAdMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.user(TEST_UPN), Jenkins.ADMINISTER));

        assertEquals("no warnings", 0, l.getMessages().size());

        {
            Node agent = j.jenkins.getNode("agent");
            assertThat(agent, is(notNullValue()));
            assertThat(agent.getDisplayName(), is(equalTo("agent")));
            AzureAdAuthorizationMatrixNodeProperty nodeProperty =
                    agent.getNodeProperty(AzureAdAuthorizationMatrixNodeProperty.class);
            assertThat(nodeProperty, is(notNullValue()));
            assertThat(nodeProperty.getInheritanceStrategy(), instanceOf(NonInheritingStrategy.class));
            assertThat(
                    nodeProperty
                            .hasExplicitPermission(PermissionEntry.user("Adele Vance (be674052-e519-4231-b5e7-2b390bff6346)"),
                                    Computer.BUILD),
                    is(true)
            );
        }

        {
            Folder folder = (Folder) j.jenkins.getItem("generated");
            assertNotNull(folder);
            AzureAdAuthorizationMatrixFolderProperty property = folder.getProperties()
                    .get(AzureAdAuthorizationMatrixFolderProperty.class);
            assertTrue("folder property inherits", property.getInheritanceStrategy() instanceof NonInheritingStrategy);
            String groupSid = "Some group (7fe913e8-6c9f-40f8-913e-7178b7768cc5)";
            assertTrue(property.hasExplicitPermission(PermissionEntry.group(groupSid), Item.BUILD));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group(groupSid), Item.READ));
            assertFalse(property.hasExplicitPermission(PermissionEntry.user("anonymous"), Item.READ));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group(groupSid), Item.CONFIGURE));
            assertTrue(property.hasExplicitPermission(PermissionEntry.group(groupSid), Item.DELETE));

            String userSid = "c411116f-cfa6-472c-8ccf-d0cb6053c9aa";
            assertTrue(property.hasExplicitPermission(PermissionEntry.user(userSid), Item.BUILD));
        }
    }

    @Test
    public void export_configuration() throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        CNode yourAttribute = getJenkinsRoot(context).get("authorizationStrategy");

        String exported = toYamlString(yourAttribute);

        String expected = toStringFromYamlFile(this, "configuration-as-code-exported.yml");

        assertThat(exported, is(expected));
    }
}