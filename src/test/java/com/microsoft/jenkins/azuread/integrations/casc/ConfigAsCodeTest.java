package com.microsoft.jenkins.azuread.integrations.casc;

import com.microsoft.jenkins.azuread.AzureAdMatrixAuthorizationStrategy;
import com.microsoft.jenkins.azuread.AzureSecurityRealm;
import hudson.model.Item;
import hudson.security.AuthorizationStrategy;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.Configurator;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.model.CNode;
import io.jenkins.plugins.casc.model.Mapping;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.LoggerRule;
import org.jvnet.hudson.test.recipes.LocalData;

import java.util.List;
import java.util.logging.Level;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ConfigAsCodeTest {
    private static final String TEST_UPN = "abc@jenkins.com";

    @Rule
    public JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @Rule
    public LoggerRule l = new LoggerRule().record(AzureAdMatrixAuthorizationStrategyConfigurator.class, Level.WARNING).capture(20);

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    public void should_support_configuration_as_code() {
        SecurityRealm securityRealm = j.jenkins.getSecurityRealm();
        assertTrue("security realm", securityRealm instanceof AzureSecurityRealm);
        AzureSecurityRealm azureSecurityRealm = (AzureSecurityRealm) securityRealm;
        assertNotEquals("clientId", azureSecurityRealm.getClientIdSecret());
        assertNotEquals("clientSecret", azureSecurityRealm.getClientSecretSecret());
        assertNotEquals("tenantId", azureSecurityRealm.getTenantSecret());
        assertEquals("clientId", azureSecurityRealm.getClientId());
        assertEquals("clientSecret", azureSecurityRealm.getClientSecret());
        assertEquals("tenantId", azureSecurityRealm.getTenant());
        assertTrue(azureSecurityRealm.isFromRequest());

        AuthorizationStrategy authorizationStrategy = j.jenkins.getAuthorizationStrategy();
        assertTrue("authorization strategy", authorizationStrategy instanceof AzureAdMatrixAuthorizationStrategy);
        AzureAdMatrixAuthorizationStrategy azureAdMatrixAuthorizationStrategy = (AzureAdMatrixAuthorizationStrategy) authorizationStrategy;

        assertEquals("one real user sid", 2, azureAdMatrixAuthorizationStrategy.getAllSIDs().size());
        assertTrue("anon can read", azureAdMatrixAuthorizationStrategy.hasExplicitPermission("anonymous", Jenkins.READ));
        assertTrue("authenticated can read", azureAdMatrixAuthorizationStrategy.hasExplicitPermission(TEST_UPN, Jenkins.READ));
        assertTrue("authenticated can build", azureAdMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Item.BUILD));
        assertTrue("authenticated can delete jobs", azureAdMatrixAuthorizationStrategy.hasExplicitPermission(TEST_UPN, Item.DELETE));
        assertTrue("authenticated can administer", azureAdMatrixAuthorizationStrategy.hasExplicitPermission(TEST_UPN, Jenkins.ADMINISTER));

        assertEquals("no warnings", 0, l.getMessages().size());
    }

    @Test
    @LocalData
    public void export_configuration() throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);

        SecurityRealm securityRealm = j.jenkins.getSecurityRealm();
        Configurator realmConfigurator = context.lookupOrFail(AzureSecurityRealm.class);
        @SuppressWarnings("unchecked")
        CNode realmNode = realmConfigurator.describe(securityRealm, context);
        assertNotNull(realmNode);
        Mapping realMapping = realmNode.asMapping();
        assertEquals(4, realMapping.size());

        AzureSecurityRealm azureSecurityRealm = (AzureSecurityRealm) securityRealm;
        String encryptedClientSecret = azureSecurityRealm.getClientSecretSecret();
        String clientSecret = realMapping.getScalarValue("clientSecret");
        assertNotEquals(clientSecret, encryptedClientSecret);
        assertEquals(clientSecret, azureSecurityRealm.getClientSecret());

        AuthorizationStrategy authorizationStrategy = j.jenkins.getAuthorizationStrategy();
        Configurator c = context.lookupOrFail(AzureAdMatrixAuthorizationStrategy.class);

        @SuppressWarnings("unchecked")
        CNode node = c.describe(authorizationStrategy, context);
        assertNotNull(node);
        Mapping mapping = node.asMapping();

        List<CNode> permissions = mapping.get("permissions").asSequence();
        assertEquals("list size", 18, permissions.size());
    }
}
