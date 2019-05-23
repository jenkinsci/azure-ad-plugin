package com.microsoft.jenkins.azuread.integrations.casc;

import com.microsoft.jenkins.azuread.AzureAdMatrixAuthorizationStrategy;
import com.microsoft.jenkins.azuread.AzureSecurityRealm;
import hudson.model.Item;
import hudson.security.AuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import jenkins.model.Jenkins;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.LoggerRule;

import java.util.logging.Level;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ConfigAsCodeTest {
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
        assertEquals("clientId", azureSecurityRealm.getClientId());
        assertEquals("clientSecret", azureSecurityRealm.getClientSecret());
        assertEquals("tenantId", azureSecurityRealm.getTenant());

        AuthorizationStrategy authorizationStrategy = j.jenkins.getAuthorizationStrategy();
        assertTrue("authorization strategy", authorizationStrategy instanceof AzureAdMatrixAuthorizationStrategy);
        AzureAdMatrixAuthorizationStrategy azureAdMatrixAuthorizationStrategy = (AzureAdMatrixAuthorizationStrategy) authorizationStrategy;
        { // global
            assertEquals("one real user sid", 2, azureAdMatrixAuthorizationStrategy.getAllSIDs().size());
            assertTrue("anon can read", azureAdMatrixAuthorizationStrategy.hasExplicitPermission("anonymous", Jenkins.READ));
            assertTrue("authenticated can read", azureAdMatrixAuthorizationStrategy.hasExplicitPermission("upn", Jenkins.READ));
            assertTrue("authenticated can build", azureAdMatrixAuthorizationStrategy.hasExplicitPermission("authenticated", Item.BUILD));
            assertTrue("authenticated can delete jobs", azureAdMatrixAuthorizationStrategy.hasExplicitPermission("upn", Item.DELETE));
            assertTrue("authenticated can administer", azureAdMatrixAuthorizationStrategy.hasExplicitPermission("upn", Jenkins.ADMINISTER));
        }

        assertEquals("no warnings", 0, l.getMessages().size());
    }

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    public void export_configuration() throws Exception {

    }
}
