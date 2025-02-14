package com.microsoft.jenkins.azuread.integrations.casc;

import com.microsoft.jenkins.azuread.AzureSecurityRealm;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import org.junit.ClassRule;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class ConfigAsCodeClientSecretTest extends BaseConfigAsCodeTest {

    @ClassRule
    @ConfiguredWithCode("configuration-as-code-secret-auth.yml")
    public static JenkinsConfiguredWithCodeRule jSecret = new JenkinsConfiguredWithCodeRule();

    @Test
    public void should_support_configuration_as_code_clientSecret() {
        SecurityRealm securityRealm = jSecret.jenkins.getSecurityRealm();
        assertTrue("security realm", securityRealm instanceof AzureSecurityRealm);
        AzureSecurityRealm azureSecurityRealm = (AzureSecurityRealm) securityRealm;
        assertNotEquals("clientId", azureSecurityRealm.getClientIdSecret());
        assertNotEquals("clientSecret", azureSecurityRealm.getClientSecretSecret());
        assertNotEquals("tenantId", azureSecurityRealm.getTenantSecret());
        assertEquals("clientId", azureSecurityRealm.getClientId());
        assertEquals("Secret", azureSecurityRealm.getCredentialType());
        assertEquals("clientSecret", azureSecurityRealm.getClientSecret().getPlainText());
        assertEquals("tenantId", azureSecurityRealm.getTenant());
        assertEquals(0, azureSecurityRealm.getCacheDuration());
        assertTrue(azureSecurityRealm.isFromRequest());

        validateCommonAssertions(jSecret);
    }
}
