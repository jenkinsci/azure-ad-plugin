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

public class ConfigAsCodeClientCertificateTest extends BaseConfigAsCodeTest {

    @ClassRule
    @ConfiguredWithCode("configuration-as-code-certificate-auth.yml")
    public static JenkinsConfiguredWithCodeRule jCertificate = new JenkinsConfiguredWithCodeRule();

    @Test
    public void should_support_configuration_as_code_clientCertificate() {
        SecurityRealm securityRealm = jCertificate.jenkins.getSecurityRealm();
        assertTrue("security realm", securityRealm instanceof AzureSecurityRealm);
        AzureSecurityRealm azureSecurityRealm = (AzureSecurityRealm) securityRealm;
        assertNotEquals("clientId", azureSecurityRealm.getClientIdSecret());
        assertNotEquals("clientCertificate", azureSecurityRealm.getClientCertificateSecret());
        assertNotEquals("tenantId", azureSecurityRealm.getTenantSecret());
        assertEquals("clientId", azureSecurityRealm.getClientId());
        assertEquals("Certificate", azureSecurityRealm.getCredentialType());
        assertEquals("clientCertificate", azureSecurityRealm.getClientCertificate().getPlainText());
        assertEquals("tenantId", azureSecurityRealm.getTenant());
        assertEquals(0, azureSecurityRealm.getCacheDuration());
        assertTrue(azureSecurityRealm.isFromRequest());

        validateCommonAssertions(jCertificate);
    }
}
