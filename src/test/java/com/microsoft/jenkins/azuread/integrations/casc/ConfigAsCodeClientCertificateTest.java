package com.microsoft.jenkins.azuread.integrations.casc;

import com.microsoft.jenkins.azuread.AzureSecurityRealm;
import hudson.security.SecurityRealm;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkinsConfiguredWithCode
class ConfigAsCodeClientCertificateTest extends BaseConfigAsCodeTest {

    @Test
    @ConfiguredWithCode("configuration-as-code-certificate-auth.yml")
    void should_support_configuration_as_code_clientCertificate(JenkinsConfiguredWithCodeRule jCertificate) {
        SecurityRealm securityRealm = jCertificate.jenkins.getSecurityRealm();
        assertInstanceOf(AzureSecurityRealm.class, securityRealm, "security realm");
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
