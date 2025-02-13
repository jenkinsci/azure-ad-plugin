package com.microsoft.jenkins.azuread;

import hudson.util.Secret;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.core.Is.is;

@WithJenkins
class AzureAdConfigurationSaveTest {

    private static final String TENANT = "tenant";
    private static final String CLIENT_ID = "clientId";
    private static final String CLIENT_SECRET = "thisIsSpecialSecret";
    private static final String CLIENT_CERTIFICATE = "thisIsSpecialCertificateSecret";
    private static final int CACHE_DURATION = 15;

    private JenkinsRule r;

    @BeforeEach
    void setUp(JenkinsRule r) {
        this.r = r;
    }

    static Object[][] data() {
        return new Object[][]{
                {"Secret"},
                {"Certificate"}
        };
    }

    @ParameterizedTest(name = "{index}: credentialType={0}")
    @MethodSource("data")
    void fromRequestSaveTest(String credentialType) throws Throwable {
        AzureSecurityRealm realm = new AzureSecurityRealm(
                TENANT,
                CLIENT_ID,
                Secret.fromString(CLIENT_SECRET),
                CACHE_DURATION);
        realm.setFromRequest(true);
        r.jenkins.setSecurityRealm(realm);

        AzureSecurityRealm result = (AzureSecurityRealm) r.jenkins.getSecurityRealm();
        result.setCredentialType(credentialType);
        if ("Certificate".equals(credentialType)) {
            result.setClientCertificate(CLIENT_CERTIFICATE);
        }
        verifyRealm(result, credentialType);

        r.restart();

        result = (AzureSecurityRealm) r.jenkins.getSecurityRealm();
        result.setCredentialType(credentialType);
        if ("Certificate".equals(credentialType)) {
            result.setClientCertificate(CLIENT_CERTIFICATE);
        }
        verifyRealm(result, credentialType);
    }

    private static void verifyRealm(AzureSecurityRealm realm, String credentialType) {
        assertThat(realm, is(notNullValue()));
        assertThat(realm.isFromRequest(), is(true));
        assertThat(realm.getTenant(), is(TENANT));
        assertThat(realm.getClientId(), is(CLIENT_ID));
        if ("Secret".equals(credentialType)) {
            assertThat(realm.getClientSecret().getPlainText(), is(CLIENT_SECRET));
        } else if ("Certificate".equals(credentialType)) {
            assertThat(realm.getClientCertificate().getPlainText(), is(CLIENT_CERTIFICATE));
        }
        assertThat(realm.getCredentialType(), is(credentialType));
        assertThat(realm.getCacheDuration(), is(CACHE_DURATION));
    }
}
