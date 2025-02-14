package com.microsoft.jenkins.azuread;

import hudson.util.Secret;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import java.util.Arrays;
import java.util.Collection;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.core.Is.is;

@RunWith(Parameterized.class)
public class AzureAdConfigurationSaveTest {

    public static final String TENANT = "tenant";
    public static final String CLIENT_ID = "clientId";
    public static final String CLIENT_SECRET = "thisIsSpecialSecret";
    public static final String CLIENT_CERTIFICATE = "thisIsSpecialCertificateSecret";
    public static final int CACHE_DURATION = 15;

    @Rule
    public final RestartableJenkinsRule r = new RestartableJenkinsRule();

    @Parameterized.Parameter(0)
    public String credentialType;

    @Parameterized.Parameters(name = "{index}: credentialType={0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                {"Secret"},
                {"Certificate"}
        });
    }

    @Test
    public void FromRequestSaveTest() {
        r.then(r -> {
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
        });

        r.then(r -> {
            AzureSecurityRealm result = (AzureSecurityRealm) r.jenkins.getSecurityRealm();
            result.setCredentialType(credentialType);
            if ("Certificate".equals(credentialType)) {
                result.setClientCertificate(CLIENT_CERTIFICATE);
            }
            verifyRealm(result, credentialType);
        });
    }

    private void verifyRealm(AzureSecurityRealm realm, String credentialType) {
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
