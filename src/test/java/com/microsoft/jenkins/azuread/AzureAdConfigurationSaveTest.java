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
                    Secret.fromString(CLIENT_CERTIFICATE),
                    credentialType,
                    CACHE_DURATION);
            realm.setFromRequest(true);
            r.jenkins.setSecurityRealm(realm);

            AzureSecurityRealm result = (AzureSecurityRealm) r.jenkins.getSecurityRealm();
            assertThat(result, is(notNullValue()));
            assertThat(result.isFromRequest(), is(true));
            assertThat(result.getTenant(), is(TENANT));
            assertThat(result.getClientId(), is(CLIENT_ID));
            if ("Secret".equals(credentialType)) {
                assertThat(result.getClientSecret().getPlainText(), is(CLIENT_SECRET));
            } else if ("Certificate".equals(credentialType)) {
                assertThat(result.getClientCertificate().getPlainText(), is(CLIENT_CERTIFICATE));
            }
            assertThat(result.getCredentialType(), is(credentialType));
            assertThat(result.getCacheDuration(), is(CACHE_DURATION));
        });
        r.then(r -> {
            AzureSecurityRealm result = (AzureSecurityRealm) r.jenkins.getSecurityRealm();
            assertThat(result, is(notNullValue()));
            assertThat(result.isFromRequest(), is(true));
            assertThat(result.getTenant(), is(TENANT));
            assertThat(result.getClientId(), is(CLIENT_ID));
            if ("Secret".equals(credentialType)) {
                assertThat(result.getClientSecret().getPlainText(), is(CLIENT_SECRET));
            } else if ("Certificate".equals(credentialType)) {
                assertThat(result.getClientCertificate().getPlainText(), is(CLIENT_CERTIFICATE));
            }
            assertThat(result.getCredentialType(), is(credentialType));
            assertThat(result.getCacheDuration(), is(CACHE_DURATION));
        });
    }
}