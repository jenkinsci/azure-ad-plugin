package com.microsoft.jenkins.azuread;

import hudson.util.Secret;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.core.Is.is;

public class AzureAdConfigurationSaveTest {

    public static final String TENANT = "tenant";
    public static final String CLIENT_ID = "clientId";
    public static final String CLIENT_SECRET = "thisIsSpecialSecret";
    public static final String CLIENT_CERTIFICATE= "thisIsSpecialCertificateSecret";

    public static final String CREDENTIAL_TYPE= "Secret";
    public static final int CACHE_DURATION = 15;
    @Rule
    public final RestartableJenkinsRule r = new RestartableJenkinsRule();

    @Test
    public void FromRequestSaveTest() {

        r.then(r->{
            AzureSecurityRealm realm = new AzureSecurityRealm(
                    TENANT,
                    CLIENT_ID,
                    Secret.fromString(CLIENT_SECRET),
                    Secret.fromString(CLIENT_CERTIFICATE),
                    CREDENTIAL_TYPE,
                    CACHE_DURATION);
            realm.setFromRequest(true);
            r.jenkins.setSecurityRealm(realm);

            AzureSecurityRealm result = (AzureSecurityRealm) r.jenkins.getSecurityRealm();
            assertThat(result, is(notNullValue()));
            assertThat(result.isFromRequest(), is(true));
            assertThat(result.getTenant(), is(TENANT));
            assertThat(result.getClientId(), is(CLIENT_ID));
            assertThat(result.getClientSecret().getPlainText(), is(CLIENT_SECRET));
            assertThat(result.getClientCertificate().getPlainText(), is(CLIENT_CERTIFICATE));
            assertThat(result.getCredentialType(), is(CREDENTIAL_TYPE));
            assertThat(result.getCacheDuration(), is(CACHE_DURATION));

        });
        r.then(r -> {
            AzureSecurityRealm result = (AzureSecurityRealm) r.jenkins.getSecurityRealm();
            assertThat(result, is(notNullValue()));
            assertThat(result.isFromRequest(), is(true));
            assertThat(result.getTenant(), is(TENANT));
            assertThat(result.getClientId(), is(CLIENT_ID));
            assertThat(result.getClientSecret().getPlainText(), is(CLIENT_SECRET));
            assertThat(result.getCredentialType(), is(CREDENTIAL_TYPE));
            assertThat(result.getCacheDuration(), is(CACHE_DURATION));

        });

    }

}
