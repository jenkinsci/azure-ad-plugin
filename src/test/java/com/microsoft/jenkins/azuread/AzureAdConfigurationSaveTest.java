package com.microsoft.jenkins.azuread;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class AzureAdConfigurationSaveTest {

    public static final String TENANT = "tenant";
    public static final String CLIENT_ID = "clientId";
    public static final String CLIENT_SECRET = "thisIsSpecialSecret";
    public static final int CACHE_DURATION = 15;
    public static final String UNWANTED_USERNAME_SUFFIXES = "suffix";
    @Rule
    public final RestartableJenkinsRule r = new RestartableJenkinsRule();

    @Test
    public void FromRequestSaveTest() throws Exception {

        r.then(r->{
            AzureSecurityRealm realm = new AzureSecurityRealm(
                    TENANT,
                    CLIENT_ID,
                    CLIENT_SECRET,
                    CACHE_DURATION,
                    UNWANTED_USERNAME_SUFFIXES);
            realm.setFromRequest(true);
            r.jenkins.setSecurityRealm(realm);

            AzureSecurityRealm result = (AzureSecurityRealm) r.jenkins.getSecurityRealm();
            assertThat(result, is(notNullValue()));
            assertThat(result.isFromRequest(), is(true));
            assertThat(result.getTenant(), is(TENANT));
            assertThat(result.getClientId(), is(CLIENT_ID));
            assertThat(result.getClientSecret().getPlainText(), is(CLIENT_SECRET));
            assertThat(result.getCacheDuration(), is(CACHE_DURATION));

        });
        r.then(r -> {
            AzureSecurityRealm result = (AzureSecurityRealm) r.jenkins.getSecurityRealm();
            assertThat(result, is(notNullValue()));
            assertThat(result.isFromRequest(), is(true));
            assertThat(result.getTenant(), is(TENANT));
            assertThat(result.getClientId(), is(CLIENT_ID));
            assertThat(result.getClientSecret().getPlainText(), is(CLIENT_SECRET));
            assertThat(result.getCacheDuration(), is(CACHE_DURATION));

        });

    }

}
