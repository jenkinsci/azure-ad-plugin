package com.microsoft.jenkins.azuread;

import io.jenkins.plugins.microsoftgraph.GraphServiceClient;
import hudson.ProxyConfiguration;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

@WithJenkins
class GraphClientCacheTest {

    private static GraphServiceClient getClient() {
        return GraphClientCache.getClient(new GraphClientCacheKey(
                "client-id",
                "client-secret",
                "",
                "Secret",
                "tenant",
                "Azure",
                GraphClientCache.proxyConfigurationFingerprint(),
                null
        ));
    }

    @Test
    void testGraphClientIsRebuiltWhenProxyConfigurationChanges(JenkinsRule j) {
        GraphServiceClient first = getClient();
        assertSame(first, getClient());

        j.jenkins.setProxy(new ProxyConfiguration("proxy.example.com", 8888));
        GraphServiceClient second = getClient();
        assertNotSame(first, second);
        assertSame(second, getClient());

        j.jenkins.setProxy(null);
        assertNotSame(second, getClient());
    }
}
