package com.microsoft.jenkins.azuread;

import com.microsoft.graph.requests.GraphServiceClient;
import hudson.ProxyConfiguration;
import okhttp3.Request;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

@WithJenkins
class GraphClientCacheTest {

    private static GraphServiceClient<Request> getClient() {
        return GraphClientCache.getClient(new GraphClientCacheKey(
                "client-id",
                "client-secret",
                "",
                "Secret",
                "tenant",
                "Azure",
                GraphClientCache.proxyConfigurationFingerprint()
        ));
    }

    @Test
    void testGraphClientIsRebuiltWhenProxyConfigurationChanges(JenkinsRule j) {
        GraphServiceClient<Request> first = getClient();
        assertSame(first, getClient());

        j.jenkins.setProxy(new ProxyConfiguration("proxy.example.com", 8888));
        GraphServiceClient<Request> second = getClient();
        assertNotSame(first, second);
        assertSame(second, getClient());

        j.jenkins.setProxy(null);
        assertNotSame(second, getClient());
    }
}
