package com.microsoft.jenkins.azuread;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.ClientCertificateCredential;
import com.azure.identity.ClientCertificateCredentialBuilder;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.microsoft.graph.authentication.TokenCredentialAuthProvider;
import com.microsoft.graph.httpcore.HttpClients;
import com.microsoft.graph.requests.GraphServiceClient;
import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.util.Secret;
import io.jenkins.plugins.azuresdk.HttpClientRetriever;
import java.net.URI;
import jenkins.model.Jenkins;
import jenkins.util.JenkinsJVM;
import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.apache.commons.lang3.StringUtils;

import java.net.Proxy;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static com.microsoft.jenkins.azuread.AzureEnvironment.AZURE_PUBLIC_CLOUD;
import static com.microsoft.jenkins.azuread.AzureEnvironment.getAuthorityHost;
import static com.microsoft.jenkins.azuread.AzureEnvironment.getGraphResource;
import static com.microsoft.jenkins.azuread.AzureEnvironment.getServiceRoot;
import static java.util.Collections.singletonList;

public class GraphClientCache {

    private static final int TEN = 10;
    private static final LoadingCache<GraphClientCacheKey, GraphServiceClient<Request>> TOKEN_CACHE = Caffeine.newBuilder()
            .maximumSize(TEN)
            .build(GraphClientCache::createGraphClient);

    private static GraphServiceClient<Request> createGraphClient(GraphClientCacheKey key) {
        TokenCredentialAuthProvider authProvider = getAuthProvider(key);

        OkHttpClient.Builder builder = HttpClients.createDefault(authProvider)
                .newBuilder();

        String azureEnv = key.azureEnvironmentName();
        String targetUrl = getGraphResource(azureEnv);

        builder = addProxyToHttpClientIfRequired(builder, targetUrl);
        final OkHttpClient graphHttpClient = builder.build();

        GraphServiceClient<Request> graphServiceClient = GraphServiceClient
                .builder()
                .httpClient(graphHttpClient)
                .buildClient();



        if (!azureEnv.equals(AZURE_PUBLIC_CLOUD)) {
            graphServiceClient.setServiceRoot(getServiceRoot(azureEnv));
        }
        return graphServiceClient;
    }

    private static TokenCredentialAuthProvider getAuthProvider(GraphClientCacheKey key) {
        String graphResource = AzureEnvironment.getGraphResource(key.azureEnvironmentName());

        TokenCredential tokenCredential;
        if ("Secret".equals(key.credentialType())) {
            tokenCredential = getClientSecretCredential(key);
        } else if ("Certificate".equals(key.credentialType())) {
            tokenCredential = getClientCertificateCredential(key);
        } else {
            throw new IllegalArgumentException("Invalid credential type");
        }
        return new TokenCredentialAuthProvider(
                singletonList(graphResource + ".default"),
                tokenCredential);
    }

    static ClientCertificateCredential getClientCertificateCredential(GraphClientCacheKey key) {
        return new ClientCertificateCredentialBuilder()
                .clientId(key.clientId())
                .pemCertificate(getCertificate(key))
                .tenantId(key.tenantId())
                .sendCertificateChain(true)
                .authorityHost(getAuthorityHost(key.azureEnvironmentName()))
                .httpClient(HttpClientRetriever.get())
                .build();
    }

    static ClientSecretCredential getClientSecretCredential(GraphClientCacheKey key) {
        return new ClientSecretCredentialBuilder()
                .clientId(key.clientId())
                .clientSecret(key.clientSecret())
                .tenantId(key.tenantId())
                .authorityHost(getAuthorityHost(key.azureEnvironmentName()))
                .httpClient(HttpClientRetriever.get())
                .build();
    }

    static InputStream getCertificate(GraphClientCacheKey key) {

        String secretString = key.clientCertificate();
        return new ByteArrayInputStream(secretString.getBytes(StandardCharsets.UTF_8));
    }

    static GraphServiceClient<Request> getClient(GraphClientCacheKey key) {
        return TOKEN_CACHE.get(key);
    }

    public static GraphServiceClient<Request> getClient(AzureSecurityRealm azureSecurityRealm) {
        GraphClientCacheKey key = new GraphClientCacheKey(
                azureSecurityRealm.getClientId(),
                Secret.toString(azureSecurityRealm.getClientSecret()),
                Secret.toString(azureSecurityRealm.getClientCertificate()),
                azureSecurityRealm.getCredentialType(),
                azureSecurityRealm.getTenant(),
                azureSecurityRealm.getAzureEnvironmentName(),
                proxyConfigurationFingerprint()
        );

        return TOKEN_CACHE.get(key);
    }

    /**
     * Identifies the parts of the Jenkins proxy configuration that clients are built with, so
     * cached clients can be replaced when the proxy configuration changes.
     */
    static String proxyConfigurationFingerprint() {
        if (JenkinsJVM.isJenkinsJVM()) {
            ProxyConfiguration proxy = Jenkins.get().getProxy();
            if (proxy != null) {
                // digest so the password is not retained as plain text
                return Util.getDigestOf(String.join("|",
                        String.valueOf(proxy.getName()),
                        String.valueOf(proxy.getPort()),
                        String.valueOf(proxy.getNoProxyHost()),
                        String.valueOf(proxy.getUserName()),
                        Secret.toString(proxy.getSecretPassword())));
            }
        }
        return "";
    }

    /**
     * @param targetUrl the full URL (including scheme) of the service the client will talk to,
     *                  used to evaluate the proxy exclusion list
     */
    public static OkHttpClient.Builder addProxyToHttpClientIfRequired(OkHttpClient.Builder builder, String targetUrl) {
        if (JenkinsJVM.isJenkinsJVM()) {
            ProxyConfiguration proxyConfiguration = Jenkins.get().getProxy();
            if (proxyConfiguration != null && StringUtils.isNotBlank(proxyConfiguration.getName())) {

                String targetHost = URI.create(targetUrl).getHost();
                Proxy proxy = proxyConfiguration.createProxy(targetHost);

                builder = builder.proxy(proxy);
                if (StringUtils.isNotBlank(proxyConfiguration.getUserName())) {
                    builder = builder.proxyAuthenticator((route, response) -> {
                        String credential = Credentials.basic(
                                proxyConfiguration.getUserName(),
                                proxyConfiguration.getSecretPassword().getPlainText()
                        );
                        return response.request().newBuilder().header("Authorization", credential).build();
                    });
                }
            }
        }

        return builder;
    }
}
