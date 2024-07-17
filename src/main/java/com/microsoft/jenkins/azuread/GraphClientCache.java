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
import hudson.util.Secret;
import io.jenkins.plugins.azuresdk.HttpClientRetriever;
import java.net.URI;
import java.util.Collections;
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

        builder = addProxyToHttpClientIfRequired(builder, key.getAzureEnvironmentName());
        final OkHttpClient graphHttpClient = builder.build();

        GraphServiceClient<Request> graphServiceClient = GraphServiceClient
                .builder()
                .httpClient(graphHttpClient)
                .buildClient();

        String azureEnv = key.getAzureEnvironmentName();

        if (!azureEnv.equals(AZURE_PUBLIC_CLOUD)) {
            graphServiceClient.setServiceRoot(getServiceRoot(azureEnv));
        }
        return graphServiceClient;
    }

    private static TokenCredentialAuthProvider getAuthProvider(GraphClientCacheKey key) {
        String graphResource = AzureEnvironment.getGraphResource(key.getAzureEnvironmentName());

        TokenCredential tokenCredential;
        if ("Secret".equals(key.getCredentialType())) {
            tokenCredential = getClientSecretCredential(key);
        } else if ("Certificate".equals(key.getCredentialType())) {
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
                .clientId(key.getClientId())
                .pemCertificate(getCertificate(key))
                .tenantId(key.getTenantId())
                .sendCertificateChain(true)
                .authorityHost(getAuthorityHost(key.getAzureEnvironmentName()))
                .httpClient(HttpClientRetriever.get())
                .build();
    }

    static ClientSecretCredential getClientSecretCredential(GraphClientCacheKey key) {
        return new ClientSecretCredentialBuilder()
                .clientId(key.getClientId())
                .clientSecret(key.getClientSecret())
                .tenantId(key.getTenantId())
                .authorityHost(getAuthorityHost(key.getAzureEnvironmentName()))
                .httpClient(HttpClientRetriever.get())
                .build();
    }

    static InputStream getCertificate(GraphClientCacheKey key) {

        String secretString = key.getClientCertificate();
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
                azureSecurityRealm.getAzureEnvironmentName()
        );

        return TOKEN_CACHE.get(key);
    }

    public static OkHttpClient.Builder addProxyToHttpClientIfRequired(OkHttpClient.Builder builder, String azureEnvironmentName) {
        if (JenkinsJVM.isJenkinsJVM()) {
            ProxyConfiguration proxyConfiguration = Jenkins.get().getProxy();
            if (proxyConfiguration != null && StringUtils.isNotBlank(proxyConfiguration.getName())) {

                String graphHost = URI.create(getGraphResource(azureEnvironmentName)).getHost();
                Proxy proxy = proxyConfiguration.createProxy(graphHost);

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