package com.microsoft.jenkins.azuread;

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
import jenkins.model.Jenkins;
import jenkins.util.JenkinsJVM;
import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.apache.commons.lang3.StringUtils;

import java.net.Proxy;

import static com.microsoft.jenkins.azuread.AzureEnvironment.AZURE_PUBLIC_CLOUD;
import static com.microsoft.jenkins.azuread.AzureEnvironment.getAuthorityHost;
import static com.microsoft.jenkins.azuread.AzureEnvironment.getServiceRoot;

public class GraphClientCache {

    private static final int TEN = 10;
    private static final LoadingCache<GraphClientCacheKey, GraphServiceClient<Request>> TOKEN_CACHE = Caffeine.newBuilder()
            .maximumSize(TEN)
            .build(GraphClientCache::createGraphClient);

    private static GraphServiceClient<Request> createGraphClient(GraphClientCacheKey key) {

        TokenCredentialAuthProvider authProvider;
        
        if (key.useClientCertificate()) {
            ClientCertificateCredential clientCertificateCredential = getClientCertificateCredential(key);
            authProvider = new TokenCredentialAuthProvider(clientCertificateCredential);
        } else {
            ClientSecretCredential clientSecretCredential = getClientSecretCredential(key);
            authProvider = new TokenCredentialAuthProvider(clientSecretCredential);
        }

        OkHttpClient.Builder builder = HttpClients.createDefault(authProvider)
                .newBuilder();

        builder = addProxyToHttpClientIfRequired(builder);
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

    static ClientCertificateCredential getClientCertificateCredential(GraphClientCacheKey key) {
        return new ClientCertificateCredentialBuilder()
                .clientId(key.getClientId())
                .pemCertificate(key.pemCertificate())
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

    static GraphServiceClient<Request> getClient(GraphClientCacheKey key) {
        return TOKEN_CACHE.get(key);
    }

    public static GraphServiceClient<Request> getClient(AzureSecurityRealm azureSecurityRealm) {
        GraphClientCacheKey key = new GraphClientCacheKey(
                azureSecurityRealm.getClientId(),
                Secret.toString(azureSecurityRealm.getClientSecret()),
                azureSecurityRealm.getTenant(),
                azureSecurityRealm.getAzureEnvironmentName(),
                azureSecurityRealm.useClientCertificate()
        );

        return TOKEN_CACHE.get(key);
    }

    public static OkHttpClient.Builder addProxyToHttpClientIfRequired(OkHttpClient.Builder builder) {
        if (JenkinsJVM.isJenkinsJVM()) {
            ProxyConfiguration proxyConfiguration = Jenkins.get().getProxy();
            if (proxyConfiguration != null && StringUtils.isNotBlank(proxyConfiguration.getName())) {
                Proxy proxy = proxyConfiguration.createProxy("graph.microsoft.com");

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
