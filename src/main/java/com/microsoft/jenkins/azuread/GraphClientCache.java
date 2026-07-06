package com.microsoft.jenkins.azuread;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.ClientAssertionCredential;
import com.azure.identity.ClientAssertionCredentialBuilder;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.ClientCertificateCredential;
import com.azure.identity.ClientCertificateCredentialBuilder;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.microsoft.graph.core.authentication.AzureIdentityAuthenticationProvider;
import com.microsoft.graph.core.requests.GraphClientFactory;
import io.jenkins.plugins.microsoftgraph.GraphServiceClient;
import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.security.ACL;
import hudson.util.Secret;
import io.jenkins.plugins.azuresdk.HttpClientRetriever;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import jenkins.util.JenkinsJVM;
import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.net.Proxy;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.jenkinsci.plugins.plaincredentials.FileCredentials;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;

import static com.microsoft.jenkins.azuread.AzureEnvironment.AZURE_PUBLIC_CLOUD;
import static com.microsoft.jenkins.azuread.AzureEnvironment.getAuthorityHost;
import static com.microsoft.jenkins.azuread.AzureEnvironment.getGraphResource;
import static com.microsoft.jenkins.azuread.AzureEnvironment.getServiceRoot;

public class GraphClientCache {

    private static final Logger LOGGER =
            Logger.getLogger(GraphClientCache.class.getName());
    private static final int TEN = 10;
    private static final LoadingCache<GraphClientCacheKey, GraphServiceClient> TOKEN_CACHE = Caffeine.newBuilder()
            .maximumSize(TEN)
            .build(GraphClientCache::createGraphClient);

    private static GraphServiceClient createGraphClient(GraphClientCacheKey key) {
        LOGGER.log(Level.FINE,
                "createGraphClient: creating client for credentialType={0}, environment={1}",
                new Object[]{key.credentialType(), key.azureEnvironmentName()});
        AzureIdentityAuthenticationProvider authProvider = getAuthProvider(key);

        OkHttpClient.Builder builder = GraphClientFactory.create();

        String azureEnv = key.azureEnvironmentName();
        String targetUrl = getGraphResource(azureEnv);

        builder = addProxyToHttpClientIfRequired(builder, targetUrl);
        final OkHttpClient graphHttpClient = builder.build();

        GraphServiceClient graphServiceClient = new GraphServiceClient(authProvider, graphHttpClient);

        if (!azureEnv.equals(AZURE_PUBLIC_CLOUD)) {
            graphServiceClient.getRequestAdapter().setBaseUrl(getServiceRoot(azureEnv));
        }
        LOGGER.log(Level.FINE, "createGraphClient: client created successfully");
        return graphServiceClient;
    }

    private static AzureIdentityAuthenticationProvider getAuthProvider(GraphClientCacheKey key) {
        String graphResource = AzureEnvironment.getGraphResource(key.azureEnvironmentName());

        TokenCredential tokenCredential = switch (key.credentialType()) {
            case "Secret" -> getClientSecretCredential(key);
            case "Certificate" -> getClientCertificateCredential(key);
            case "WorkloadIdentity" -> getWorkloadIdentityCredential(key);
            default -> throw new IllegalArgumentException("Invalid credential type: " + key.credentialType());
        };
        return new AzureIdentityAuthenticationProvider(
                tokenCredential,
                new String[]{URI.create(graphResource).getHost()},
                graphResource + ".default");
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

     static ClientAssertionCredential getWorkloadIdentityCredential(GraphClientCacheKey key) {
        return new ClientAssertionCredentialBuilder()
                .clientId(key.clientId())
                .tenantId(key.tenantId())
                .clientAssertion(() -> getWorkloadIdentityToken(key.federatedCredentialsId()))
                .authorityHost(getAuthorityHost(key.azureEnvironmentName()))
                .httpClient(HttpClientRetriever.get())
                .build();
    }

    public static String getWorkloadIdentityToken(String federatedCredentialsId) {
        try {
            if (Util.fixEmpty(federatedCredentialsId) != null) {
                StandardCredentials creds = CredentialsProvider.findCredentialByIdInItemGroup(
                        federatedCredentialsId,
                        StandardCredentials.class,
                        null,
                        ACL.SYSTEM2,
                        null);

                switch (creds) {
                    case null -> throw new IOException("No credentials found for id: " + federatedCredentialsId);
                    case StringCredentials stringCreds -> {
                        return stringCreds.getSecret().getPlainText();
                    }
                    case FileCredentials fileCreds -> {
                        try (var is = fileCreds.getContent()) {
                            return IOUtils.toString(is, StandardCharsets.UTF_8).trim();
                        }
                    }
                    default -> throw new IOException("Unsupported credentials type: " + creds.getClass().getName());
                }

            } else {
                String tokenFile = System.getenv("AZURE_FEDERATED_TOKEN_FILE");
                if (Util.fixEmpty(tokenFile) == null) {
                    throw new IOException("AZURE_FEDERATED_TOKEN_FILE environment variable is not set or empty.");
                }
                return Files.readString(Path.of(tokenFile), StandardCharsets.UTF_8).trim();
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read federated token for Workload Identity authentication", e);
        }
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

    static GraphServiceClient getClient(GraphClientCacheKey key) {
        return TOKEN_CACHE.get(key);
    }

    public static GraphServiceClient getClient(AzureSecurityRealm azureSecurityRealm) {
        return TOKEN_CACHE.get(azureSecurityRealm.getGraphClientCacheKey());
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
