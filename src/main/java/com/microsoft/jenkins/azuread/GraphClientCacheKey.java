package com.microsoft.jenkins.azuread;

import java.util.Objects;

public class GraphClientCacheKey {
    private final String clientId;
    private final String clientSecret;
    private final String pemCertificate;
    private final String tenantId;
    private final String azureEnvironmentName;
    private final boolean enableClientCertificateAuth;

    public GraphClientCacheKey(String clientId, String clientSecret, String pemCertificate, String tenantId, String azureEnvironmentName, boolean enableClientCertificateAuth) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.pemCertificate = pemCertificate;
        this.tenantId = tenantId;
        this.azureEnvironmentName = azureEnvironmentName;
        this.enableClientCertificateAuth = enableClientCertificateAuth;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GraphClientCacheKey that = (GraphClientCacheKey) o;
        return enableClientCertificateAuth == that.enableClientCertificateAuth &&
                Objects.equals(clientId, that.clientId) &&
                Objects.equals(clientSecret, that.clientSecret) &&
                Objects.equals(pemCertificate, that.pemCertificate) &&
                Objects.equals(tenantId, that.tenantId) &&
                Objects.equals(azureEnvironmentName, that.azureEnvironmentName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, clientSecret, pemCertificate, tenantId, azureEnvironmentName, enableClientCertificateAuth);
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getPemCertificate() {
        return pemCertificate;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getAzureEnvironmentName() {
        return azureEnvironmentName;
    }

    public boolean isEnableClientCertificateAuth() {
        return enableClientCertificateAuth;
    }
}
