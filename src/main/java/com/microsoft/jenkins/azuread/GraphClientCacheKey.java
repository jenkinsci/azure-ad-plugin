package com.microsoft.jenkins.azuread;

import java.util.Objects;

class GraphClientCacheKey {
    private final String clientId;
    private final String clientSecret;
    private final String pemCertificate;
    private final String tenantId;
    private final String azureEnvironmentName;
    private final boolean isEnableClientCertificate;

    public GraphClientCacheKey(String clientId, String clientSecret, String pemCertificate, String tenantId, String azureEnvironmentName, boolean isEnableClientCertificate) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.pemCertificate = pemCertificate;
        this.tenantId = tenantId;
        this.azureEnvironmentName = azureEnvironmentName;
        this.isEnableClientCertificate = isEnableClientCertificate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GraphClientCacheKey cacheKey = (GraphClientCacheKey) o;
        return isEnableClientCertificate == cacheKey.isEnableClientCertificate &&
                Objects.equals(clientId, cacheKey.clientId) &&
                Objects.equals(clientSecret, cacheKey.clientSecret) &&
                Objects.equals(pemCertificate, cacheKey.pemCertificate) &&
                Objects.equals(tenantId, cacheKey.tenantId) &&
                Objects.equals(azureEnvironmentName, cacheKey.azureEnvironmentName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, clientSecret, pemCertificate, tenantId, azureEnvironmentName, isEnableClientCertificate);
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

    public boolean isEnableClientCertificate() {
        return isEnableClientCertificate;
    }
}
