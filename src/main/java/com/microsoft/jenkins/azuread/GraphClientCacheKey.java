package com.microsoft.jenkins.azuread;

import java.util.Objects;

public class GraphClientCacheKey {
    private final String clientId;
    private final String clientSecret;
    private final String clientCertificate;
    private final String tenantId;
    private final String azureEnvironmentName;
    private final String credentialType;

    public GraphClientCacheKey(String clientId, String clientSecret, String clientCertificate, String tenantId, String azureEnvironmentName, String credentialType) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.clientCertificate = clientCertificate;
        this.tenantId = tenantId;
        this.azureEnvironmentName = azureEnvironmentName;
        this.credentialType = credentialType;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GraphClientCacheKey that = (GraphClientCacheKey) o;
        return  Objects.equals(clientId, that.clientId) &&
                Objects.equals(clientSecret, that.clientSecret) &&
                Objects.equals(clientCertificate, that.clientCertificate) &&
                Objects.equals(credentialType, that.credentialType) &&
                Objects.equals(tenantId, that.tenantId) &&
                Objects.equals(azureEnvironmentName, that.azureEnvironmentName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, clientSecret, clientCertificate, credentialType, tenantId, azureEnvironmentName);
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getClientCertificate() {
        return clientCertificate;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getAzureEnvironmentName() {
        return azureEnvironmentName;
    }

    public String getCredentialType() {
        return credentialType;
    }
}
