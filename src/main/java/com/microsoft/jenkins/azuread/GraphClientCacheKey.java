package com.microsoft.jenkins.azuread;

import java.util.Objects;

class GraphClientCacheKey {
        private final String clientId;
        private final String clientSecret;
        private final String tenantId;
        private final String azureEnvironmentName;

        public GraphClientCacheKey(String clientId, String clientSecret, String tenantId, String azureEnvironmentName) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.tenantId = tenantId;
            this.azureEnvironmentName = azureEnvironmentName;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            GraphClientCacheKey cacheKey = (GraphClientCacheKey) o;
            return Objects.equals(clientId, cacheKey.clientId) && Objects.equals(clientSecret, cacheKey.clientSecret) && Objects.equals(tenantId, cacheKey.tenantId) && Objects.equals(azureEnvironmentName, cacheKey.azureEnvironmentName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(clientId, clientSecret, tenantId, azureEnvironmentName);
        }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getAzureEnvironmentName() {
        return azureEnvironmentName;
    }
}