package com.microsoft.jenkins.azuread;

record GraphClientCacheKey(
        String clientId,
        String clientSecret,
        String clientCertificate,
        String credentialType,
        String tenantId,
        String azureEnvironmentName,
        String proxyFingerprint,
        String federatedCredentialsId) {
}
