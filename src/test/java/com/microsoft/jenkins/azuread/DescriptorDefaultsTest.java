/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests for DescriptorImpl environment variable default methods.
 *
 * <p>These tests verify the getter methods return non-null values
 * (empty string when env var is not set). The actual env var-populated
 * behavior is validated via manual testing with {@code mvn hpi:run}
 * since env vars cannot be reliably set in JUnit tests.</p>
 */
@WithJenkins
class DescriptorDefaultsTest {

    @Test
    @DisplayName("getDefaultClientId returns non-null (empty when env var unset)")
    void testGetDefaultClientIdReturnsNonNull() {
        AzureSecurityRealm.DescriptorImpl descriptor = new AzureSecurityRealm.DescriptorImpl();
        String result = descriptor.getDefaultClientId();
        assertNotNull(result, "getDefaultClientId should never return null");
        // When AZURE_CLIENT_ID is not set, should return empty string
        if (System.getenv("AZURE_CLIENT_ID") == null) {
            assertEquals("", result);
        } else {
            assertEquals(System.getenv("AZURE_CLIENT_ID"), result);
        }
    }

    @Test
    @DisplayName("getDefaultTenant returns non-null (empty when env var unset)")
    void testGetDefaultTenantReturnsNonNull() {
        AzureSecurityRealm.DescriptorImpl descriptor = new AzureSecurityRealm.DescriptorImpl();
        String result = descriptor.getDefaultTenant();
        assertNotNull(result, "getDefaultTenant should never return null");
        if (System.getenv("AZURE_TENANT_ID") == null) {
            assertEquals("", result);
        } else {
            assertEquals(System.getenv("AZURE_TENANT_ID"), result);
        }
    }

    @Test
    @DisplayName("getDefaultCredentialType returns Secret when no env vars set")
    void testGetDefaultCredentialTypeReturnsSecret() {
        AzureSecurityRealm.DescriptorImpl descriptor = new AzureSecurityRealm.DescriptorImpl();
        String result = descriptor.getDefaultCredentialType();
        assertNotNull(result, "getDefaultCredentialType should never return null");
        if (System.getenv("AZURE_FEDERATED_TOKEN_FILE") == null) {
            assertEquals("Secret", result,
                    "Should default to Secret when AZURE_FEDERATED_TOKEN_FILE is not set");
        } else {
            assertEquals("WorkloadIdentity", result,
                    "Should default to WorkloadIdentity when AZURE_FEDERATED_TOKEN_FILE is set");
        }
    }

    @Test
    @DisplayName("getDefaultCredentialType returns valid credential type value")
    void testGetDefaultCredentialTypeReturnsValidValue() {
        AzureSecurityRealm.DescriptorImpl descriptor = new AzureSecurityRealm.DescriptorImpl();
        String result = descriptor.getDefaultCredentialType();
        assertTrue(result.equals("Secret") || result.equals("Certificate") || result.equals("WorkloadIdentity"),
                "Should return a valid credential type, got: " + result);
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
