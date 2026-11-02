package com.microsoft.jenkins.azuread;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;

/**
 * Marks a Jenkins user record as originating from Entra ID.
 *
 * <p>Written on every successful authentication, so the absence of this property
 * identifies an account that already existed when the realm was switched.
 * {@link AzureSecurityRealm} uses that distinction to decide whether a lookup
 * that Entra ID cannot resolve may keep API-token impersonation alive.
 */
public class EntraIdentityProperty extends UserProperty {

    private final String objectId;

    public EntraIdentityProperty(String objectId) {
        this.objectId = objectId;
    }

    public String getObjectId() {
        return objectId;
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @Override
        @NonNull
        public String getDisplayName() {
            return "Entra ID identity";
        }

        /**
         * The property records what the realm observed during login; there is
         * nothing for a user or an administrator to configure.
         */
        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public UserProperty newInstance(User user) {
            return null;
        }
    }
}
