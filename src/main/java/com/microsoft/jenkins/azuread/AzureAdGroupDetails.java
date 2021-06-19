package com.microsoft.jenkins.azuread;

import hudson.security.GroupDetails;

public class AzureAdGroupDetails extends GroupDetails {

    private final String id;
    private final String displayName;

    public AzureAdGroupDetails(String id, String displayName) {
        this.id = id;
        this.displayName = displayName;
    }

    @Override
    public String getName() {
        return id;
    }

    @Override
    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return String.format("%s (%s)", displayName, id);
    }
}
