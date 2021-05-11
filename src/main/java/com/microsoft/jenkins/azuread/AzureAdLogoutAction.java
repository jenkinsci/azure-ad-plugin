package com.microsoft.jenkins.azuread;

import hudson.Extension;
import hudson.model.UnprotectedRootAction;

/**
 * A page that shows a simple message when the user logs out.
 * This prevents a logout - login loop when using this security realm and Anonymous does not have
 * {@code Overall.READ} permission.
 */
@Extension
public class AzureAdLogoutAction implements UnprotectedRootAction {

    /**
     * The URL of the action.
     */
    static final String POST_LOGOUT_URL = "azureAdLogout";

    @Override
    public String getDisplayName() {
        return Messages.AzureAdLogoutAction_DisplayName();
    }

    @Override
    public String getIconFileName() {
        // hide it
        return null;
    }

    @Override
    public String getUrlName() {
        return POST_LOGOUT_URL;
    }
}
