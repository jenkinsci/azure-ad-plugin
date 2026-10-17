package com.microsoft.jenkins.azuread;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Extension;
import hudson.model.AdministrativeMonitor;
import jenkins.model.Jenkins;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.verb.POST;

import java.io.IOException;

/**
 * Tells administrators that the Entra ID matrix-based authorization strategies are deprecated, and offers to
 * migrate their configuration to the Matrix Authorization Strategy plugin.
 */
@Extension
@Restricted(NoExternalUse.class)
public class EntraIdAuthorizationMigrationMonitor extends AdministrativeMonitor {

    private transient volatile EntraIdAuthorizationMigrator.Plan lastResult;

    @Override
    public String getDisplayName() {
        return Messages.EntraIdAuthorizationMigrationMonitor_DisplayName();
    }

    @Override
    public boolean isSecurity() {
        return true;
    }

    @Override
    public boolean isActivated() {
        return Jenkins.get().getAuthorizationStrategy() instanceof GlobalMatrixAuthorizationStrategy;
    }

    /**
     * Used by the view to preview the migration.
     */
    public EntraIdAuthorizationMigrator.Plan getPreview() {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return EntraIdAuthorizationMigrator.preview();
    }

    @CheckForNull
    public EntraIdAuthorizationMigrator.Plan getLastResult() {
        return lastResult;
    }

    @POST
    public HttpResponse doMigrate() throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        lastResult = EntraIdAuthorizationMigrator.migrate();
        return new HttpRedirect(".");
    }
}
