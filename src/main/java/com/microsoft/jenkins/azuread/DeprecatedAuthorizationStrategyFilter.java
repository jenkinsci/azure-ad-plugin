package com.microsoft.jenkins.azuread;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.DescriptorVisibilityFilter;
import jenkins.model.Jenkins;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Hides the deprecated Entra ID authorization strategies from the security configuration unless they are in use.
 */
@Extension
@Restricted(NoExternalUse.class)
public class DeprecatedAuthorizationStrategyFilter extends DescriptorVisibilityFilter {

    @Override
    public boolean filter(Object context, @NonNull Descriptor descriptor) {
        if (descriptor.clazz == AzureAdMatrixAuthorizationStrategy.class
                || descriptor.clazz == GlobalMatrixAuthorizationStrategy.class) {
            return Jenkins.get().getAuthorizationStrategy().getClass() == descriptor.clazz;
        }
        return true;
    }
}
