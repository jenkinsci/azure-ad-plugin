package com.microsoft.jenkins.azuread.integrations.casc;

import com.microsoft.jenkins.azuread.AzureAdMatrixAuthorizationStrategy;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.model.CNode;
import io.jenkins.plugins.casc.model.Mapping;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Extension(optional = true, ordinal = 2)
@Restricted(NoExternalUse.class)
public class AzureAdMatrixAuthorizationStrategyConfigurator
        extends MatrixAuthorizationStrategyConfigurator<AzureAdMatrixAuthorizationStrategy> {

    @Override
    @NonNull
    public String getName() {
        return "azureAdMatrix";
    }

    @Override
    public Class<AzureAdMatrixAuthorizationStrategy> getTarget() {
        return AzureAdMatrixAuthorizationStrategy.class;
    }

    @Override
    public AzureAdMatrixAuthorizationStrategy instance(Mapping mapping, ConfigurationContext context) {
        return new AzureAdMatrixAuthorizationStrategy();
    }

    @CheckForNull
    @Override
    public CNode describe(AzureAdMatrixAuthorizationStrategy instance, ConfigurationContext context) throws Exception {
        return compare(instance, new AzureAdMatrixAuthorizationStrategy(), context);
    }
}
