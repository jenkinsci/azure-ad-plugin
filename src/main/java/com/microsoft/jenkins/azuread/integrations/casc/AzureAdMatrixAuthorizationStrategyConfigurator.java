package com.microsoft.jenkins.azuread.integrations.casc;

import com.microsoft.jenkins.azuread.AzureAdMatrixAuthorizationStrategy;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import io.jenkins.plugins.casc.Attribute;
import io.jenkins.plugins.casc.BaseConfigurator;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.impl.attributes.MultivaluedAttribute;
import io.jenkins.plugins.casc.model.CNode;
import io.jenkins.plugins.casc.model.Mapping;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainer;
import org.jenkinsci.plugins.matrixauth.integrations.PermissionFinder;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Extension(optional = true)
@Restricted(NoExternalUse.class)
public class AzureAdMatrixAuthorizationStrategyConfigurator extends
        BaseConfigurator<AzureAdMatrixAuthorizationStrategy> {
    @NonNull
    @Override
    public String getName() {
        return "azureAdMatrix";
    }

    @Override
    public Class<AzureAdMatrixAuthorizationStrategy> getTarget() {
        return AzureAdMatrixAuthorizationStrategy.class;
    }

    @NonNull
    @Override
    public Class getImplementedAPI() {
        return AuthorizationStrategy.class;
    }

    @Override
    @NonNull
    public Set<Attribute<AzureAdMatrixAuthorizationStrategy, ?>> describe() {
        return new HashSet<>(Collections.singletonList(
                new MultivaluedAttribute<AzureAdMatrixAuthorizationStrategy, String>("permissions", String.class)
                        .getter(AzureAdMatrixAuthorizationStrategyConfigurator::getPermissions)
                        .setter(AzureAdMatrixAuthorizationStrategyConfigurator::setPermissions)
        ));
    }

    @Override
    protected AzureAdMatrixAuthorizationStrategy instance(Mapping mapping, ConfigurationContext context) {
        return new AzureAdMatrixAuthorizationStrategy();
    }

    @Override
    public CNode describe(AzureAdMatrixAuthorizationStrategy instance, ConfigurationContext context) throws Exception {
        return compare(instance, new AzureAdMatrixAuthorizationStrategy(), context);
    }

    /**
     * Extract container's permissions as a List of "PERMISSION:sid".
     */
    public static Collection<String> getPermissions(AuthorizationContainer container) {
        return container.getGrantedPermissions().entrySet().stream()
                .flatMap(e -> e.getValue().stream()
                        .map(v -> e.getKey().group.getId() + "/" + e.getKey().name + ":" + v))
                .collect(Collectors.toList());
    }

    /**
     * Configure container's permissions from a List of "PERMISSION:sid".
     */
    public static void setPermissions(AuthorizationContainer container, Collection<String> permissions) {
        permissions.forEach(p -> {
            final int i = p.indexOf(':');
            final Permission permission = PermissionFinder.findPermission(p.substring(0, i));
            if (permission == null) {
                throw new IllegalStateException(String.format("Cannot find permission for %s.", p));
            }
            container.add(permission, p.substring(i + 1));
        });
    }
}
