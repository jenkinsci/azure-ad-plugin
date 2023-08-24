package com.microsoft.jenkins.azuread;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.JobPropertyDescriptor;
import hudson.security.Permission;
import hudson.security.PermissionScope;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritGlobalStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.verb.GET;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AzureAdAuthorizationMatrixProperty extends AuthorizationMatrixProperty {

    private final transient ObjId2FullSidMap objId2FullSidMap = new ObjId2FullSidMap();

    public AzureAdAuthorizationMatrixProperty() {
        super(Collections.emptyList());
    }

    public AzureAdAuthorizationMatrixProperty(
            Map<Permission, Set<PermissionEntry>> grantedPermissions,
            InheritanceStrategy inheritanceStrategy
    ) {
        super(grantedPermissions, new InheritGlobalStrategy());
        refreshMap();
    }

    @DataBoundConstructor
    @Restricted(NoExternalUse.class)
    public AzureAdAuthorizationMatrixProperty(List<String> permissions) {
        this();
        for (String permission : permissions) {
            add(permission);
        }
    }

    void refreshMap() {
        for (PermissionEntry entry : this.getAllPermissionEntries()) {
            objId2FullSidMap.putFullSid(entry.getSid());
        }
        new AzureAdAuthorizationMatrixProperty();
    }

    @Override
    public void add(Permission p, PermissionEntry entry) {
        super.add(p, entry);
        objId2FullSidMap.putFullSid(entry.getSid());
    }

    @Override
    public boolean hasExplicitPermission(PermissionEntry entry, Permission p) {
        // Jenkins will pass in the object Id as sid
        final String objectId = entry.getSid();
        if (objectId == null) {
            return false;
        }

        PermissionEntry entry1 = new PermissionEntry(entry.getType(), objId2FullSidMap.getOrOriginal(objectId));
        return super.hasExplicitPermission(entry1, p);
    }

    @Override
    public boolean hasPermission(String sid, Permission p, boolean principal) {
        // Jenkins will pass in the object Id as sid
        return super.hasPermission(objId2FullSidMap.getOrOriginal(sid), p, principal);
    }

    @Extension
    @Symbol("azureAdAuthorizationMatrix")
    public static class DescriptorImpl extends JobPropertyDescriptor implements
            AuthorizationPropertyDescriptor<AzureAdAuthorizationMatrixProperty> {

        @Override
        public AzureAdAuthorizationMatrixProperty create() {
            return new AzureAdAuthorizationMatrixProperty();
        }

        @Override
        public PermissionScope getPermissionScope() {
            return PermissionScope.ITEM;
        }

        @Override
        public JobProperty<?> newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            return createNewInstance(req, formData, true);
        }

        @Override
        public boolean isApplicable() {
            return Jenkins.get().getAuthorizationStrategy() instanceof AzureAdMatrixAuthorizationStrategy;
        }

        @GET
        public FormValidation doCheckName(@AncestorInPath Job<?, ?> project, @QueryParameter String value) {
            if (isDisableGraphIntegration()) {
                return Utils.undecidableResponse(value);
            }

            return doCheckName_(value, project, Item.CONFIGURE);
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "Azure Active Directory Authorization Matrix";
        }

        @SuppressWarnings("unused") // called by jelly
        public boolean isDisableGraphIntegration() {
            SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
            if (securityRealm instanceof AzureSecurityRealm) {
                AzureSecurityRealm azureSecurityRealm = (AzureSecurityRealm) securityRealm;
                return azureSecurityRealm.isDisableGraphIntegration();
            }

            return true;
        }
    }

    public static class ConverterImpl extends AbstractAuthorizationPropertyConverter {

        @Override
        public boolean canConvert(Class type) {
            return type == AzureAdAuthorizationMatrixProperty.class;
        }

        @Override
        public AuthorizationProperty create() {
            return new AzureAdAuthorizationMatrixProperty();
        }

    }
}
