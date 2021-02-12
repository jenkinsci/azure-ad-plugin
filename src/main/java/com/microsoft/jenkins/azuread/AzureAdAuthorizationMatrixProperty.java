package com.microsoft.jenkins.azuread;

import hudson.Extension;
import hudson.model.AutoCompletionCandidates;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.JobPropertyDescriptor;
import hudson.security.AuthorizationMatrixProperty;
import hudson.security.Permission;
import hudson.security.PermissionScope;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.matrixauth.AbstractAuthorizationPropertyConverter;
import org.jenkinsci.plugins.matrixauth.AuthorizationProperty;
import org.jenkinsci.plugins.matrixauth.AuthorizationPropertyDescriptor;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.verb.GET;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AzureAdAuthorizationMatrixProperty extends AuthorizationMatrixProperty {

    private final transient ObjId2FullSidMap objId2FullSidMap = new ObjId2FullSidMap();

    public AzureAdAuthorizationMatrixProperty() {
        super(Collections.emptyList());
    }

    public AzureAdAuthorizationMatrixProperty(Map<Permission, Set<String>> grantedPermissions) {
        super(grantedPermissions);
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
        for (String fullSid : this.getAllSIDs()) {
            objId2FullSidMap.putFullSid(fullSid);
        }
        new AzureAdAuthorizationMatrixProperty();
    }

    @Override
    public void add(Permission p, String sid) {
        super.add(p, sid);
        objId2FullSidMap.putFullSid(sid);
    }

    @Override
    public boolean hasExplicitPermission(String sid, Permission p) {
        // Jenkins will pass in the object Id as sid
        final String objectId = sid;
        if (objectId == null) {
            return false;
        }
        return super.hasExplicitPermission(objId2FullSidMap.getOrOriginal(objectId), p);
    }

    @Override
    public boolean hasPermission(String sid, Permission p) {
        // Jenkins will pass in the object Id as sid
        final String objectId = sid;
        return super.hasPermission(objId2FullSidMap.getOrOriginal(objectId), p);
    }

    @Override
    public boolean hasPermission(String sid, Permission p, boolean principal) {
        // Jenkins will pass in the object Id as sid
        final String objectId = sid;
        return super.hasPermission(objId2FullSidMap.getOrOriginal(objectId), p, principal);
    }

    @Extension
    @Symbol("azureAdAuthorizationMatrix")
    @SuppressRestrictedWarnings(AuthorizationPropertyDescriptor.class)
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
            return Jenkins.getInstance().getAuthorizationStrategy() instanceof AzureAdMatrixAuthorizationStrategy;
        }

        @GET
        public FormValidation doCheckName(@AncestorInPath Job<?, ?> project, @QueryParameter String value) {
            return doCheckName_(value, project, Item.CONFIGURE);
        }

        @Nonnull
        @Override
        public String getDisplayName() {
            return "Azure Active Directory Authorization Matrix";
        }

        public AutoCompletionCandidates doAutoCompleteUserOrGroup(@QueryParameter String value) throws IOException {
            return AzureAdMatrixAuthorizationStrategy.searchAndGenerateCandidates(value);
        }
    }

    @SuppressRestrictedWarnings(AbstractAuthorizationPropertyConverter.class)
    public static class ConverterImpl extends AbstractAuthorizationPropertyConverter {

        @Override
        @SuppressWarnings("rawtypes")
        public boolean canConvert(Class type) {
            return type == AzureAdAuthorizationMatrixProperty.class;
        }

        @Override
        public AuthorizationProperty create() {
            return new AzureAdAuthorizationMatrixProperty();
        }

    }
}
