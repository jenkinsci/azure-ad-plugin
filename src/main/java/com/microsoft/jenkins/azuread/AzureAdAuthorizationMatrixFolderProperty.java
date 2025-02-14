package com.microsoft.jenkins.azuread;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.AbstractFolderPropertyDescriptor;
import com.microsoft.jenkins.azuread.folder.properties.AuthorizationMatrixProperty;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.AutoCompletionCandidates;
import hudson.model.Item;
import hudson.security.Permission;
import hudson.security.PermissionScope;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.verb.GET;

import java.util.List;

public class AzureAdAuthorizationMatrixFolderProperty extends AuthorizationMatrixProperty {

    private final transient ObjId2FullSidMap objId2FullSidMap = new ObjId2FullSidMap();

    protected AzureAdAuthorizationMatrixFolderProperty() {
    }

    @DataBoundConstructor
    @Restricted(NoExternalUse.class)
    public AzureAdAuthorizationMatrixFolderProperty(List<DslEntry> entries) {
        setEntries(entries);
    }

    @Override
    public void add(Permission permission, PermissionEntry entry) {
        super.add(permission, entry);
        objId2FullSidMap.putFullSid(entry.getSid());
    }

    @Override
    public boolean hasExplicitPermission(PermissionEntry entry, Permission p) {
        // Jenkins will pass in the object Id as sid
        final String objectId = entry.getSid();
        if (objectId == null) {
            return false;
        }
        String fullSid = objId2FullSidMap.getOrOriginal(objectId);
        return super.hasExplicitPermission(new PermissionEntry(entry.getType(), fullSid), p);
    }

    @Override
    public boolean hasPermission(String sid, Permission p, boolean principal) {
        // Jenkins will pass in the object Id as sid
        String fullSid = objId2FullSidMap.getOrOriginal(sid);
        return super.hasPermission(fullSid, p, principal);
    }

    @Extension(optional = true)
    @Symbol("azureAdAuthorizationMatrix")
    public static class DescriptorImpl extends AbstractFolderPropertyDescriptor implements
            AuthorizationPropertyDescriptor<AzureAdAuthorizationMatrixFolderProperty> {

        @Override
        public AzureAdAuthorizationMatrixFolderProperty create() {
            return new AzureAdAuthorizationMatrixFolderProperty();
        }

        @Override
        public PermissionScope getPermissionScope() {
            return PermissionScope.ITEM_GROUP;
        }

        @Override
        public AuthorizationMatrixProperty newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            return createNewInstance(req, formData, true);
        }

        @Override
        public boolean isApplicable() {
            return Jenkins.get().getAuthorizationStrategy() instanceof AzureAdMatrixAuthorizationStrategy;
        }

        @GET
        public FormValidation doCheckName(@AncestorInPath AbstractFolder<?> folder, @QueryParameter String value) {
            if (isDisableGraphIntegration()) {
                return Utils.undecidableResponse(value);
            }

            return doCheckName_(value, folder, Item.CONFIGURE);
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

        @Override
        @NonNull
        public String getDisplayName() {
            return "Azure Active Directory Authorization Matrix";
        }

        @SuppressWarnings("unused")
        public AutoCompletionCandidates doAutoCompleteUserOrGroup(@QueryParameter String value) {
            return AzureAdMatrixAuthorizationStrategy.searchAndGenerateCandidates(value);
        }
    }

    @SuppressWarnings("unused")
    public static class ConverterImpl extends AbstractAuthorizationPropertyConverter<AzureAdAuthorizationMatrixFolderProperty> {

        @Override
        public boolean canConvert(Class type) {
            return type == AzureAdAuthorizationMatrixFolderProperty.class;
        }

        @Override
        public AzureAdAuthorizationMatrixFolderProperty create() {
            return new AzureAdAuthorizationMatrixFolderProperty();
        }
    }
}
