package com.microsoft.jenkins.azuread;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.AbstractFolderPropertyDescriptor;
import com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty;
import hudson.Extension;
import hudson.model.AutoCompletionCandidates;
import hudson.model.Item;
import hudson.security.Permission;
import hudson.security.PermissionScope;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.matrixauth.AbstractAuthorizationPropertyConverter;
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
import java.util.List;

public class AzureAdAuthorizationMatrixFolderProperty extends AuthorizationMatrixProperty {

    private final transient ObjId2FullSidMap objId2FullSidMap = new ObjId2FullSidMap();

    protected AzureAdAuthorizationMatrixFolderProperty() {
    }

    @DataBoundConstructor
    @Restricted(NoExternalUse.class)
    public AzureAdAuthorizationMatrixFolderProperty(List<String> permissions) {
        for (String permission : permissions) {
            add(permission);
        }
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

    @Extension(optional = true)
    @Symbol("azureAdAuthorizationMatrix")
    @SuppressRestrictedWarnings(AuthorizationPropertyDescriptor.class)
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
            return doCheckName_(value, folder, Item.CONFIGURE);
        }

        @Override
        @Nonnull
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
            return type == AzureAdAuthorizationMatrixFolderProperty.class;
        }

        @Override
        public AzureAdAuthorizationMatrixFolderProperty create() {
            return new AzureAdAuthorizationMatrixFolderProperty();
        }
    }
}
