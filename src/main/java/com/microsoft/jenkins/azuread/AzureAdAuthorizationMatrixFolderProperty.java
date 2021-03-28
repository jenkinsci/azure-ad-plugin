package com.microsoft.jenkins.azuread;

import com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty;
import hudson.Extension;
import hudson.model.AutoCompletionCandidates;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.AbstractAuthorizationPropertyConverter;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.Nonnull;
import java.io.IOException;

public class AzureAdAuthorizationMatrixFolderProperty extends AuthorizationMatrixProperty {

    private final transient ObjId2FullSidMap objId2FullSidMap = new ObjId2FullSidMap();

    protected AzureAdAuthorizationMatrixFolderProperty() {
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
    public static class DescriptorImpl extends AuthorizationMatrixProperty.DescriptorImpl {

        @Override
        public AuthorizationMatrixProperty create() {
            return new AzureAdAuthorizationMatrixFolderProperty();
        }

        @Override
        public boolean isApplicable() {
            return Jenkins.get().getAuthorizationStrategy() instanceof AzureAdMatrixAuthorizationStrategy;
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
