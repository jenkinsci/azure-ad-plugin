package com.microsoft.jenkins.azuread;

import hudson.Extension;
import hudson.model.AutoCompletionCandidates;
import hudson.security.AuthorizationMatrixProperty;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.AbstractAuthorizationPropertyConverter;
import org.jenkinsci.plugins.matrixauth.AuthorizationProperty;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.Collections;
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
    public static class DescriptorImpl extends AuthorizationMatrixProperty.DescriptorImpl {

        @Override
        public AuthorizationMatrixProperty create() {
            return new AzureAdAuthorizationMatrixProperty();
        }

        @Override
        public boolean isApplicable() {
            return Jenkins.getInstance().getAuthorizationStrategy() instanceof AzureAdMatrixAuthorizationStrategy;
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
