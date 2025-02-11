package com.microsoft.jenkins.azuread;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Computer;
import hudson.model.Node;
import hudson.model.User;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.PermissionScope;
import hudson.security.SecurityRealm;
import hudson.slaves.NodePropertyDescriptor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.model.NodeListener;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest2;

import java.io.IOException;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AzureAdAuthorizationMatrixNodeProperty extends AuthorizationMatrixNodeProperty {

    private final transient ObjId2FullSidMap objId2FullSidMap = new ObjId2FullSidMap();

    public AzureAdAuthorizationMatrixNodeProperty() {
        super(Collections.emptyMap());
    }

    void refreshMap() {
        for (PermissionEntry entry : this.getAllPermissionEntries()) {
            objId2FullSidMap.putFullSid(entry.getSid());
        }
        new AzureAdAuthorizationMatrixNodeProperty();
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
        return super.hasPermission(objId2FullSidMap.getOrOriginal(sid), p, principal);
    }

    /**
     * Persist {@link AzureAdAuthorizationMatrixNodeProperty} as a list of IDs that
     * represent {@link AzureAdAuthorizationMatrixNodeProperty#getGrantedPermissionEntries()}.
     */
    @SuppressWarnings("unused")
    @Restricted(NoExternalUse.class)
    public static final class ConverterImpl extends
            AbstractAuthorizationPropertyConverter<AzureAdAuthorizationMatrixNodeProperty> {
        public boolean canConvert(Class type) {
            return type == AzureAdAuthorizationMatrixNodeProperty.class;
        }

        public AzureAdAuthorizationMatrixNodeProperty create() {
            return new AzureAdAuthorizationMatrixNodeProperty();
        }
    }

    @Extension
    @Symbol("azureAdAuthorizationMatrix")
    public static class DescriptorImpl extends NodePropertyDescriptor
            implements AuthorizationPropertyDescriptor<AzureAdAuthorizationMatrixNodeProperty> {

        @Override
        public AzureAdAuthorizationMatrixNodeProperty create() {
            return new AzureAdAuthorizationMatrixNodeProperty();
        }

        @Override
        public PermissionScope getPermissionScope() {
            return PermissionScope.COMPUTER;
        }

        @Override
        public AzureAdAuthorizationMatrixNodeProperty newInstance(
                StaplerRequest2 req,
                @NonNull JSONObject formData
        ) throws FormException {
            return createNewInstance(req, formData, false);
        }

        @Override
        public boolean isApplicable() {
            return Jenkins.get().getAuthorizationStrategy() instanceof AzureAdMatrixAuthorizationStrategy;
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

        @SuppressWarnings("unused")
        @Restricted(DoNotUse.class)
        public FormValidation doCheckName(@AncestorInPath Computer computer, @QueryParameter String value) {
            if (isDisableGraphIntegration()) {
                return Utils.undecidableResponse(value);
            }

            // Computer isn't a DescriptorByNameOwner before Jenkins 2.78, and then @AncestorInPath doesn't work
            return doCheckName_(value,
                    computer == null ? Jenkins.get() : computer,
                    computer == null ? Jenkins.ADMINISTER : Computer.CONFIGURE);
        }
    }

    /**
     * Ensure that the user creating a node has Read and Configure permissions.
     */
    @Extension
    @Restricted(NoExternalUse.class)
    public static class NodeListenerImpl extends NodeListener {
        @Override
        protected void onCreated(@NonNull Node node) {
            AuthorizationStrategy authorizationStrategy = Jenkins.get().getAuthorizationStrategy();
            if (authorizationStrategy instanceof AzureAdMatrixAuthorizationStrategy) {
                AzureAdMatrixAuthorizationStrategy strategy =
                        (AzureAdMatrixAuthorizationStrategy) authorizationStrategy;

                AuthorizationMatrixNodeProperty prop = node
                        .getNodeProperty(AzureAdAuthorizationMatrixNodeProperty.class);
                if (prop == null) {
                    prop = new AzureAdAuthorizationMatrixNodeProperty();
                }

                User current = User.current();
                String sid = current == null ? "anonymous" : current.getId();

                if (!strategy.getACL(node).hasPermission2(Jenkins.getAuthentication2(), Computer.CONFIGURE)) {
                    prop.add(Computer.CONFIGURE, PermissionEntry.user(sid));
                }
                if (!prop.getGrantedPermissionEntries().isEmpty()) {
                    try {
                        node.getNodeProperties().replace(prop);
                    } catch (IOException ex) {
                        LOGGER.log(Level.WARNING, "Failed to grant creator permissions on node "
                                + node.getDisplayName(), ex);
                    }
                }
            }
        }
    }

    private static final Logger LOGGER = Logger.getLogger(AzureAdAuthorizationMatrixNodeProperty.class.getName());
}
