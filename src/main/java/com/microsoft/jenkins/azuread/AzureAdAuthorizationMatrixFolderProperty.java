package com.microsoft.jenkins.azuread;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.AbstractFolderProperty;
import com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import hudson.Extension;
import hudson.model.AutoCompletionCandidates;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;

public class AzureAdAuthorizationMatrixFolderProperty extends AuthorizationMatrixProperty {

    private final transient ObjId2FullSidMap objId2FullSidMap = new ObjId2FullSidMap();

    public AzureAdAuthorizationMatrixFolderProperty(Map<Permission, Set<String>> grantedPermissions) {
        super(grantedPermissions);
        refreshMap();
    }

    public AzureAdAuthorizationMatrixFolderProperty(AuthorizationMatrixProperty orig) throws IllegalAccessException {
        this(orig.getGrantedPermissions());
        // use the reflection hacks since the superclass is hard to inherit
        FieldUtils.writeField(this, "blocksInheritance", orig.isBlocksInheritance(), true);
    }

    void refreshMap() {
        for (String fullSid : this.getAllSIDs()) {
            objId2FullSidMap.putFullSid(fullSid);
        }
    }

    @Override
    protected void add(Permission p, String sid) {
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
        public AbstractFolderProperty<?> newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            AuthorizationMatrixProperty as = (AuthorizationMatrixProperty) super.newInstance(req, formData);
            if (as == null) {
                return null;
            }
            try {
                return new AzureAdAuthorizationMatrixFolderProperty(as);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractFolder> containerType) {
            // only applicable when AzureAdMatrixAuthorizationStategy is in charge
            try {
                return Jenkins.getActiveInstance().getAuthorizationStrategy()
                        instanceof AzureAdMatrixAuthorizationStategy;
            } catch (NoClassDefFoundError x) {
                return false;
            }
        }

        @Override
        public String getDisplayName() {
            return "Azure Active Directory Authorization Matrix";
        }

        public AutoCompletionCandidates doAutoCompleteUserOrGroup(@QueryParameter String value)
                throws ExecutionException, IOException, InterruptedException {
            return AzureAdMatrixAuthorizationStategy.searchAndGenerateCandidates(value);
        }
    }

    @Restricted(DoNotUse.class)
    public static class ConverterImpl implements Converter {

        private Converter delegate = new AuthorizationMatrixProperty.ConverterImpl();

        @Override
        @SuppressWarnings("rawtypes")
        public boolean canConvert(Class type) {
            return type == AzureAdAuthorizationMatrixFolderProperty.class;
        }

        @Override
        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
            delegate.marshal(source, writer, context);
        }

        @Override
        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
            AuthorizationMatrixProperty as = (AuthorizationMatrixProperty) delegate.unmarshal(reader, context);
            if (as == null) {
                return null;
            }
            try {
                return new AzureAdAuthorizationMatrixFolderProperty(as);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
