package com.microsoft.jenkins.azuread;

import com.microsoft.jenkins.azuread.utils.UUIDValidator;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.Node;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.SecurityRealm;
import hudson.slaves.NodeProperty;
import hudson.util.DescribableList;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Converts configuration of the deprecated Entra ID matrix authorization strategies to the equivalent
 * configuration of the Matrix Authorization Strategy plugin.
 *
 * <p>SIDs of the form {@code Display Name (objectId)} are replaced by the bare object id, which is what
 * {@link AzureAdUser} reports as its username and group authorities.
 *
 * <p>New properties are added before the strategy is replaced and the old properties are only removed afterwards,
 * so that permissions stay in effect throughout the migration.
 */
@Restricted(NoExternalUse.class)
public final class EntraIdAuthorizationMigrator {

    private static final Logger LOGGER = Logger.getLogger(EntraIdAuthorizationMigrator.class.getName());

    private final boolean dryRun;
    private final Plan plan = new Plan();

    private EntraIdAuthorizationMigrator(boolean dryRun) {
        this.dryRun = dryRun;
    }

    /**
     * Compute what a migration would change, without changing anything.
     */
    @NonNull
    public static Plan preview() {
        EntraIdAuthorizationMigrator migrator = new EntraIdAuthorizationMigrator(true);
        try {
            migrator.run(Jenkins.getAuthentication2());
        } catch (IOException e) {
            // cannot happen in a dry run
            throw new IllegalStateException(e);
        }
        return migrator.plan;
    }

    /**
     * Migrate the configuration. Nothing is changed if the current user would lose administrative access.
     *
     * @throws IOException if saving configuration failed
     */
    @NonNull
    public static Plan migrate() throws IOException {
        EntraIdAuthorizationMigrator migrator = new EntraIdAuthorizationMigrator(false);
        migrator.run(Jenkins.getAuthentication2());
        return migrator.plan;
    }

    private void run(Authentication currentUser) throws IOException {
        Jenkins jenkins = Jenkins.get();
        AuthorizationStrategy current = jenkins.getAuthorizationStrategy();
        if (!(current instanceof GlobalMatrixAuthorizationStrategy oldStrategy)) {
            plan.errors.add("The current authorization strategy is not an Entra ID matrix-based strategy.");
            return;
        }

        hudson.security.GlobalMatrixAuthorizationStrategy newStrategy;
        if (current instanceof AzureAdMatrixAuthorizationStrategy) {
            newStrategy = new hudson.security.ProjectMatrixAuthorizationStrategy();
            plan.targetStrategy = hudson.security.ProjectMatrixAuthorizationStrategy.DESCRIPTOR.getDisplayName();
        } else {
            newStrategy = new hudson.security.GlobalMatrixAuthorizationStrategy();
            plan.targetStrategy = hudson.security.GlobalMatrixAuthorizationStrategy.DESCRIPTOR.getDisplayName();
        }
        copyEntries(oldStrategy, (p, e) -> newStrategy.add(p, e), "global configuration");

        if (!newStrategy.getRootACL().hasPermission2(currentUser, Jenkins.ADMINISTER)) {
            plan.errors.add("You would no longer have Overall/Administer permission after the migration.");
        }
        if (!plan.errors.isEmpty()) {
            return;
        }

        List<Runnable> cleanup = new ArrayList<>();
        try (ACLContext ignored = ACL.as2(ACL.SYSTEM2)) {
            if (current instanceof AzureAdMatrixAuthorizationStrategy) {
                migrateJobs(jenkins, cleanup);
                if (jenkins.getPlugin("cloudbees-folder") != null) {
                    FolderMigration.migrate(this, cleanup);
                }
                migrateNodes(jenkins, cleanup);
            }
            if (dryRun) {
                return;
            }

            jenkins.setAuthorizationStrategy(newStrategy);
            jenkins.save();
            LOGGER.info("Migrated Entra ID matrix-based authorization to " + plan.targetStrategy);

            for (Runnable action : cleanup) {
                try {
                    action.run();
                } catch (RuntimeException e) {
                    LOGGER.log(Level.WARNING, "Failed to remove deprecated authorization property", e);
                    plan.warnings.add("Failed to remove a deprecated property, see the system log: " + e.getMessage());
                }
            }
        }
    }

    private void migrateJobs(Jenkins jenkins, List<Runnable> cleanup) throws IOException {
        for (Job<?, ?> job : jenkins.allItems(Job.class)) {
            List<AuthorizationMatrixProperty> oldProperties = new ArrayList<>();
            for (JobProperty<?> property : job.getAllProperties()) {
                if (property instanceof AuthorizationMatrixProperty oldProperty) {
                    oldProperties.add(oldProperty);
                }
            }
            if (oldProperties.isEmpty()) {
                continue;
            }
            plan.jobs++;
            String context = "job " + job.getFullName();

            hudson.security.AuthorizationMatrixProperty newProperty =
                    job.getProperty(hudson.security.AuthorizationMatrixProperty.class);
            boolean isNew = newProperty == null;
            if (isNew) {
                newProperty = new hudson.security.AuthorizationMatrixProperty(
                        Collections.emptyMap(), oldProperties.get(0).getInheritanceStrategy());
            }
            hudson.security.AuthorizationMatrixProperty target = newProperty;
            for (AuthorizationMatrixProperty oldProperty : oldProperties) {
                copyEntries(oldProperty, (p, e) -> target.add(p, e), context);
            }
            if (dryRun) {
                continue;
            }
            if (isNew) {
                job.addProperty(newProperty);
            } else {
                job.save();
            }
            cleanup.add(() -> {
                try {
                    for (AuthorizationMatrixProperty oldProperty : oldProperties) {
                        job.removeProperty(oldProperty);
                    }
                } catch (IOException e) {
                    throw new IllegalStateException("Failed to update " + job.getFullName(), e);
                }
            });
        }
    }

    private void migrateNodes(Jenkins jenkins, List<Runnable> cleanup) throws IOException {
        migrateNode(jenkins.getNodeProperties(), "built-in node", jenkins::save, cleanup);
        for (Node node : jenkins.getNodes()) {
            migrateNode(node.getNodeProperties(), "agent " + node.getNodeName(), () -> jenkins.updateNode(node),
                    cleanup);
        }
    }

    private void migrateNode(DescribableList<NodeProperty<?>, ?> properties, String context, IoAction save,
                             List<Runnable> cleanup) throws IOException {
        List<AuthorizationMatrixNodeProperty> oldProperties = properties.getAll(AuthorizationMatrixNodeProperty.class);
        if (oldProperties.isEmpty()) {
            return;
        }
        plan.nodes++;

        org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty newProperty =
                properties.get(org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty.class);
        boolean isNew = newProperty == null;
        if (isNew) {
            newProperty = new org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty(Collections.emptyMap());
            newProperty.setInheritanceStrategy(oldProperties.get(0).getInheritanceStrategy());
        }
        org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty target = newProperty;
        for (AuthorizationMatrixNodeProperty oldProperty : oldProperties) {
            copyEntries(oldProperty, (p, e) -> target.add(p, e), context);
        }
        if (dryRun) {
            return;
        }
        if (isNew) {
            properties.add(newProperty);
        }
        save.run();
        cleanup.add(() -> {
            try {
                for (AuthorizationMatrixNodeProperty oldProperty : oldProperties) {
                    properties.remove(oldProperty);
                }
                save.run();
            } catch (IOException e) {
                throw new IllegalStateException("Failed to update " + context, e);
            }
        });
    }

    void copyEntries(AuthorizationContainer from,
                     BiConsumer<Permission, org.jenkinsci.plugins.matrixauth.PermissionEntry> to, String context) {
        for (Map.Entry<Permission, Set<PermissionEntry>> e : from.getGrantedPermissionEntries().entrySet()) {
            for (PermissionEntry entry : e.getValue()) {
                to.accept(e.getKey(), convert(entry, context));
            }
        }
    }

    private org.jenkinsci.plugins.matrixauth.PermissionEntry convert(PermissionEntry entry, String context) {
        org.jenkinsci.plugins.matrixauth.AuthorizationType type =
                org.jenkinsci.plugins.matrixauth.AuthorizationType.valueOf(entry.getType().name());
        String sid = entry.getSid();
        String newSid = normalizeSid(sid, entry.getType(), context);
        if (!newSid.equals(sid)) {
            plan.sidChanges.put(sid, newSid);
        }
        return new org.jenkinsci.plugins.matrixauth.PermissionEntry(type, newSid);
    }

    private String normalizeSid(String sid, AuthorizationType type, String context) {
        if ("anonymous".equals(sid) || "authenticated".equals(sid) || UUIDValidator.isValidUUID(sid)) {
            return sid;
        }
        String objectId = ObjId2FullSidMap.extractObjectId(sid);
        if (UUIDValidator.isValidUUID(objectId)) {
            return objectId;
        }
        if (type == AuthorizationType.USER) {
            // user principal names are also granted as authorities
            return sid;
        }
        String groupId = lookupGroupId(sid);
        if (groupId != null) {
            return groupId;
        }
        if (type == AuthorizationType.GROUP) {
            plan.warnings.add("Could not find the object id of group '" + sid + "' (" + context
                    + "); it was kept as is and will probably not match anyone.");
        }
        return sid;
    }

    @CheckForNull
    private String lookupGroupId(String groupName) {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();
        if (!(realm instanceof AzureSecurityRealm)) {
            return null;
        }
        try {
            return realm.loadGroupByGroupname2(groupName, false).getName();
        } catch (UsernameNotFoundException e) {
            return null;
        } catch (RuntimeException e) {
            LOGGER.log(Level.FINE, "Failed to look up group " + groupName, e);
            return null;
        }
    }

    boolean isDryRun() {
        return dryRun;
    }

    Plan getPlan() {
        return plan;
    }

    @FunctionalInterface
    interface IoAction {
        void run() throws IOException;
    }

    /**
     * What a migration changes or changed.
     */
    public static final class Plan {
        private String targetStrategy;
        int jobs;
        int folders;
        int nodes;
        private final Map<String, String> sidChanges = new TreeMap<>();
        private final List<String> warnings = new ArrayList<>();
        private final List<String> errors = new ArrayList<>();

        public String getTargetStrategy() {
            return targetStrategy;
        }

        public int getJobs() {
            return jobs;
        }

        public int getFolders() {
            return folders;
        }

        public int getNodes() {
            return nodes;
        }

        public Map<String, String> getSidChanges() {
            return sidChanges;
        }

        public List<String> getWarnings() {
            return warnings;
        }

        public List<String> getErrors() {
            return errors;
        }

        public boolean isPossible() {
            return errors.isEmpty();
        }
    }

    /**
     * Separate class so that it is only loaded when cloudbees-folder is installed.
     */
    static final class FolderMigration {
        private FolderMigration() {
        }

        static void migrate(EntraIdAuthorizationMigrator migrator, List<Runnable> cleanup) throws IOException {
            for (com.cloudbees.hudson.plugins.folder.AbstractFolder<?> folder
                    : Jenkins.get().allItems(com.cloudbees.hudson.plugins.folder.AbstractFolder.class)) {
                List<com.microsoft.jenkins.azuread.folder.properties.AuthorizationMatrixProperty> oldProperties =
                        folder.getProperties().getAll(
                                com.microsoft.jenkins.azuread.folder.properties.AuthorizationMatrixProperty.class);
                if (oldProperties.isEmpty()) {
                    continue;
                }
                migrator.getPlan().folders++;
                String context = "folder " + folder.getFullName();

                com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty newProperty =
                        folder.getProperties().get(
                                com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty.class);
                boolean isNew = newProperty == null;
                if (isNew) {
                    newProperty = new com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty(
                            Collections.<Permission, Set<String>>emptyMap());
                    InheritanceStrategy inheritanceStrategy = oldProperties.get(0).getInheritanceStrategy();
                    newProperty.setInheritanceStrategy(inheritanceStrategy);
                }
                var target = newProperty;
                for (var oldProperty : oldProperties) {
                    migrator.copyEntries(oldProperty, (p, e) -> target.add(p, e), context);
                }
                if (migrator.isDryRun()) {
                    continue;
                }
                if (isNew) {
                    // AbstractFolder#addProperty rejects it until matrix-based security is active
                    folder.getProperties().add(newProperty);
                } else {
                    folder.save();
                }
                cleanup.add(() -> {
                    for (var oldProperty : oldProperties) {
                        folder.getProperties().remove(oldProperty);
                    }
                });
            }
        }
    }
}
