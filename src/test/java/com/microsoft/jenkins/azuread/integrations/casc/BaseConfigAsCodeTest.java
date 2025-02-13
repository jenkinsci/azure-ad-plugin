package com.microsoft.jenkins.azuread.integrations.casc;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.microsoft.jenkins.azuread.AzureAdAuthorizationMatrixFolderProperty;
import com.microsoft.jenkins.azuread.AzureAdAuthorizationMatrixNodeProperty;
import com.microsoft.jenkins.azuread.AzureAdMatrixAuthorizationStrategy;
import com.microsoft.jenkins.azuread.PermissionEntry;
import hudson.model.Computer;
import hudson.model.Item;
import hudson.model.Node;
import hudson.security.AuthorizationStrategy;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.jvnet.hudson.test.LogRecorder;

import java.util.logging.Level;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkinsConfiguredWithCode
abstract class BaseConfigAsCodeTest {
    protected static final String TEST_UPN = "abc@jenkins.com";

    protected final LogRecorder logRecorder = new LogRecorder().record(AzureAdMatrixAuthorizationStrategy.class, Level.WARNING).capture(20);

    protected void validateCommonAssertions(JenkinsConfiguredWithCodeRule j) {
        AuthorizationStrategy authorizationStrategy = j.jenkins.getAuthorizationStrategy();
        assertInstanceOf(AzureAdMatrixAuthorizationStrategy.class, authorizationStrategy, "authorization strategy");
        AzureAdMatrixAuthorizationStrategy azureAdMatrixAuthorizationStrategy = (AzureAdMatrixAuthorizationStrategy) authorizationStrategy;

        assertEquals(2, azureAdMatrixAuthorizationStrategy.getAllPermissionEntries().size(), "one real user sid");
        assertTrue(azureAdMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.user("anonymous"), Jenkins.READ), "anon can read");
        assertTrue(azureAdMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.user(TEST_UPN), Jenkins.READ), "authenticated can read");
        assertTrue(azureAdMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.group("authenticated"), Item.BUILD), "authenticated can build");
        assertTrue(azureAdMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.user(TEST_UPN), Item.DELETE), "authenticated can delete jobs");
        assertTrue(azureAdMatrixAuthorizationStrategy.hasExplicitPermission(PermissionEntry.user(TEST_UPN), Jenkins.ADMINISTER), "authenticated can administer");
        assertTrue(logRecorder.getMessages().isEmpty(), "no warnings");

        Node agent = j.jenkins.getNode("agent");
        assertThat(agent, is(notNullValue()));
        assertThat(agent.getDisplayName(), is(equalTo("agent")));
        AzureAdAuthorizationMatrixNodeProperty nodeProperty =
                agent.getNodeProperty(AzureAdAuthorizationMatrixNodeProperty.class);
        assertThat(nodeProperty, is(notNullValue()));
        assertThat(nodeProperty.getInheritanceStrategy(), instanceOf(NonInheritingStrategy.class));
        assertThat(
                nodeProperty
                        .hasExplicitPermission(PermissionEntry.user("Adele Vance (be674052-e519-4231-b5e7-2b390bff6346)"),
                                Computer.BUILD),
                is(true)
        );

        Folder folder = (Folder) j.jenkins.getItem("generated");
        assertNotNull(folder);
        AzureAdAuthorizationMatrixFolderProperty property = folder.getProperties()
                .get(AzureAdAuthorizationMatrixFolderProperty.class);
        assertInstanceOf(NonInheritingStrategy.class, property.getInheritanceStrategy(), "folder property inherits");
        String groupSid = "Some group (7fe913e8-6c9f-40f8-913e-7178b7768cc5)";
        assertTrue(property.hasExplicitPermission(PermissionEntry.group(groupSid), Item.BUILD));
        assertTrue(property.hasExplicitPermission(PermissionEntry.group(groupSid), Item.READ));
        assertFalse(property.hasExplicitPermission(PermissionEntry.user("anonymous"), Item.READ));
        assertTrue(property.hasExplicitPermission(PermissionEntry.group(groupSid), Item.CONFIGURE));
        assertTrue(property.hasExplicitPermission(PermissionEntry.group(groupSid), Item.DELETE));
        String userSid = "c411116f-cfa6-472c-8ccf-d0cb6053c9aa";
        assertTrue(property.hasExplicitPermission(PermissionEntry.user(userSid), Item.BUILD));
    }
}