package com.microsoft.jenkins.azuread;

import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.junit.jupiter.FlagExtension;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AzureAdUserTest {

    private static final String PRIVILEGED_OBJECT_ID = "11111111-1111-1111-1111-111111111111";

    private static AzureAdUser newUser() {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("name", "Test User");
        claims.setClaim("preferred_username", "user@example.com");
        claims.setClaim("tid", "tenant-id");
        claims.setClaim("oid", "22222222-2222-2222-2222-222222222222");
        claims.setClaim("email", "user@example.com");
        claims.setStringListClaim("groups", List.of());
        return AzureAdUser.createFromJwt(claims);
    }

    private static boolean hasAuthority(AzureAdUser user, String authority) {
        for (GrantedAuthority granted : user.getAuthorities()) {
            if (authority.equals(granted.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    @Test
    void displayNameIsNotAddedAsAuthorityByDefault() {
        // Display-name authorization is disabled by default (SECURITY-3935): an Entra group's
        // display name is forgeable, so it must not become an authority. Only the object id is.
        AzureAdUser user = newUser();
        AzureAdGroup group = new AzureAdGroup("33333333-3333-3333-3333-333333333333", "MyGroup");

        user.setAuthorities(List.of(group), user.getUniqueName());

        assertFalse(hasAuthority(user, "MyGroup"),
                "a display name must not be exposed as an authority by default");
        assertTrue(hasAuthority(user, "33333333-3333-3333-3333-333333333333"),
                "the group's object id should always be an authority");
    }

    @Nested
    class WithDisplayNameAuthorizationEnabled {

        @RegisterExtension
        final FlagExtension<String> escapeHatch = FlagExtension.systemProperty(
                ObjId2FullSidMap.ENABLE_DISPLAY_NAME_AUTHORIZATION_PROPERTY, "true");

        @Test
        void plainDisplayNameIsAddedAsAuthority() {
            // The escape hatch restores the legacy behaviour so display-name-only grants keep
            // working while administrators migrate to object IDs.
            AzureAdUser user = newUser();
            AzureAdGroup group = new AzureAdGroup("33333333-3333-3333-3333-333333333333", "MyGroup");

            user.setAuthorities(List.of(group), user.getUniqueName());

            assertTrue(hasAuthority(user, "MyGroup"),
                    "with the escape hatch enabled a plain display name is exposed as an authority");
        }

        @Test
        void displayNameShapedLikeFullSidIsNotAdded() {
            // Even with the escape hatch enabled, an attacker-controlled display name that embeds a
            // privileged group's object id must NOT become an authority, otherwise
            // ObjId2FullSidMap.getOrOriginal would extract the object id and inherit its grant
            // (SECURITY-3935).
            AzureAdUser user = newUser();
            String maliciousName = ObjId2FullSidMap.generateFullSid("Whatever", PRIVILEGED_OBJECT_ID);
            AzureAdGroup attackerGroup = new AzureAdGroup("99999999-9999-9999-9999-999999999999", maliciousName);

            user.setAuthorities(List.of(attackerGroup), user.getUniqueName());

            assertFalse(hasAuthority(user, maliciousName),
                    "display name shaped like \"x (objectId)\" must not be exposed as an authority");
            // The group is still represented by its own (real) object id, so a grant on that id works.
            assertTrue(hasAuthority(user, "99999999-9999-9999-9999-999999999999"),
                    "the group's real object id should still be an authority");
        }
    }
}
