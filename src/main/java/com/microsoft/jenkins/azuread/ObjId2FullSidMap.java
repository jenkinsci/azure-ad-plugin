package com.microsoft.jenkins.azuread;

import java.util.HashMap;
import jenkins.util.SystemProperties;

public class ObjId2FullSidMap extends HashMap<String, String> {

    /**
     * Escape hatch to restore the legacy behaviour of authorizing groups by their Entra display
     * name. Disabled by default (SECURITY-3935): Entra group display names are neither unique nor
     * immutable and, unless the tenant restricts it, any member can create a group with an
     * arbitrary display name. Matching a bare display name against a grant therefore lets an
     * attacker inherit a privileged group's permissions by creating a colliding group. Set this
     * system property to {@code true} at startup only as a temporary measure while migrating
     * existing grants to object IDs.
     */
    public static final String ENABLE_DISPLAY_NAME_AUTHORIZATION_PROPERTY =
            ObjId2FullSidMap.class.getName() + ".enableDisplayNameAuthorization";

    /**
     * Whether the insecure legacy display-name authorization behaviour is enabled via
     * {@link #ENABLE_DISPLAY_NAME_AUTHORIZATION_PROPERTY}. Defaults to {@code false}.
     */
    public static boolean isDisplayNameAuthorizationEnabled() {
        return SystemProperties.getBoolean(ENABLE_DISPLAY_NAME_AUTHORIZATION_PROPERTY, false);
    }

    public void putFullSid(String fullSid) {
        String objectId = extractObjectId(fullSid);
        if (objectId != null) {
            put(objectId, fullSid);
        }
    }

    public String getOrOriginal(String objectId) {
        if (containsKey(objectId)) {
            return get(objectId);
        }
        String extractedObjectId = extractObjectId(objectId);
        if (containsKey(extractedObjectId)) {
            return get(extractedObjectId);
        }
        // Display-name fallback: resolving a bare display name to a stored "displayName (objectId)"
        // entry lets an attacker-created Entra group whose display name collides with a privileged
        // group inherit its permissions (SECURITY-3935). Disabled by default; only performed when
        // the legacy escape hatch is explicitly enabled.
        if (isDisplayNameAuthorizationEnabled()) {
            String objValuesPrefix = objectId + " (";
            for (String value : values()) {
                if (value.startsWith(objValuesPrefix)) {
                    return value;
                }
            }
        }
        return objectId;
    }

    static String extractObjectId(String fullSid) {
        // full sid should be in the form of "<username> (<object_id>)".

        // this code previously used regex: (.*) \((.*)\), which was shown to be a CPU hotspot in certain
        // Jenkins installations

        if (fullSid.isEmpty()) {
            return null;
        }
        if (fullSid.charAt(fullSid.length() - 1) != ')') {
            return null;
        }
        int openingParenthesesPosition = fullSid.lastIndexOf('(');
        if (openingParenthesesPosition <= 0) {
            return null;
        }
        if (fullSid.charAt(openingParenthesesPosition - 1) != ' ') {
            return null;
        }
        return fullSid.substring(openingParenthesesPosition + 1, fullSid.length() - 1);
    }

    static String generateFullSid(final String displayName, final String objectId) {
        return String.format("%s (%s)", displayName, objectId);
    }
}
