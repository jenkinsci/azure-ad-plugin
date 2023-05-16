package com.microsoft.jenkins.azuread;

import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ObjId2FullSidMap extends HashMap<String, String> {

    // full sid should be in the form of "<username> (<object_id>)".
    private static final Pattern FULL_SID_PATTERN = Pattern.compile("(.*) \\((.*)\\)");

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
        String objValuesPrefix = objectId + " (";
        for (String value : values()) {
            if (value.startsWith(objValuesPrefix)) {
                return value;
            }
        }
        return objectId;
    }

    static String extractObjectId(String fullSid) {
        Matcher matcher = FULL_SID_PATTERN.matcher(fullSid);
        if (matcher.matches()) {
            String objectId = matcher.group(2);
            return objectId;
        } else {
            return null;
        }
    }

    static String generateFullSid(final String displayName, final String objectId) {
        return String.format("%s (%s)", displayName, objectId);
    }
}
