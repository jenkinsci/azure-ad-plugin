package com.microsoft.jenkins.azuread;

import java.util.HashMap;

public class ObjId2FullSidMap extends HashMap<String, String> {

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
