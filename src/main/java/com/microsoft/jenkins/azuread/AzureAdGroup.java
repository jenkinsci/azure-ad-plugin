/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import org.springframework.security.core.GrantedAuthority;

public class AzureAdGroup implements GrantedAuthority {

    private String objectId;

    private String groupName;

    public AzureAdGroup(String objectId, String groupName) {
        this.objectId = objectId;
        this.groupName = groupName;
    }

    @Override
    public String getAuthority() {
        return groupName;
    }

    public String getObjectId() {
        return objectId;
    }

    public String getGroupName() {
        return groupName;
    }

    @Override
    public String toString() {
        return "AzureAdGroup{"
                + "objectId='" + objectId + '\''
                + ", groupName='" + groupName + '\''
                + '}';
    }
}
