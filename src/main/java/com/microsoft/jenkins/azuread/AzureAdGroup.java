/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import org.acegisecurity.GrantedAuthority;

public class AzureAdGroup implements GrantedAuthority {

    private String objectId;

    private String groupName;

    public AzureAdGroup(String objectId) {
        this.objectId = objectId;
    }

    @Override
    public String getAuthority() {
        return objectId;
    }

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }
}
