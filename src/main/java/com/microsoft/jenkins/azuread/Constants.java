/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

public final class Constants {
    public static final String DEFAULT_MANAGEMENT_URL = "https://management.core.windows.net/";
    public static final String DEFAULT_AUTHENTICATION_ENDPOINT = "https://login.microsoftonline.com/";
    public static final String DEFAULT_RESOURCE_MANAGER_ENDPOINT = "https://management.azure.com/";
    public static final String DEFAULT_GRAPH_ENDPOINT = "https://graph.microsoft.com/";
    public static final String AZURE_PORTAL_URL = "https://ms.portal.azure.com";
    public static final boolean DEBUG = false;

    private Constants() {
    }
}
