package com.microsoft.jenkins.azuread;

import com.azure.identity.AzureAuthorityHosts;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Restricted(NoExternalUse.class)
public final class AzureEnvironment {

    public static final String AZURE_PUBLIC_CLOUD = "Azure";
    public static final String AZURE_CHINA = "Azure China";
    public static final String AZURE_US_GOVERNMENT_L4 = "Azure US Government L4";
    public static final String AZURE_US_GOVERNMENT_L5 = "Azure US Government L5 (DOD)";

    private AzureEnvironment() {
    }

    static String getAuthorityHost(String azureEnvironmentName) {
        switch (azureEnvironmentName) {
            case AZURE_CHINA:
                return AzureAuthorityHosts.AZURE_CHINA;
            case AZURE_US_GOVERNMENT_L4:
            case AZURE_US_GOVERNMENT_L5:
                return AzureAuthorityHosts.AZURE_GOVERNMENT;
            case AZURE_PUBLIC_CLOUD:
            default:
                return AzureAuthorityHosts.AZURE_PUBLIC_CLOUD;
        }
    }

    static String getGraphResource(String azureEnv) {
        switch (azureEnv) {
            case AZURE_CHINA:
                return "https://microsoftgraph.chinacloudapi.cn/";
            case AZURE_US_GOVERNMENT_L4:
                return "https://graph.microsoft.us/";
            case AZURE_US_GOVERNMENT_L5:
                return "https://dod-graph.microsoft.us/";
            case AZURE_PUBLIC_CLOUD:
            default:
                return "https://graph.microsoft.com/";
        }
    }

    static String getServiceRoot(String azureEnv) {
        return getGraphResource(azureEnv) + "v1.0";
    }

}
