/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 */

package com.microsoft.jenkins.azuread;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import com.microsoft.jenkins.azurecommons.telemetry.AppInsightsClientFactory;
import com.microsoft.jenkins.azurecommons.telemetry.AzureHttpRecorder;
import hudson.Plugin;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.Map;

public class AzureAdPlugin extends Plugin {

    public static final String AI_PLUGIN_NAME = "AzureJenkinsAd";

    public static final String AI_EVENT_ITEM_SECURITY_REALM = "SecurityRealm";

    public static final String AI_EVENT_ACTION_LOGIN = "Login";

    public static final String AI_EVENT_ACTION_LOGIN_FAIL = "LoginFail";

    public static void sendEvent(final String item, final String action, final Map<String, String> properties) {
        AppInsightsClientFactory.getInstance(AzureAdPlugin.class)
                .sendEvent(item, action, properties, false);
    }

    public static void sendLoginEvent(String userId, String tenantId) {
        sendEvent(AI_EVENT_ITEM_SECURITY_REALM,
                AI_EVENT_ACTION_LOGIN,
                Maps.newHashMap(ImmutableMap.of("userId", userId, "tenantId", tenantId)));
    }

    public static void sendLoginFailEvent(String tenantId, String failReason) {
        sendEvent(AI_EVENT_ITEM_SECURITY_REALM,
                AI_EVENT_ACTION_LOGIN_FAIL,
                Maps.newHashMap(ImmutableMap.of("tenantId", tenantId, "failReason", failReason)));
    }

    public static class AzureTelemetryInterceptor implements Interceptor {
        @Override
        public Response intercept(final Chain chain) throws IOException {
            final Request request = chain.request();
            final Response response = chain.proceed(request);
            new AzureHttpRecorder(AppInsightsClientFactory.getInstance(AzureAdPlugin.class))
                    .record(new AzureHttpRecorder.HttpRecordable()
                            .withHttpCode(response.code())
                            .withHttpMessage(response.message())
                            .withHttpMethod(request.method())
                            .withRequestUri(request.url().uri())
                            .withRequestId(response.header("x-ms-request-id"))
                    );
            return response;
        }
    }
}
