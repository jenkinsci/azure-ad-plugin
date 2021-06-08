package com.microsoft.jenkins.azuread;

import hudson.Extension;
import hudson.model.RootAction;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.apache.commons.lang3.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerProxy;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Extension
@Restricted(NoExternalUse.class)
/**
 * Proxies calls to the Microsoft Graph API
 */
public class GraphProxy implements RootAction, StaplerProxy {

    private static final OkHttpClient CLIENT = new OkHttpClient();

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return null;
    }

    @Override
    public String getUrlName() {
        return "GraphProxy";
    }

    @Override
    public Object getTarget() {
        // TODO attach the action to a job so that someone configuring a job can do this
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return this;
    }

    public void doDynamic(StaplerRequest request, StaplerResponse response) throws IOException {
        // can't load anything because we're using a confidential client and not a user
        // this is just checking for a 200 response to see that we're logged in anyway
        // TODO I think we can use the logged in user, so that me/people works to retrieve the 'people I work with'
        if (request.getRestOfPath().startsWith("/v1.0/me")) {
            response.setContentType("application/json");
            response.getWriter().write("{}");
            return;
        }

        proxy(request, response);
    }

    private void proxy(StaplerRequest request, StaplerResponse response) throws IOException {
        String baseUrl = getBaseUrl();
        String token = getToken();

        String url = buildUrl(request, baseUrl);
        Request okRequest = buildRequest(request, token, url);

        try (Response okResp = CLIENT.newCall(okRequest).execute()) {
            String contentType = okResp.header("Content-Type", "application/json");

            response.setContentType(contentType);

            response.setStatus(okResp.code());
            response.addHeader("request-id", okResp.header("request-id"));
            response.addHeader("client-request-id", okResp.header("client-request-id"));
            ResponseBody body = okResp.body();
            if (body != null) {
                if ("application/json".equals(contentType)) {
                    String string = body.string();
                    response.getWriter().write(string);
                } else {
                    // okhttp guesses the charset wrong for pictures when calling .string directly
                    // it's supposed to use the content-type but it only seems to get utf-8 when that's not the
                    // right one, (this is currently used for loading the user's photo
                    response.getWriter().write(body.byteString().string(StandardCharsets.ISO_8859_1));
                }
            }
        }
    }

    private String getToken() {
        SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
        if (securityRealm instanceof AzureSecurityRealm) {
            // TODO Add caching
            String token = ((AzureSecurityRealm) securityRealm).getToken();
            System.out.println(token);
            return token;
        }
        throw new IllegalStateException("GraphProxy only works when Authentication is set to Azure");
    }

    private String getBaseUrl() {
        SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
        if (securityRealm instanceof AzureSecurityRealm) {
            return ((AzureSecurityRealm) securityRealm).getAzureClient().getServiceRoot();
        }
        throw new IllegalStateException("GraphProxy only works when Authentication is set to Azure");
    }

    private Request buildRequest(StaplerRequest request, String token, String url) {
        Request.Builder okRequest = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer " + token);

        String consistencyLevel = request.getHeader("ConsistencyLevel");
        if (consistencyLevel != null) {
            okRequest.addHeader("ConsistencyLevel", consistencyLevel);
        }

        String accept = request.getHeader("Accept");
        if (accept != null) {
            okRequest.addHeader("Accept", accept);
        }

        String ifMatch = request.getHeader("If-Match");
        if (ifMatch != null) {
            okRequest.addHeader("If-Match", ifMatch);
        }

        return okRequest.build();
    }

    private String buildUrl(StaplerRequest request, String baseUrl) {
        StringBuilder builder = new StringBuilder(baseUrl)
                .append(StringUtils.removeStart(request.getRestOfPath(), "/v1.0"));

        if (request.getQueryString() != null) {
            builder.append("?")
                    .append(request.getQueryString());
        }

        return builder.toString();
    }

}
