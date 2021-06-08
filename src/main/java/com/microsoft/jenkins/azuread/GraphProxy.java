package com.microsoft.jenkins.azuread;

import hudson.Extension;
import hudson.model.RootAction;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerProxy;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Extension
@Restricted(NoExternalUse.class)
public class GraphProxy implements RootAction, StaplerProxy {
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

    public Object getDynamic(String token, StaplerRequest req, StaplerResponse rsp) {
        return new V1();
    }

    public void doIndex(StaplerRequest request, StaplerResponse response) throws IOException {
        response.getWriter().write("Hello");
    }

    @Override
    public Object getTarget() {
        // TODO attach the action to a job so that someone configuring a job can do this
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return this;
    }


    public static class V1 {

        private static final OkHttpClient CLIENT = new OkHttpClient();

        private String getToken() {
            SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
            if (securityRealm instanceof AzureSecurityRealm) {
                return ((AzureSecurityRealm) securityRealm).getToken();
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

        public void doIndex(StaplerRequest request, StaplerResponse response) throws IOException {
            response.getWriter().write("Hello v1");
        }

        public void doMe(StaplerRequest request, StaplerResponse response) throws IOException {
            // can't load anything because we're using a confidential client and not a user
            // this is just checking for a 200 response to see that we're logged in anyway
            // TODO I think we can use the logged in user, so that me/people works to retrieve the 'people I work with'
            response.getWriter().write("{}");
            response.setContentType("application/json");
        }

        public void doGroups(StaplerRequest request, StaplerResponse response) throws IOException {
            String path = "groups";

            proxy(request, response, path);
        }

        private void proxy(StaplerRequest request, StaplerResponse response, String path) throws IOException {
            String baseUrl = getBaseUrl();
            String token = getToken();

            String url = buildUrl(request, path, baseUrl);
            Request okRequest = buildRequest(request, token, url);

            try (Response okResp = CLIENT.newCall(okRequest).execute()) {
                String contentType = okResp.header("Content-Type", "application/json");

                response.setContentType(contentType);

                response.setStatus(okResp.code());
                response.addHeader("request-id", okResp.header("request-id"));
                response.addHeader("client-request-id", okResp.header("client-request-id"));
                if ("application/json".equals(contentType)) {
                    String string = okResp.body().string();
                    response.getWriter().write(string);
                } else {
                    // okhttp guesses the charset wrong for pictures when calling .string directly
                    // it's supposed to use the content-type but it only seems to get utf-8 when that's not the right
                    // one, (this is currently used for loading the user's photo
                    response.getWriter().write(okResp.body().byteString().string(StandardCharsets.ISO_8859_1));
                }

            }
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

        private String buildUrl(StaplerRequest request, String path, String baseUrl) {
            StringBuilder builder = new StringBuilder(baseUrl)
                    .append("/")
                    .append(path);

            if (!request.getRestOfPath().equals("")) {
                builder.append(request.getRestOfPath());
            }

            if (request.getQueryString() != null) {
                builder.append("?")
                        .append(request.getQueryString());
            }

            return builder.toString();
        }

        public void doUsers(StaplerRequest request, StaplerResponse response) throws IOException {
            String path = "users";

            proxy(request, response, path);
        }

    }

}
