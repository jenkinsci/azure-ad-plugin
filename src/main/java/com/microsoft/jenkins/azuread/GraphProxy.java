package com.microsoft.jenkins.azuread;

import com.azure.core.credential.AccessToken;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import edu.umd.cs.findbugs.annotations.NonNull;
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
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

/**
 * Proxies calls to the Microsoft Graph API.
 */
@Extension
@Restricted(NoExternalUse.class)
public class GraphProxy implements RootAction, StaplerProxy {

    private static final OkHttpClient CLIENT = new OkHttpClient();
    private static final long CLOCK_SKEW_TOLERANCE = TimeUnit.MINUTES.toNanos(1);
    private final Cache<String, AccessToken> tokenCache = Caffeine.newBuilder()
            .expireAfter(new Expiry<String, AccessToken>() {
                @Override
                public long expireAfterCreate(
                        @NonNull String key, @NonNull AccessToken value, long currentTime) {
                    long diff = ChronoUnit.NANOS.between(OffsetDateTime.now(), value.getExpiresAt());
                    return diff - CLOCK_SKEW_TOLERANCE;
                }

                @Override
                public long expireAfterUpdate(
                        @NonNull String key, @NonNull AccessToken value, long currentTime, long currentDuration) {
                    return Long.MAX_VALUE;
                }

                @Override
                public long expireAfterRead(
                        @NonNull String key, @NonNull AccessToken value, long currentTime, long currentDuration) {
                    return Long.MAX_VALUE;
                }
            })
            .build();

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
            AzureSecurityRealm azureSecurityRealm = ((AzureSecurityRealm) securityRealm);
            String cacheKey = azureSecurityRealm.getCredentialCacheKey();
            AccessToken accessToken = tokenCache.get(cacheKey, (unused) -> azureSecurityRealm.getAccessToken());

            if (accessToken == null) {
                throw new IllegalStateException("Access token must not be null here");
            }

            return accessToken.getToken();
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
