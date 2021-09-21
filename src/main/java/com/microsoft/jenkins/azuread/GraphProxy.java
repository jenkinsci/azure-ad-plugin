package com.microsoft.jenkins.azuread;

import com.azure.core.credential.AccessToken;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ProxyConfiguration;
import hudson.model.AbstractItem;
import hudson.model.Action;
import hudson.model.Computer;
import hudson.model.RootAction;
import hudson.security.AccessControlled;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import jenkins.model.TransientActionFactory;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.apache.commons.lang3.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerProxy;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static com.microsoft.jenkins.azuread.AzureSecurityRealm.addProxyToHttpClientIfRequired;

/**
 * Proxies calls to the Microsoft Graph API.
 */
@Extension
@Restricted(NoExternalUse.class)
public class GraphProxy implements RootAction, StaplerProxy {
    private static final int TEN = 10;
    private final Cache<String, AccessToken> tokenCache = Caffeine.newBuilder()
            .expireAfterWrite(TEN, TimeUnit.MINUTES)
            .build();

    private AccessControlled accessControlled;
    private static final OkHttpClient DEFAULT_CLIENT = new OkHttpClient();

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

    // used for the root action
    @SuppressWarnings("unused")
    public GraphProxy() {
    }

    public GraphProxy(AccessControlled accessControlled) {
        this.accessControlled = accessControlled;
    }

    @Override
    public Object getTarget() {
        if (accessControlled != null) {
            if (accessControlled instanceof AbstractItem) {
                accessControlled.checkPermission(AbstractItem.CONFIGURE);
            } else if (accessControlled instanceof Computer) {
                accessControlled.checkPermission(Computer.CONFIGURE);
            } else {
                accessControlled.checkPermission(Jenkins.ADMINISTER);
            }

            return this;
        }

        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        return this;
    }

    @Extension
    public static class TransientActionFactoryImpl extends TransientActionFactory<AbstractItem> {

        @Override
        public Class<AbstractItem> type() {
            return AbstractItem.class;
        }

        @NonNull
        @Override
        public Collection<? extends Action> createFor(@NonNull AbstractItem target) {
            return Collections.singletonList(new GraphProxy(target));
        }
    }

    @Extension
    public static class TransientActionFactoryComputer extends TransientActionFactory<Computer> {

        @Override
        public Class<Computer> type() {
            return Computer.class;
        }

        @NonNull
        @Override
        public Collection<? extends Action> createFor(@NonNull Computer target) {
            return Collections.singletonList(new GraphProxy(target));
        }
    }
    public void doDynamic(StaplerRequest request, StaplerResponse response) throws IOException {
        proxy(request, response);
    }

    private void proxy(StaplerRequest request, StaplerResponse response) throws IOException {
        OkHttpClient client = getClient();
        String baseUrl = getBaseUrl();
        String token = getToken();

        String url = buildUrl(request, baseUrl);
        Request okRequest = buildRequest(request, token, url);

        try (Response okResp = client.newCall(okRequest).execute()) {
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

    /**
     * Prefers the default client for performance, proxy users will get a new instance each time.
     */
    private OkHttpClient getClient() {
        ProxyConfiguration proxyConfiguration = Jenkins.get().getProxy();
        if (proxyConfiguration != null && StringUtils.isNotBlank(proxyConfiguration.getName())) {
            return addProxyToHttpClientIfRequired(new OkHttpClient().newBuilder()).build();
        }
        return DEFAULT_CLIENT;
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

    private Request buildRequest(StaplerRequest request, String token, String url) throws IOException {
        Request.Builder okRequest = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer " + token);

        String consistencyLevel = request.getHeader("ConsistencyLevel");
        if (consistencyLevel != null) {
            okRequest.addHeader("ConsistencyLevel", consistencyLevel);
        }

        if (request.getMethod().equals("POST")) {
            String body = request.getReader().lines()
                    .collect(Collectors.joining(System.lineSeparator()));

            okRequest.post(RequestBody.create(body, MediaType.get(request.getHeader("Content-Type"))));
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
        String apiUrl = baseUrl;

        if (request.getRestOfPath().startsWith("/beta")) {
            apiUrl = baseUrl.replace("/v1.0", "");
        }

        StringBuilder builder = new StringBuilder(apiUrl);

        String path = StringUtils.removeStart(request.getRestOfPath(), "/v1.0");

        // /me doesn't work for service principals but we can use the current logged in user instead
        // this is also used for /me/people to get the people the current logged in user works with
        if (path.startsWith("/me")) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication instanceof AzureAuthenticationToken) {
                String objectID = ((AzureAuthenticationToken) authentication).getAzureAdUser().getObjectID();
                path = path.replace("me", "users/" + objectID);
            }
        }

        builder.append(path);

        if (request.getQueryString() != null) {
            builder.append("?")
                    .append(request.getQueryString());
        }

        return builder.toString();
    }

}
