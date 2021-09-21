/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenRequestContext;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.microsoft.graph.authentication.TokenCredentialAuthProvider;
import com.microsoft.graph.http.GraphServiceException;
import com.microsoft.graph.httpcore.HttpClients;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.options.HeaderOption;
import com.microsoft.graph.options.Option;
import com.microsoft.graph.options.QueryOption;
import com.microsoft.graph.requests.GraphServiceClient;
import com.microsoft.graph.requests.GroupCollectionPage;
import com.microsoft.jenkins.azuread.scribe.AzureApi;
import com.microsoft.jenkins.azuread.scribe.AzureOAuthService;
import com.microsoft.jenkins.azuread.utils.UUIDValidator;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ProxyConfiguration;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException2;
import hudson.security.csrf.CrumbExclusion;
import hudson.tasks.Mailer;
import hudson.tasks.Mailer.UserProperty;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import io.jenkins.plugins.azuresdk.HttpClientRetriever;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import jenkins.util.JenkinsJVM;
import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Proxy;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static com.microsoft.jenkins.azuread.AzureEnvironment.AZURE_CHINA;
import static com.microsoft.jenkins.azuread.AzureEnvironment.AZURE_GERMANY;
import static com.microsoft.jenkins.azuread.AzureEnvironment.AZURE_PUBLIC_CLOUD;
import static com.microsoft.jenkins.azuread.AzureEnvironment.AZURE_US_GOVERNMENT_L4;
import static com.microsoft.jenkins.azuread.AzureEnvironment.AZURE_US_GOVERNMENT_L5;
import static com.microsoft.jenkins.azuread.AzureEnvironment.getAuthorityHost;
import static com.microsoft.jenkins.azuread.AzureEnvironment.getGraphResource;
import static com.microsoft.jenkins.azuread.AzureEnvironment.getServiceRoot;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;

public class AzureSecurityRealm extends SecurityRealm {

    private static final String REFERER_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".referer";
    private static final String TIMESTAMP_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".beginTime";
    private static final String NONCE_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".nonce";
    private static final Logger LOGGER = Logger.getLogger(AzureSecurityRealm.class.getName());
    private static final int NONCE_LENGTH = 10;
    public static final String CALLBACK_URL = "/securityRealm/finishLogin";
    private static final String CONVERTER_NODE_CLIENT_ID = "clientid";
    private static final String CONVERTER_NODE_CLIENT_SECRET = "clientsecret";
    private static final String CONVERTER_NODE_TENANT = "tenant";
    private static final String CONVERTER_NODE_CACHE_DURATION = "cacheduration";
    private static final String CONVERTER_NODE_FROM_REQUEST = "fromrequest";
    private static final int CACHE_KEY_LOG_LENGTH = 8;
    private static final int NOT_FOUND = 404;
    public static final String CONVERTER_DISABLE_GRAPH_INTEGRATION = "disableGraphIntegration";
    public static final String CONVERTER_ENVIRONMENT_NAME = "environmentName";

    private Cache<String, AzureAdUser> caches;

    private Secret clientId;
    private Secret clientSecret;
    private Secret tenant;
    private int cacheDuration;
    private boolean fromRequest = false;
    private boolean singleLogout;
    private boolean disableGraphIntegration;
    private String azureEnvironmentName = "Azure";

    private final transient Supplier<GraphServiceClient<Request>> cachedAzureClient = Suppliers.memoize(() -> {

        String azureEnv = getAzureEnvironmentName();
        final ClientSecretCredential clientSecretCredential = getClientSecretCredential();

        final TokenCredentialAuthProvider authProvider = new TokenCredentialAuthProvider(clientSecretCredential);

        OkHttpClient.Builder builder = HttpClients.createDefault(authProvider)
                .newBuilder();

        builder = addProxyToHttpClientIfRequired(builder);
        final OkHttpClient graphHttpClient = builder.build();

        GraphServiceClient<Request> graphServiceClient = GraphServiceClient
                .builder()
                .httpClient(graphHttpClient)
                .buildClient();

        if (!azureEnv.equals(AZURE_PUBLIC_CLOUD)) {
            graphServiceClient.setServiceRoot(getServiceRoot(azureEnv));
        }
        return graphServiceClient;

    });

    public AccessToken getAccessToken() {
        ClientSecretCredential clientSecretCredential = getClientSecretCredential();

        TokenRequestContext tokenRequestContext = new TokenRequestContext();
        tokenRequestContext.setScopes(singletonList("https://graph.microsoft.com/.default"));

        AccessToken accessToken = clientSecretCredential.getToken(tokenRequestContext).block();

        if (accessToken == null) {
            throw new IllegalStateException("Access token null when it is required");
        }

        return accessToken;
    }

    private ClientSecretCredential getClientSecretCredential() {
        String azureEnv = getAzureEnvironmentName();
        return new ClientSecretCredentialBuilder()
                .clientId(clientId.getPlainText())
                .clientSecret(clientSecret.getPlainText())
                .tenantId(tenant.getPlainText())
                .authorityHost(getAuthorityHost(azureEnv))
                .httpClient(HttpClientRetriever.get())
                .build();
    }

    public static OkHttpClient.Builder addProxyToHttpClientIfRequired(OkHttpClient.Builder builder) {
        if (JenkinsJVM.isJenkinsJVM()) {
            ProxyConfiguration proxyConfiguration = Jenkins.get().getProxy();
            if (proxyConfiguration != null && StringUtils.isNotBlank(proxyConfiguration.getName())) {
                Proxy proxy = proxyConfiguration.createProxy("graph.microsoft.com");

                builder = builder.proxy(proxy);
                if (StringUtils.isNotBlank(proxyConfiguration.getUserName())) {
                    builder = builder.proxyAuthenticator((route, response) -> {
                        String credential = Credentials.basic(
                                proxyConfiguration.getUserName(),
                                proxyConfiguration.getSecretPassword().getPlainText()
                        );
                        return response.request().newBuilder().header("Authorization", credential).build();
                    });
                }
            }
        }

        return builder;
    }


    public boolean isSingleLogout() {
        return singleLogout;
    }

    @DataBoundSetter
    public void setSingleLogout(boolean singleLogout) {
        this.singleLogout = singleLogout;
    }

    private final Supplier<JwtConsumer> jwtConsumer = Suppliers.memoize(() ->
            Utils.JwtUtil.jwt(getClientId(), getTenant()));

    public String getClientIdSecret() {
        return clientId.getEncryptedValue();
    }

    public String getClientSecretSecret() {
        return clientSecret.getEncryptedValue();
    }

    public String getTenantSecret() {
        return tenant.getEncryptedValue();
    }

    String getCredentialCacheKey() {
        return Util.getDigestOf(clientId.getPlainText()
                        + clientSecret.getPlainText()
                        + tenant.getPlainText()
                        + azureEnvironmentName
        );
    }

    public String getClientId() {
        return clientId.getPlainText();
    }

    public String getAzureEnvironmentName() {
        if (StringUtils.isBlank(azureEnvironmentName)) {
            return AZURE_PUBLIC_CLOUD;
        }

        return azureEnvironmentName;
    }

    @DataBoundSetter
    public void setAzureEnvironmentName(String azureEnvironmentName) {
        this.azureEnvironmentName = azureEnvironmentName;
    }

    public boolean isDisableGraphIntegration() {
        return disableGraphIntegration;
    }

    @DataBoundSetter
    public void setDisableGraphIntegration(boolean disableGraphIntegration) {
        this.disableGraphIntegration = disableGraphIntegration;
    }

    public void setClientId(String clientId) {
        this.clientId = Secret.fromString(clientId);
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = Secret.fromString(clientSecret);
    }

    public String getTenant() {
        return tenant.getPlainText();
    }

    public void setTenant(String tenant) {
        this.tenant = Secret.fromString(tenant);
    }

    public int getCacheDuration() {
        return cacheDuration;
    }

    public void setCacheDuration(int cacheDuration) {
        this.cacheDuration = cacheDuration;
    }

    public void setCaches(Cache<String, AzureAdUser> caches) {
        this.caches = caches;
    }

    public boolean isFromRequest() {
        return fromRequest;
    }

    @DataBoundSetter
    public void setFromRequest(boolean fromRequest) {
        this.fromRequest = fromRequest;
    }

    public JwtConsumer getJwtConsumer() {
        return jwtConsumer.get();
    }

    AzureOAuthService getOAuthService() {
        return (AzureOAuthService) new ServiceBuilder(clientId.getPlainText())
                .apiSecret(clientSecret.getPlainText())
                .responseType("id_token")
                .scope("openid profile email")
                .callback(getRootUrl() + CALLBACK_URL)
                .build(AzureApi.instance(getGraphResource(getAzureEnvironmentName()),
                        this.getTenant(),
                        getAuthorityHost(getAzureEnvironmentName())));
    }

    GraphServiceClient<Request> getAzureClient() {
        return cachedAzureClient.get();
    }


    private String getRootUrl() {
        Jenkins jenkins = Jenkins.get();
        String url = isFromRequest() ? jenkins.getRootUrlFromRequest() : jenkins.getRootUrl();
        return StringUtils.stripEnd(url, "/");
    }

    @DataBoundConstructor
    public AzureSecurityRealm(String tenant, String clientId, Secret clientSecret, int cacheDuration) {
        super();
        this.clientId = Secret.fromString(clientId);
        this.clientSecret = clientSecret;
        this.tenant = Secret.fromString(tenant);
        this.cacheDuration = cacheDuration;
        caches = Caffeine.newBuilder()
                .expireAfterWrite(cacheDuration, TimeUnit.SECONDS)
                .build();
    }

    public AzureSecurityRealm() {
        super();
        LOGGER.log(Level.FINE, "AzureSecurityRealm()");
    }

    @SuppressWarnings("unused") // used by stapler
    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) {
        request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);
        OAuth20Service service = getOAuthService();
        request.getSession().setAttribute(TIMESTAMP_ATTRIBUTE, System.currentTimeMillis());
        String nonce = RandomStringUtils.randomAlphanumeric(NONCE_LENGTH);
        request.getSession().setAttribute(NONCE_ATTRIBUTE, nonce);

        Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put("nonce", nonce);
        additionalParams.put("response_mode", "form_post");

        return new HttpRedirect(service.getAuthorizationUrl(additionalParams));
    }

    public HttpResponse doFinishLogin(StaplerRequest request)
            throws InvalidJwtException, IOException {
        try {
            final Long beginTime = (Long) request.getSession().getAttribute(TIMESTAMP_ATTRIBUTE);
            final String expectedNonce = (String) request.getSession().getAttribute(NONCE_ATTRIBUTE);
            if (expectedNonce == null) {
                // no nonce, probably some issue with an old session, force the user to re-auth
                request.getSession().invalidate();
                return HttpResponses.redirectToContextRoot();
            }

            if (beginTime != null) {
                long endTime = System.currentTimeMillis();
                LOGGER.info("Requesting oauth code time = " + (endTime - beginTime) + " ms");
            }

            final String idToken = request.getParameter("id_token");

            if (StringUtils.isBlank(idToken)) {
                LOGGER.info("No `id_token` found ensure you have enabled it on the 'Authentication' page of the "
                        + "app registration");
                request.getSession().invalidate();
                return HttpResponses.redirectToContextRoot();
            }
            // validate the nonce to avoid CSRF
            final JwtClaims claims = validateIdToken(expectedNonce, idToken);
            String key = (String) claims.getClaimValue("preferred_username");

            AzureAdUser userDetails = caches.get(key, (cacheKey) -> {
                final AzureAdUser user;
                user = AzureAdUser.createFromJwt(claims);

                List<AzureAdGroup> groups = emptyList();
                if (!isDisableGraphIntegration()) {
                    groups = AzureCachePool.get(getAzureClient())
                            .getBelongingGroupsByOid(user.getObjectID());
                }
                user.setAuthorities(groups);
                LOGGER.info(String.format("Fetch user details with sub: %s***",
                        key.substring(0, CACHE_KEY_LOG_LENGTH)));
                return user;
            });

            if (userDetails == null) {
                throw new IllegalStateException("Should not be possible");
            }

            final AzureAuthenticationToken auth = new AzureAuthenticationToken(userDetails);

            // Enforce updating current identity
            SecurityContextHolder.getContext().setAuthentication(auth);
            User u = User.current();
            if (u != null) {
                String description = generateDescription(auth);
                u.setDescription(description);
                u.setFullName(auth.getAzureAdUser().getName());
                if (StringUtils.isNotBlank(auth.getAzureAdUser().getEmail())) {
                    UserProperty existing = u.getProperty(UserProperty.class);
                    if (existing == null || !existing.hasExplicitlyConfiguredAddress()) {
                        u.addProperty(new Mailer.UserProperty(auth.getAzureAdUser().getEmail()));
                    }
                }
            }


            SecurityListener.fireAuthenticated2(userDetails);
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "error", ex);
            throw ex;
        } finally {
            if (request.isRequestedSessionIdValid()) {
                request.getSession().removeAttribute(NONCE_ATTRIBUTE);
            }
        }

        // redirect to referer
        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        if (referer != null) {
            return HttpResponses.redirectTo(referer);
        } else {
            return HttpResponses.redirectToContextRoot();
        }
    }

    JwtClaims validateIdToken(String expectedNonce, String idToken) throws InvalidJwtException {
        JwtClaims claims = getJwtConsumer().processToClaims(idToken);
        final String responseNonce = (String) claims.getClaimValue("nonce");
        if (StringUtils.isAnyEmpty(expectedNonce, responseNonce) || !expectedNonce.equals(responseNonce)) {
            throw new IllegalStateException(String.format("Invalid nonce in the response, "
                    + "expected: %s actual: %s", expectedNonce, responseNonce));
        }
        return claims;
    }

    @Override
    protected String getPostLogOutUrl2(StaplerRequest req, Authentication auth) {
        if (auth instanceof AzureAuthenticationToken) {
            AzureAuthenticationToken azureToken = (AzureAuthenticationToken) auth;
            String oid = azureToken.getAzureAdUser().getObjectID();
            AzureCachePool.invalidateBelongingGroupsByOid(oid);
        }
        // Ensure single sign-out

        if (singleLogout) {
            return getOAuthService().getLogoutUrl();
        }
        return req.getContextPath() + "/" + AzureAdLogoutAction.POST_LOGOUT_URL;
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents((AuthenticationManager) authentication -> {
            if (authentication instanceof AzureAuthenticationToken) {
                return authentication;
            }
            throw new BadCredentialsException("Unexpected authentication type: " + authentication);
        }, username -> {
            if (username == null) {
                throw new UserMayOrMayNotExistException2("Can't find a user with no username");
            }

            if (isDisableGraphIntegration()) {
                throw new UserMayOrMayNotExistException2("Can't lookup a user if graph integration is disabled");
            }

            AzureAdUser azureAdUser = caches.get(username, (cacheKey) -> {
                GraphServiceClient<Request> azureClient = getAzureClient();
                String userId = ObjId2FullSidMap.extractObjectId(username);

                if (userId == null) {
                    userId = username;
                }

                // Currently triggers annoying log spam if the user is a group, but there's no way to tell currently
                // as we look up by object id we don't know if it's a user or a group :(
                try {
                    com.microsoft.graph.models.User activeDirectoryUser = azureClient.users(userId).buildRequest()
                            .get();

                    if (activeDirectoryUser != null & activeDirectoryUser.id == null) {
                        // known to happen when subject is a group with display name only and starts with a #
                        return null;
                    }

                    AzureAdUser user = requireNonNull(AzureAdUser.createFromActiveDirectoryUser(activeDirectoryUser));
                    List<AzureAdGroup> groups = AzureCachePool.get(azureClient)
                            .getBelongingGroupsByOid(user.getObjectID());

                    user.setAuthorities(groups);
                    return user;
                } catch (GraphServiceException e) {
                    if (e.getResponseCode() == NOT_FOUND) {
                        return null;
                    }
                    throw e;
                }
            });

            if (azureAdUser == null) {
                throw new UsernameNotFoundException("Cannot find user: " + username);
            }

            return azureAdUser;
        });
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public GroupDetails loadGroupByGroupname2(String groupName, boolean fetchMembers) {
        if (isDisableGraphIntegration()) {
            throw new UserMayOrMayNotExistException2("Can't lookup a group if graph integration is disabled");
        }

        GraphServiceClient<Request> azureClient = getAzureClient();

        String groupId = ObjId2FullSidMap.extractObjectId(groupName);

        if (groupId == null) {
            // just an object id on it's own?
            groupId = groupName;
        }

        Group group;
        if (UUIDValidator.isValidUUID(groupId)) {
            group = azureClient.groups(groupId)
                    .buildRequest()
                    .get();
        } else {
            group = loadGroupByDisplayName(groupName);
        }

        if (group == null || group.id == null) {
            throw new UsernameNotFoundException("Group: " + groupName + " not found");
        }

        return new AzureAdGroupDetails(group.id, group.displayName);
    }

    @CheckForNull
    private Group loadGroupByDisplayName(String groupName) {
        LinkedList<Option> requestOptions = new LinkedList<>();
        String encodedGroupName = groupName
                .replace("'", "''");
        try {
            encodedGroupName = URLEncoder.encode(encodedGroupName, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            LOGGER.log(Level.WARNING, "Failed to url encode query, group name was: " + groupName);
        }

        String query = String.format("\"displayName:%s\"", encodedGroupName);

        requestOptions.add(new QueryOption("$search", query));
        requestOptions.add(new HeaderOption("ConsistencyLevel", "eventual"));

        GroupCollectionPage groupCollectionPage = getAzureClient().groups()
                .buildRequest(requestOptions)
                .select("id,displayName")
                .get();

        assert groupCollectionPage != null;
        List<Group> currentPage = groupCollectionPage.getCurrentPage();
        Group group = null;
        if (currentPage.size() > 1) {
            String groupIds = currentPage
                    .stream()
                    .map(groupO -> groupO.id)
                    .collect(Collectors.joining(","));
            throw new UsernameNotFoundException("Multiple matches found for group display name, "
                    + "this must be unique: " + groupIds);
        } else if (currentPage.size() == 1) {
             group = currentPage.get(0);
        }
        return group;
    }

    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    public static final class ConverterImpl implements Converter {

        public boolean canConvert(Class type) {
            return type == AzureSecurityRealm.class;
        }

        @Override
        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {

            AzureSecurityRealm realm = (AzureSecurityRealm) source;

            writer.startNode(CONVERTER_NODE_CLIENT_ID);
            writer.setValue(realm.getClientIdSecret());
            writer.endNode();

            writer.startNode(CONVERTER_NODE_CLIENT_SECRET);
            writer.setValue(realm.getClientSecretSecret());
            writer.endNode();

            writer.startNode(CONVERTER_NODE_TENANT);
            writer.setValue(realm.getTenantSecret());
            writer.endNode();

            writer.startNode(CONVERTER_NODE_CACHE_DURATION);
            writer.setValue(String.valueOf(realm.getCacheDuration()));
            writer.endNode();

            writer.startNode(CONVERTER_NODE_FROM_REQUEST);
            writer.setValue(String.valueOf(realm.isFromRequest()));
            writer.endNode();

            writer.startNode(CONVERTER_ENVIRONMENT_NAME);
            writer.setValue(String.valueOf(realm.getAzureEnvironmentName()));
            writer.endNode();

            writer.startNode(CONVERTER_DISABLE_GRAPH_INTEGRATION);
            writer.setValue(String.valueOf(realm.isDisableGraphIntegration()));
            writer.endNode();
        }

        @Override
        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
            AzureSecurityRealm realm = new AzureSecurityRealm();
            while (reader.hasMoreChildren()) {
                reader.moveDown();
                String node = reader.getNodeName();
                String value = reader.getValue();
                switch (node) {
                    case CONVERTER_NODE_CLIENT_ID:
                        realm.setClientId(value);
                        break;
                    case CONVERTER_NODE_CLIENT_SECRET:
                        realm.setClientSecret(value);
                        break;
                    case CONVERTER_NODE_TENANT:
                        realm.setTenant(value);
                        break;
                    case CONVERTER_NODE_CACHE_DURATION:
                        realm.setCacheDuration(Integer.parseInt(value));
                        break;
                    case CONVERTER_NODE_FROM_REQUEST:
                        realm.setFromRequest(Boolean.parseBoolean(value));
                        break;
                    case CONVERTER_ENVIRONMENT_NAME:
                        realm.setAzureEnvironmentName(value);
                        break;
                    case CONVERTER_DISABLE_GRAPH_INTEGRATION:
                        realm.setDisableGraphIntegration(Boolean.parseBoolean(value));
                        break;
                    default:
                        break;
                }
                reader.moveUp();
            }
            Cache<String, AzureAdUser> caches = Caffeine.newBuilder()
                    .expireAfterWrite(realm.getCacheDuration(), TimeUnit.SECONDS)
                    .build();
            realm.setCaches(caches);
            return realm;
        }

    }

    @Extension
    public static final class CrumbExempt extends CrumbExclusion {

        @Override
        public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            String pathInfo = request.getPathInfo();
            if (pathInfo != null && pathInfo.equals(CALLBACK_URL)) {
                chain.doFilter(request, response);
                return true;
            }
            return false;
        }
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        @Override
        @NonNull
        public String getDisplayName() {
            return "Azure Active Directory";
        }

        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
            super(clazz);
        }


        public ListBoxModel doFillAzureEnvironmentNameItems() {
            ListBoxModel model = new ListBoxModel();

            model.add(AZURE_PUBLIC_CLOUD);
            model.add(AZURE_CHINA);
            model.add(AZURE_GERMANY);
            model.add(AZURE_US_GOVERNMENT_L4);
            model.add(AZURE_US_GOVERNMENT_L5);
            return model;
        }

        public FormValidation doVerifyConfiguration(@QueryParameter final String clientId,
                                                    @QueryParameter final Secret clientSecret,
                                                    @QueryParameter final String tenant,
                                                    @QueryParameter final String testObject,
                                                    @QueryParameter final String azureEnvironmentName) {
            if (testObject.equals("")) {
                return FormValidation.error("Please set a test user principal name or object ID");
            }

            final ClientSecretCredential clientSecretCredential = new ClientSecretCredentialBuilder()
                    .clientId(clientId)
                    .clientSecret(clientSecret.getPlainText())
                    .tenantId(tenant)
                    .httpClient(HttpClientRetriever.get())
                    .authorityHost(getAuthorityHost(azureEnvironmentName))
                    .build();

            final TokenCredentialAuthProvider authProvider = new TokenCredentialAuthProvider(clientSecretCredential);

            OkHttpClient.Builder builder = HttpClients.createDefault(authProvider)
                    .newBuilder();

            builder = addProxyToHttpClientIfRequired(builder);
            OkHttpClient httpClient = builder.build();

            GraphServiceClient<Request> graphServiceClient = GraphServiceClient
                    .builder()
                    .httpClient(httpClient)
                    .buildClient();
            try {
                com.microsoft.graph.models.User user = graphServiceClient.users(testObject).buildRequest().get();

                return FormValidation.ok("Successfully verified, found display name: " + user.displayName);
            } catch (Exception ex) {
                return FormValidation.error(ex, ex.getMessage());
            }
        }
    }

    private String generateDescription(Authentication auth) {
        if (auth instanceof AzureAuthenticationToken) {
            AzureAdUser user = ((AzureAuthenticationToken) auth).getAzureAdUser();
            return "Azure Active Directory User\n"
                    + "\nUnique Principal Name: " + user.getUniqueName()
                    + "\nEmail: " + user.getEmail()
                    + "\nObject ID: " + user.getObjectID()
                    + "\nTenant ID: " + user.getTenantID()
                    + "\nGroups: " + user.getGroupOIDs() + "\n";
        }
        return "";
    }

}
