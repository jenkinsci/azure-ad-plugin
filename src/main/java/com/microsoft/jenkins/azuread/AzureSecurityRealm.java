/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenRequestContext;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.ClientCertificateCredential;
import com.azure.identity.ClientCertificateCredentialBuilder;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.microsoft.graph.http.GraphServiceException;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.models.ProfilePhoto;
import com.microsoft.graph.options.Option;
import com.microsoft.graph.options.QueryOption;
import com.microsoft.graph.requests.GraphServiceClient;
import com.microsoft.graph.requests.GroupCollectionPage;
import com.microsoft.graph.requests.ProfilePhotoRequestBuilder;
import com.microsoft.jenkins.azuread.avatar.EntraAvatarProperty;
import com.microsoft.jenkins.azuread.oauth.StateCache;
import com.microsoft.jenkins.azuread.scribe.AzureAdApi;
import com.microsoft.jenkins.azuread.utils.UUIDValidator;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
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

import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import jakarta.servlet.http.HttpSession;

import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import jenkins.util.SystemProperties;
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
import org.kohsuke.stapler.StaplerRequest2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static com.microsoft.jenkins.azuread.AzureEnvironment.AZURE_CHINA;
import static com.microsoft.jenkins.azuread.AzureEnvironment.AZURE_PUBLIC_CLOUD;
import static com.microsoft.jenkins.azuread.AzureEnvironment.AZURE_US_GOVERNMENT_L4;
import static com.microsoft.jenkins.azuread.AzureEnvironment.AZURE_US_GOVERNMENT_L5;
import static com.microsoft.jenkins.azuread.AzureEnvironment.getAuthorityHost;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;

public class AzureSecurityRealm extends SecurityRealm {

    public static final String REFERER_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".referer";
    public static final String TIMESTAMP_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".beginTime";
    public static final String NONCE_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".nonce";
    private static final Logger LOGGER = Logger.getLogger(AzureSecurityRealm.class.getName());
    private static final int NONCE_LENGTH = 16;
    public static final String CALLBACK_URL = "/securityRealm/finishLogin";
    private static final String CONVERTER_NODE_CLIENT_ID = "clientid";
    private static final String CONVERTER_NODE_CLIENT_SECRET = "clientsecret";
    private static final String CONVERTER_NODE_CLIENT_CERTIFICATE = "clientCertificate";
    private static final String CONVERTER_NODE_CREDENTIAL_TYPE = "credentialType";
    private static final String CONVERTER_NODE_TENANT = "tenant";
    private static final String CONVERTER_NODE_CACHE_DURATION = "cacheduration";
    private static final String CONVERTER_NODE_FROM_REQUEST = "fromrequest";
    private static final int CACHE_KEY_LOG_LENGTH = 8;
    private static final int NOT_FOUND = 404;
    private static final int BAD_REQUEST = 400;
    public static final String CONVERTER_DISABLE_GRAPH_INTEGRATION = "disableGraphIntegration";
    public static final String CONVERTER_SINGLE_LOGOUT = "singleLogout";
    public static final String CONVERTER_PROMPT_ACCOUNT = "promptAccount";
    public static final String CONVERTER_DOMAIN_HINT = "domainHint";

    public static final String CONVERTER_ENVIRONMENT_NAME = "environmentName";

    private Cache<String, AzureAdUser> caches;

    private Secret clientId;
    private Secret clientSecret;
    private Secret clientCertificate;
    private Secret tenant;
    private int cacheDuration;
    private boolean fromRequest = false;
    private boolean promptAccount;
    private boolean singleLogout;
    private boolean disableGraphIntegration;
    private String azureEnvironmentName = "Azure";
    private String credentialType = "Secret";
    private String domainHint = "";

    public AccessToken getAccessToken() {
        TokenRequestContext tokenRequestContext = new TokenRequestContext();
        String graphResource = AzureEnvironment.getGraphResource(getAzureEnvironmentName());
        tokenRequestContext.setScopes(singletonList(graphResource + ".default"));

        AccessToken accessToken = ("Certificate".equals(credentialType) ? getClientCertificateCredential() : getClientSecretCredential())
                .getToken(tokenRequestContext)
                .block();

        if (accessToken == null) {
            throw new IllegalStateException("Access token null when it is required");
        }

        return accessToken;
    }

    InputStream getCertificate() {

        String secretString = clientCertificate.getPlainText();

        return new ByteArrayInputStream(secretString.getBytes(StandardCharsets.UTF_8));
    }

    ClientSecretCredential getClientSecretCredential() {
        String azureEnv = getAzureEnvironmentName();
        return new ClientSecretCredentialBuilder()
                .clientId(clientId.getPlainText())
                .clientSecret(clientSecret.getPlainText())
                .tenantId(tenant.getPlainText())
                .authorityHost(getAuthorityHost(azureEnv))
                .httpClient(HttpClientRetriever.get())
                .build();
    }

    ClientCertificateCredential getClientCertificateCredential() {
        String azureEnv = getAzureEnvironmentName();
        return new ClientCertificateCredentialBuilder()
                .clientId(clientId.getPlainText())
                .pemCertificate(getCertificate())
                .tenantId(tenant.getPlainText())
                .sendCertificateChain(true)
                .authorityHost(getAuthorityHost(azureEnv))
                .httpClient(HttpClientRetriever.get())
                .build();
    }

    public boolean isPromptAccount() {
        return promptAccount;
    }

    @DataBoundSetter
    public void setPromptAccount(boolean promptAccount) {
        this.promptAccount = promptAccount;
    }

    public String getDomainHint() {
        return domainHint;
    }

    @DataBoundSetter
    public void setDomainHint(String domainHint) {
        this.domainHint = domainHint;
    }

    public boolean isSingleLogout() {
        return singleLogout;
    }

    @DataBoundSetter
    public void setSingleLogout(boolean singleLogout) {
        this.singleLogout = singleLogout;
    }

    private final Supplier<JwtConsumer> jwtConsumer = Suppliers.memoize(() ->
            Utils.JwtUtil.jwt(getAuthorityHost(getAzureEnvironmentName()), getClientId(), getTenant()));

    public String getClientIdSecret() {
        return clientId.getEncryptedValue();
    }

    public String getClientSecretSecret() {
        return clientSecret.getEncryptedValue();
    }

    public String getClientCertificateSecret() {
        return clientCertificate.getEncryptedValue();
    }

    public String getCredentialType() {
        return credentialType;
    }

    public String getTenantSecret() {
        return tenant.getEncryptedValue();
    }

    String getCredentialCacheKey() {
        String credentialComponent = clientId.getPlainText()
                + ("Certificate".equals(credentialType) ? clientCertificate.getPlainText() : clientSecret.getPlainText())
                + tenant.getPlainText()
                + azureEnvironmentName;

        return Util.getDigestOf(credentialComponent);
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

    @DataBoundSetter
    public void setCredentialType(String credentialType) {
        this.credentialType = credentialType;
    }

    public void setClientId(String clientId) {
        this.clientId = Secret.fromString(clientId);
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    public Secret getClientCertificate() {
        return clientCertificate;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = Secret.fromString(clientSecret);
    }

    @DataBoundSetter
    public void setClientCertificate(String clientCertificate) {
        this.clientCertificate = Secret.fromString(clientCertificate);
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

    OAuth20Service getOAuthService() {
        return new ServiceBuilder(clientId.getPlainText())
                .apiSecret("Certificate".equals(credentialType) ? clientCertificate.getPlainText() : clientSecret.getPlainText())
                .responseType("id_token")
                .defaultScope("openid profile email")
                .callback(getRootUrl() + CALLBACK_URL)
                .build(AzureAdApi.custom(getTenant(), getAuthorityHost(getAzureEnvironmentName())));
    }

    GraphServiceClient<Request> getAzureClient() {
        return GraphClientCache.getClient(this);
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
    public HttpResponse doCommenceLogin(StaplerRequest2 request, @Header("Referer") final String referer) {
        String trimmedReferrer = getReferer(referer);

        recreateSession(request);
        request.getSession().setAttribute(REFERER_ATTRIBUTE, trimmedReferrer);
        OAuth20Service service = getOAuthService();
        request.getSession().setAttribute(TIMESTAMP_ATTRIBUTE, System.currentTimeMillis());
        String nonce = RandomStringUtils.secure().nextAlphanumeric(NONCE_LENGTH);
        request.getSession().setAttribute(NONCE_ATTRIBUTE, nonce);

        String state = new StateCache().generateValue(request.getSession());

        Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put("nonce", nonce);
        additionalParams.put("response_mode", "form_post");
        additionalParams.put("state", state);
        if (promptAccount) {
            additionalParams.put("prompt", "select_account");
        }
        if (!StringUtils.isBlank(domainHint)) {
            additionalParams.put("domain_hint", domainHint);
        }

        return new HttpRedirect(service.getAuthorizationUrl(additionalParams));
    }

    /**
     * Logged out page shows a login button which just sends you back to the logged out page
     * which is a bit silly, so we override it to send you to the root page.
     */
    private static String getReferer(String referer) {
        String trimmedReferrer = referer;
        if (referer != null && referer.endsWith("azureAdLogout/")) {
            trimmedReferrer = referer.replace("azureAdLogout/", "");
        }
        return trimmedReferrer;
    }

    /**
     * Check if a request contains a session, if so, invalidate the session and create a new one to avoid session
     * fixation.
     */
    private void recreateSession(StaplerRequest2 request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        request.getSession(true);
    }


    public HttpResponse doFinishLogin(StaplerRequest2 request)
            throws InvalidJwtException, IOException {
        recreateSession(request);
        String state = request.getParameter("state");
        StateCache.CacheHolder cachedStateValue = StateCache.CACHE.getIfPresent(state);
        if (cachedStateValue == null || cachedStateValue.nonce() == null) {
            // no nonce, probably some issue with an old session, force the user to re-auth
            return HttpResponses.redirectToContextRoot();
        }
        String referer = cachedStateValue.referrer();
        try {
            final Long beginTime = cachedStateValue.beginTime();
            final String expectedNonce = cachedStateValue.nonce();

            long endTime = System.currentTimeMillis();
            LOGGER.info("Requesting oauth code time = " + (endTime - beginTime) + " ms");

            final String idToken = request.getParameter("id_token");

            if (StringUtils.isBlank(idToken)) {
                LOGGER.info("No `id_token` found ensure you have enabled it on the 'Authentication' page of the "
                        + "app registration");
                return HttpResponses.redirectToContextRoot();
            }
            // validate the nonce to avoid CSRF
            final JwtClaims claims = validateIdToken(expectedNonce, idToken);
            String key = (String) claims.getClaimValue("oid");

            AzureAdUser userDetails = caches.get(key, (cacheKey) -> {
                final AzureAdUser user;
                user = AzureAdUser.createFromJwt(claims);

                List<AzureAdGroup> groups = emptyList();
                if (!isDisableGraphIntegration()) {
                    groups = AzureCachePool.get(getAzureClient())
                            .getBelongingGroupsByOid(user.getObjectID());
                }
                user.setAuthorities(groups, user.getUniqueName());
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
            User currentUser = User.current();
            updateIdentity(auth.getAzureAdUser(), currentUser);

            SecurityListener.fireAuthenticated2(userDetails);

            if (!isDisableGraphIntegration()) {
                updateAvatar(userDetails, currentUser);
            }
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "error", ex);
            throw ex;
        }

        if (referer != null) {
            return HttpResponses.redirectTo(referer);
        } else {
            return HttpResponses.redirectToContextRoot();
        }
    }

    private void updateAvatar(AzureAdUser userDetails, User currentUser) {
        if (currentUser == null) {
            return;
        }
        try {
            if (SystemProperties.getBoolean(AzureSecurityRealm.class.getName() + ".disableAvatar",  false)) {
                return;
            }
            ProfilePhotoRequestBuilder photosRequestBuilder = getAzureClient()
                    .users(userDetails.getObjectID()).photos("48x48");
            LOGGER.finest("Fetching avatar metadata");
            ProfilePhoto profilePhoto = photosRequestBuilder.buildRequest().get();
            LOGGER.finest("Completed fetching avatar metadata");
            if (profilePhoto != null) {
                LOGGER.finest("Fetching avatar");
                try (InputStream inputStream = photosRequestBuilder.content().buildRequest().get()) {
                    if (inputStream != null) {
                        String mediaContentType = profilePhoto.additionalDataManager().get("@odata.mediaContentType")
                                .getAsString();
                        EntraAvatarProperty.AvatarImage avatarImage = new EntraAvatarProperty.AvatarImage(
                                mediaContentType
                        );
                        EntraAvatarProperty entraAvatarProperty = new EntraAvatarProperty(avatarImage);
                        File targetFile = new File(currentUser.getUserFolder(), "entra-avatar." + avatarImage.getFilenameSuffix());

                        Files.copy(
                                inputStream,
                                targetFile.toPath(),
                                StandardCopyOption.REPLACE_EXISTING);
                        currentUser.addProperty(entraAvatarProperty);
                        LOGGER.finest("Saved avatar");
                    }

                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Failed to save profile photo for %s".formatted(currentUser.getId()), e);
                }
            } else {
                LOGGER.finest("No avatar found");
            }
        } catch (GraphServiceException e) {
            LOGGER.log(e.getResponseCode() == 404 ? Level.FINER : Level.WARNING, "Failed to get profile photo for %s".formatted(currentUser.getId()), e);
        }
    }

    JwtClaims validateIdToken(String expectedNonce, String idToken) throws InvalidJwtException {
        JwtClaims claims = getJwtConsumer().processToClaims(idToken);
        final String responseNonce = (String) claims.getClaimValue("nonce");
        if (StringUtils.isAnyEmpty(expectedNonce, responseNonce) ||
                !MessageDigest.isEqual(
                        expectedNonce.getBytes(StandardCharsets.UTF_8),
                        responseNonce.getBytes(StandardCharsets.UTF_8)
                )
        ) {
            throw new IllegalStateException(String.format("Invalid nonce in the response, "
                    + "expected: %s actual: %s", expectedNonce, responseNonce));
        }
        return claims;
    }

    @Override
    protected String getPostLogOutUrl2(StaplerRequest2 req, Authentication auth) {
        if (auth instanceof AzureAuthenticationToken) {
            AzureAuthenticationToken azureToken = (AzureAuthenticationToken) auth;
            String oid = azureToken.getAzureAdUser().getObjectID();
            AzureCachePool.invalidateBelongingGroupsByOid(oid);
        }
        // Ensure single sign-out

        if (singleLogout) {
            return ((AzureAdApi) getOAuthService().getApi()).getLogoutUrl();
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
                    // TODO try https://docs.microsoft.com/en-us/answers/questions/42697/how-to-get-a-particular-azure-ad-guest-user-from-h.html
                    com.microsoft.graph.models.User activeDirectoryUser = azureClient.users(userId).buildRequest()
                            .get();

                    if (activeDirectoryUser != null & activeDirectoryUser.id == null) {
                        // known to happen when subject is a group with display name only and starts with a #
                        return null;
                    }

                    AzureAdUser user = requireNonNull(AzureAdUser.createFromActiveDirectoryUser(activeDirectoryUser));
                    List<AzureAdGroup> groups = AzureCachePool.get(azureClient)
                            .getBelongingGroupsByOid(user.getObjectID());

                    user.setAuthorities(groups, user.getUniqueName());

                    // Enforce updating added identity
                    updateIdentity(user, User.getById(user.getObjectID(), true));

                    return user;
                } catch (GraphServiceException e) {
                    if (e.getResponseCode() == NOT_FOUND) {
                        return null;
                    } else if (e.getResponseCode() == BAD_REQUEST) {
                        if (LOGGER.isLoggable(Level.FINE)) {
                            LOGGER.log(Level.FINE, "Failed to lookup user with userid '" + userId, e);
                        } else {
                            LOGGER.log(Level.WARNING, "Failed to lookup user with userid '" + userId + "'."
                                    + " Enable 'Fine' Logging for more information.");
                        }
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
            // just an object id on its own?
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

        String query = String.format("displayName eq '%s'", encodedGroupName);

        requestOptions.add(new QueryOption("$filter", query));

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

            writer.startNode(CONVERTER_NODE_CREDENTIAL_TYPE);
            writer.setValue(realm.getCredentialType());
            writer.endNode();

            if ("Secret".equals(realm.getCredentialType())) {
                writer.startNode(CONVERTER_NODE_CLIENT_SECRET);
                writer.setValue(realm.getClientSecretSecret());
                writer.endNode();
            } else {
                writer.startNode(CONVERTER_NODE_CLIENT_CERTIFICATE);
                writer.setValue(realm.getClientCertificateSecret());
                writer.endNode();
            }

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

            writer.startNode(CONVERTER_PROMPT_ACCOUNT);
            writer.setValue(String.valueOf(realm.isPromptAccount()));
            writer.endNode();

            writer.startNode(CONVERTER_SINGLE_LOGOUT);
            writer.setValue(String.valueOf(realm.isSingleLogout()));
            writer.endNode();

            writer.startNode(CONVERTER_DOMAIN_HINT);
            writer.setValue(String.valueOf(realm.getDomainHint()));
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
                    case CONVERTER_NODE_CLIENT_CERTIFICATE:
                        realm.setClientCertificate(value);
                        break;
                    case CONVERTER_NODE_CREDENTIAL_TYPE:
                        realm.setCredentialType(value);
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
                    case CONVERTER_PROMPT_ACCOUNT:
                        realm.setPromptAccount(Boolean.parseBoolean(value));
                        break;
                    case CONVERTER_SINGLE_LOGOUT:
                        realm.setSingleLogout(Boolean.parseBoolean(value));
                        break;
                    case CONVERTER_DOMAIN_HINT:
                        realm.setDomainHint(value);
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
            model.add(AZURE_US_GOVERNMENT_L4);
            model.add(AZURE_US_GOVERNMENT_L5);
            return model;
        }

        public FormValidation doVerifyConfiguration(@QueryParameter final String clientId,
                                                    @QueryParameter final Secret clientSecret,
                                                    @QueryParameter final Secret clientCertificate,
                                                    @QueryParameter final String credentialType,
                                                    @QueryParameter final String tenant,
                                                    @QueryParameter final String testObject,
                                                    @QueryParameter final String azureEnvironmentName) {
            switch (credentialType) {
                case "Secret":
                    if (Secret.toString(clientSecret).isEmpty()) {
                        return FormValidation.error("Please set a secret");
                    }
                    break;
                case "Certificate":
                    if (Secret.toString(clientCertificate).isEmpty()) {
                        return FormValidation.error("Please set a certificate");
                    }
                    break;
                default:
                    return FormValidation.error("Invalid credential type");
            }

            if (testObject.isEmpty()) {
                return FormValidation.error("Please set a test user principal name or object ID");
            }

            GraphServiceClient<Request> graphServiceClient = GraphClientCache.getClient(
                    new GraphClientCacheKey(
                            clientId,
                            Secret.toString(clientSecret),
                            Secret.toString(clientCertificate),
                            credentialType,
                            tenant,
                            azureEnvironmentName
                    )
            );
            try {
                com.microsoft.graph.models.User user = graphServiceClient.users(testObject).buildRequest().get();

                return FormValidation.ok("Successfully verified, found display name: " + user.displayName);
            } catch (Exception ex) {
                return FormValidation.error(ex, ex.getMessage());
            }
        }
    }

    private void updateIdentity(final AzureAdUser azureAdUser, final User u) {
        if (azureAdUser != null && u != null) {
            try {
                String description = generateDescription(azureAdUser);
                u.setDescription(description);
                u.setFullName(azureAdUser.getName());
                if (StringUtils.isNotBlank(azureAdUser.getEmail())) {
                    UserProperty existing = u.getProperty(UserProperty.class);
                    if (existing == null || !existing.hasExplicitlyConfiguredAddress()) {
                        u.addProperty(new Mailer.UserProperty(azureAdUser.getEmail()));
                    }
                }
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to update user mail with userid: " + azureAdUser.getObjectID(), e);
            }
        }
    }

    private String generateDescription(AzureAdUser user) {
        return "Azure Active Directory User\n"
                + "\nUnique Principal Name: " + user.getUniqueName()
                + "\nEmail: " + user.getEmail()
                + "\nObject ID: " + user.getObjectID()
                + "\nTenant ID: " + user.getTenantID();
    }

}
