/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.common.base.Suppliers;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableMap;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.credentials.AzureTokenCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.graphrbac.ActiveDirectoryGroup;
import com.microsoft.azure.management.graphrbac.ActiveDirectoryUser;
import com.microsoft.jenkins.azuread.scribe.AzureApi;
import com.microsoft.jenkins.azuread.scribe.AzureOAuthService;
import com.microsoft.jenkins.azurecommons.core.AzureClientFactory;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException2;
import hudson.security.csrf.CrumbExclusion;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

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

    private Cache<String, AzureAdUser> caches;

    private Secret clientId;
    private Secret clientSecret;
    private Secret tenant;
    private int cacheDuration;
    private boolean fromRequest = false;

    private final Supplier<Azure.Authenticated> cachedAzureClient = Suppliers.memoize(() -> Azure.configure()
            .withUserAgent(AzureClientFactory.getUserAgent("AzureJenkinsAd",
                    AzureSecurityRealm.class.getPackage().getImplementationVersion()))
            .authenticate(new ApplicationTokenCredentials(
                    getClientId(),
                    getTenant(),
                    getClientSecret().getPlainText(),
                    AzureEnvironment.AZURE)));

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

    public String getClientId() {
        return clientId.getPlainText();
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
                .build(AzureApi.instance(Constants.DEFAULT_GRAPH_ENDPOINT, this.getTenant()));
    }

    Azure.Authenticated getAzureClient() {
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
        caches = CacheBuilder.newBuilder()
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
        return new HttpRedirect(service.getAuthorizationUrl(ImmutableMap.of(
                "nonce", nonce,
                "response_mode", "form_post")));
    }

    public HttpResponse doFinishLogin(StaplerRequest request)
            throws InvalidJwtException, MalformedClaimException, ExecutionException {
        try {
            final Long beginTime = (Long) request.getSession().getAttribute(TIMESTAMP_ATTRIBUTE);
            final String expectedNonce = (String) request.getSession().getAttribute(NONCE_ATTRIBUTE);
            if (beginTime != null) {
                long endTime = System.currentTimeMillis();
                LOGGER.info("Requesting oauth code time = " + (endTime - beginTime) + " ms");
            }

            final String idToken = request.getParameter("id_token");

            if (StringUtils.isBlank(idToken)) {
                throw new IllegalStateException("Can't extract id_token");
            }
            // validate the nonce to avoid CSRF
            final JwtClaims claims = validateIdToken(expectedNonce, idToken);
            String key = (String) claims.getClaimValue("preferred_username");

            AzureAdUser userDetails = caches.get(key, () -> {
                final AzureAdUser user = AzureAdUser.createFromJwt(claims);
                final Collection<ActiveDirectoryGroup> groups = AzureCachePool.get(getAzureClient())
                        .getBelongingGroupsByOid(user.getObjectID());
                user.setAuthorities(groups);
                LOGGER.info(String.format("Fetch user details with sub: %s***",
                        key.substring(0, CACHE_KEY_LOG_LENGTH)));
                return user;
            });
            final AzureAuthenticationToken auth = new AzureAuthenticationToken(userDetails);

            // Enforce updating current identity
            SecurityContextHolder.getContext().setAuthentication(auth);
            User u = User.current();
            if (u != null) {
                String description = generateDescription(auth);
                u.setDescription(description);
                u.setFullName(auth.getAzureAdUser().getName());
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
            throw new IllegalStateException("Invalid nonce in the response");
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
        return getOAuthService().getLogoutUrl();
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents((AuthenticationManager) authentication -> {
            if (authentication instanceof AzureAuthenticationToken) {
                return authentication;
            }
            throw new IllegalStateException("Unexpected authentication type: " + authentication);
        }, username -> {
            try {
                return caches.get(username, () -> {
                    Azure.Authenticated azureClient = getAzureClient();
                    ActiveDirectoryUser activeDirectoryUser;
                    final String userId = ObjId2FullSidMap.extractObjectId(username);
                    if (userId != null) {
                        activeDirectoryUser = azureClient.activeDirectoryUsers().getById(userId);
                    } else {
                        activeDirectoryUser = azureClient.activeDirectoryUsers().getByName(username);
                    }

                    AzureAdUser user = AzureAdUser.createFromActiveDirectoryUser(activeDirectoryUser);
                    if (user == null) {
                        throw new UserMayOrMayNotExistException2("Cannot find user " + username);
                    }
                    Collection<ActiveDirectoryGroup> groups = AzureCachePool.get(azureClient)
                            .getBelongingGroupsByOid(user.getObjectID());

                    user.setAuthorities(groups);
                    return user;
                });
            } catch (UncheckedExecutionException e) {
                if (e.getCause() instanceof UserMayOrMayNotExistException2) {
                    throw (UserMayOrMayNotExistException2) e.getCause();
                }
                throw e;
            } catch (ExecutionException e) {
                LOGGER.log(Level.SEVERE, "error", e);
                throw new UsernameNotFoundException("Cannot find user " + username, e);
            }

        });
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public GroupDetails loadGroupByGroupname2(String groupName, boolean fetchMembers) {
        throw new UsernameNotFoundException("groups not supported");
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
                    default:
                        break;
                }
                reader.moveUp();
            }
            Cache<String, AzureAdUser> caches = CacheBuilder.newBuilder()
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
        public String getDisplayName() {
            return "Azure Active Directory";
        }

        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
            super(clazz);
        }

        public FormValidation doVerifyConfiguration(@QueryParameter final String clientId,
                                                    @QueryParameter final Secret clientSecret,
                                                    @QueryParameter final String tenant)
                throws IOException, ExecutionException {


            AzureTokenCredentials credential = new ApplicationTokenCredentials(clientId,
                    tenant,
                    clientSecret.getPlainText(),
                    AzureEnvironment.AZURE);
            try {
                Azure.authenticate(credential).subscriptions().list();
            } catch (Exception ex) {
                return FormValidation.error(ex.getMessage());
            }

            return FormValidation.ok("Successfully verified");
        }
    }

    private String generateDescription(Authentication auth) {
        if (auth instanceof AzureAuthenticationToken) {
            AzureAdUser user = ((AzureAuthenticationToken) auth).getAzureAdUser();
            return "Azure Active Directory User\n"
                    + "\nGiven Name: " + user.getGivenName()
                    + "\nFamily Name: " + user.getFamilyName()
                    + "\nUnique Principal Name: " + user.getUniqueName()
                    + "\nEmail: " + user.getEmail()
                    + "\nObject ID: " + user.getObjectID()
                    + "\nTenant ID: " + user.getTenantID()
                    + "\nGroups: " + user.getGroupOIDs() + "\n";
        }
        return "";
    }

}
