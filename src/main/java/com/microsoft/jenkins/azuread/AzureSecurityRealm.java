/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.common.collect.ImmutableMap;
import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.credentials.AzureTokenCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.graphrbac.ActiveDirectoryGroup;
import com.microsoft.jenkins.azuread.scribe.AzureApi;
import com.microsoft.jenkins.azuread.scribe.AzureOAuthService;
import com.microsoft.jenkins.azurecommons.core.AzureClientFactory;
import com.microsoft.jenkins.azurecommons.telemetry.AppInsightsUtils;
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
import hudson.security.UserMayOrMayNotExistException;
import hudson.security.csrf.CrumbExclusion;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AzureSecurityRealm extends SecurityRealm {

    private static final String REFERER_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".referer";
    private static final String TIMESTAMP_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".beginTime";
    private static final String NONCE_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".nonce";
    private static final Logger LOGGER = Logger.getLogger(AzureSecurityRealm.class.getName());
    private static final int NONCE_LENGTH = 10;
    public static final String CALLBACK_URL = "/securityRealm/finishLogin";

    private Secret clientId;
    private Secret clientSecret;
    private Secret tenant;
    private Supplier<Azure.Authenticated> cachedAzureClient = Suppliers.memoize(new Supplier<Azure.Authenticated>() {
        @Override
        public Azure.Authenticated get() {
            return Azure.configure()
                    .withInterceptor(new AzureAdPlugin.AzureTelemetryInterceptor())
                    .withUserAgent(AzureClientFactory.getUserAgent(AzureAdPlugin.AI_PLUGIN_NAME,
                            AzureAdPlugin.class.getPackage().getImplementationVersion()))
                    .authenticate(new ApplicationTokenCredentials(
                            getClientId(),
                            getTenant(),
                            getClientSecret(),
                            AzureEnvironment.AZURE));
        }
    });
    private Supplier<JwtConsumer> jwtConsumer = Suppliers.memoize(new Supplier<JwtConsumer>() {
        @Override
        public JwtConsumer get() {
            return Utils.JwtUtil.jwt(getClientId(), getTenant());
        }
    });

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

    public String getClientSecret() {
        return clientSecret.getPlainText();
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

    public JwtConsumer getJwtConsumer() {
        return jwtConsumer.get();
    }

    AzureOAuthService getOAuthService() {
        AzureOAuthService service = (AzureOAuthService) new ServiceBuilder(clientId.getPlainText())
                .apiSecret(clientSecret.getPlainText())
                .responseType("id_token")
                .scope("openid profile email")
                .callback(getRootUrl() + CALLBACK_URL)
                .build(AzureApi.instance(Constants.DEFAULT_GRAPH_ENDPOINT, this.getTenant()));
        return service;
    }

    Azure.Authenticated getAzureClient() {
        return cachedAzureClient.get();
    }


    private String getRootUrl() {
        Jenkins jenkins = Jenkins.getInstance();
        return StringUtils.stripEnd(jenkins.getRootUrl(), "/");
    }

    @DataBoundConstructor
    public AzureSecurityRealm(String tenant, String clientId, String clientSecret)
            throws ExecutionException, IOException, InterruptedException {
        super();
        this.clientId = Secret.fromString(clientId);
        this.clientSecret = Secret.fromString(clientSecret);
        this.tenant = Secret.fromString(tenant);
    }


    public AzureSecurityRealm() {
        super();
        LOGGER.log(Level.FINE, "AzureSecurityRealm()");
    }

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

    public HttpResponse doFinishLogin(StaplerRequest request) throws InvalidJwtException, MalformedClaimException {
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
            final AzureAdUser userDetails = validateAndParseIdToken(expectedNonce, idToken);
            final AzureAuthenticationToken auth = new AzureAuthenticationToken(userDetails);

            // Enforce updating current identity
            SecurityContextHolder.getContext().setAuthentication(auth);
            User u = User.current();
            if (u != null) {
                String description = generateDescription(auth);
                u.setDescription(description);
                u.setFullName(auth.getAzureAdUser().getName());
            }
            SecurityListener.fireAuthenticated(userDetails);
            AzureAdPlugin.sendLoginEvent(
                    AppInsightsUtils.hash(userDetails.getObjectID()),
                    AppInsightsUtils.hash(this.getTenant()));
        } catch (Exception ex) {
            AzureAdPlugin.sendLoginFailEvent(this.getTenant(), ex.getMessage());
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

    AzureAdUser validateAndParseIdToken(String expectedNonce, String idToken)
        throws InvalidJwtException, MalformedClaimException {
        JwtClaims claims = getJwtConsumer().processToClaims(idToken);
        final String responseNonce = (String) claims.getClaimValue("nonce");
        if (StringUtils.isAnyEmpty(expectedNonce, responseNonce) || !expectedNonce.equals(responseNonce)) {
            throw new IllegalStateException("Invalid nonce in the response");
        }
        final AzureAdUser userDetails = AzureAdUser.createFromJwt(claims);
        final Collection<ActiveDirectoryGroup> groups = AzureCachePool.get(getAzureClient())
                .getBelongingGroupsByOid(userDetails.getObjectID());
        userDetails.setAuthorities(groups);
        return userDetails;
    }

    @Override
    protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
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
        return new SecurityComponents(new AuthenticationManager() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof AzureAuthenticationToken) {
                    return authentication;
                }
                throw new IllegalStateException("Unexpected authentication type: " + authentication);
            }
        }, new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username)
                    throws UsernameNotFoundException, DataAccessException {
                throw new UserMayOrMayNotExistException("Cannot verify users in this context");
            }
        });
    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupName) {
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

            writer.startNode("clientid");
            writer.setValue(realm.getClientIdSecret());
            writer.endNode();

            writer.startNode("clientsecret");
            writer.setValue(realm.getClientSecretSecret());
            writer.endNode();

            writer.startNode("tenant");
            writer.setValue(realm.getTenantSecret());
            writer.endNode();
        }

        @Override
        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
            AzureSecurityRealm realm = new AzureSecurityRealm();
            while (reader.hasMoreChildren()) {
                reader.moveDown();
                String node = reader.getNodeName();
                String value = reader.getValue();
                if (node.equals("clientid")) {
                    realm.setClientId(value);
                } else if (node.equals("clientsecret")) {
                    realm.setClientSecret(value);
                } else if (node.equals("tenant")) {
                    realm.setTenant(value);
                }
                reader.moveUp();
            }
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
                                                    @QueryParameter final String clientSecret,
                                                    @QueryParameter final String tenant)
                throws IOException, ExecutionException {


            AzureTokenCredentials credential = new ApplicationTokenCredentials(clientId,
                    tenant,
                    clientSecret,
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
