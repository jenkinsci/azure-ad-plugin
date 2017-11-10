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
import com.microsoft.jenkins.azuread.scribe.AzureApi;
import com.microsoft.jenkins.azuread.scribe.AzureOAuthService;
import com.microsoft.jenkins.azuread.scribe.AzureToken;
import com.thoughtworks.xstream.converters.ConversionException;
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
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;

import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AzureSecurityRealm extends SecurityRealm {

    private static final String REFERER_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".referer";
    private static final String TIMESTAMP_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".beginTime";
    private static final Logger LOGGER = Logger.getLogger(AzureSecurityRealm.class.getName());
    private Secret clientId;
    private Secret clientSecret;
    private Secret tenant;
    private Supplier<Azure.Authenticated> cachedAzureClient = Suppliers.memoize(new Supplier<Azure.Authenticated>() {
        @Override
        public Azure.Authenticated get() {
            return Azure.authenticate(new ApplicationTokenCredentials(
                    getClientId(),
                    getTenant(),
                    getClientSecret(),
                    AzureEnvironment.AZURE));
        }
    });
    // TODO: replace with azure credential

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

    AzureOAuthService getOAuthService() {
        AzureOAuthService service = (AzureOAuthService) new ServiceBuilder(clientId.getPlainText())
                .apiSecret(clientSecret.getPlainText())
                .responseType("id_token")
                .scope("openid")
                .callback(getRootUrl() + "/securityRealm/finishLogin")
                .build(AzureApi.instance(Constants.DEFAULT_GRAPH_ENDPOINT, this.getTenant()));
        return service;
    }

    Azure.Authenticated getAzureClient() throws IOException {
        return cachedAzureClient.get();
    }


    private String getRootUrl() {
        Jenkins jenkins = Jenkins.getActiveInstance();
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


    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer)
            throws IOException {
        request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);
        OAuth20Service service = getOAuthService();
        request.getSession().setAttribute(TIMESTAMP_ATTRIBUTE, System.currentTimeMillis());
        return new HttpRedirect(service.getAuthorizationUrl(ImmutableMap.of(
                "nonce", "random",
                "response_mode", "form_post")));
    }

    public HttpResponse doFinishLogin(StaplerRequest request) throws Exception {
        Long beginTime = (Long) request.getSession().getAttribute(TIMESTAMP_ATTRIBUTE);
        if (beginTime != null) {
            long endTime = System.currentTimeMillis();
            System.out.println("Requesting oauth code time = " + (endTime - beginTime) + " ms");
        }
        final String idToken = request.getParameter("id_token");

        if (StringUtils.isBlank(idToken)) {
            LOGGER.log(Level.SEVERE, "doFinishLogin() idToken = null");
            LOGGER.severe(Utils.JsonUtil.toJson(request.getParameterMap()));
            return HttpResponses.redirectTo(this.getRootUrl() + AzureAuthFailAction.POST_LOGOUT_URL);
        } else {
            final AzureAuthenticationToken auth = new AzureAuthenticationToken(AzureAdUser.createFromJwt(idToken));
            Collection<String> groups = AzureCachePool.getBelongingGroupsByOid(auth.getAzureAdUser().getObjectID());
            GrantedAuthority[] authorities = new GrantedAuthority[groups.size()];
            int i = 0;
            for (String objectId : groups) {
                authorities[i++] = new AzureAdGroup(objectId);
            }
            auth.getAzureAdUser().setAuthorities(authorities);

            SecurityContextHolder.getContext().setAuthentication(auth);
            User u = User.current();
            if (u != null) {
                String description = generateDescription(auth);
                u.setDescription(description);
                u.setFullName(auth.getAzureAdUser().getUsername());
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

    @Override
    protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        // if we just redirect to the root and anonymous does not have Overall read
        // then we will start a login all over again.
        // we are actually anonymous here as the security context has been cleared

        // invalidateBelongingGroupsByOid
        if (auth instanceof AzureAuthenticationToken) {
            AzureAuthenticationToken azureToken = (AzureAuthenticationToken) auth;
            String oid = azureToken.getAzureAdUser().getObjectID();
            AzureCachePool.invalidateBelongingGroupsByOid(oid);
            System.out.println("invalidateBelongingGroupsByOid cache entry when sign out");
        }
        return getOAuthService().getLogoutUrl();
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof AzureToken) {
                    return authentication;
                }
                throw new BadCredentialsException("Unexpected authentication type: " + authentication);
            }
        }, new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username)
                    throws UsernameNotFoundException, DataAccessException {
                throw new UserMayOrMayNotExistException("Cannot verify users in this context");
            }
        });
    }

//    @Override
//    public UserDetails loadUserByUsername(String userName) {
//        UserDetails result = null;
//        Authentication token = SecurityContextHolder.getContext().getAuthentication();
//        if (token == null) {
//            throw new UsernameNotFoundException("AzureAuthenticationToken = null, no known user: " + userName);
//        }
//        if (!(token instanceof AzureAuthenticationToken)) {
//          throw new UserMayOrMayNotExistException("Unexpected authentication type: " + token);
//        }
//        result = service.getUserByUsername(userName);
//        if (result == null) {
//            throw new UsernameNotFoundException("User does not exist for login: " + userName);
//        }
//        return result;
//    }

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

        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {

            AzureSecurityRealm realm = (AzureSecurityRealm) source;

            writer.startNode("clientid");
            writer.setValue(realm.getClientIdSecret());
            writer.endNode();

            writer.startNode("clientsecret");
            writer.setValue(realm.getClientSecret());
            writer.endNode();

            writer.startNode("tenant");
            writer.setValue(realm.getTenantSecret());
            writer.endNode();
        }

        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
            reader.moveDown();
            AzureSecurityRealm realm = new AzureSecurityRealm();
            String node = reader.getNodeName();
            String value = reader.getValue();
            setValue(realm, node, value);
            reader.moveUp();
            reader.moveDown();
            node = reader.getNodeName();
            value = reader.getValue();
            setValue(realm, node, value);
            reader.moveUp();
            //

            reader.moveDown();
            node = reader.getNodeName();
            value = reader.getValue();
            setValue(realm, node, value);
            reader.moveUp();

            if (reader.hasMoreChildren()) {
                reader.moveDown();
                node = reader.getNodeName();
                value = reader.getValue();
                setValue(realm, node, value);
                reader.moveUp();
            }
            return realm;
        }

        private void setValue(AzureSecurityRealm realm, String node, String value) {

            if (node.equalsIgnoreCase("clientid")) {
                realm.setClientId(value);
            } else if (node.equalsIgnoreCase("clientsecret")) {
                realm.setClientSecret(value);
            } else if (node.equalsIgnoreCase("tenant")) {
                realm.setTenant(value);
            } else {
                throw new ConversionException("invalid node value = " + node);
            }

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
                    + "\nTenant ID: " + user.getTenantID() + "\n";
        }
        return "";
    }

}
