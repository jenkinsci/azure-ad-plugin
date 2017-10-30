/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.common.base.Stopwatch;
import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.credentials.AzureTokenCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.jenkins.azuread.scribe.AzureApi;
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
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AzureSecurityRealm extends SecurityRealm {

    private static final String REFERER_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".referer";
    private static final String TIMESTAMP_ATTRIBUTE = AzureSecurityRealm.class.getName() + ".beginTime";
    private static final Logger LOGGER = Logger.getLogger(AzureSecurityRealm.class.getName());
    private Secret clientId;
    private Secret clientSecret;
    private Secret tenant;

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

    OAuth20Service getOAuthService() {
        OAuth20Service service = new ServiceBuilder(clientId.getPlainText()).apiSecret(clientSecret.getPlainText())
                .callback(getRootUrl() + "/securityRealm/finishLogin")
                .build(AzureApi.instance(Constants.DEFAULT_GRAPH_ENDPOINT, this.getTenant()));
        return service;
    }

    AzureTokenCredentials getAzureCredential() throws IOException {
        return new ApplicationTokenCredentials(
                getClientId(),
                getTenant(),
                getClientSecret(),
                AzureEnvironment.AZURE);
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
        return new HttpRedirect(service.getAuthorizationUrl());
    }

    public HttpResponse doFinishLogin(StaplerRequest request) throws Exception {
        Long beginTime = (Long) request.getSession().getAttribute(TIMESTAMP_ATTRIBUTE);
        if (beginTime != null) {
            long endTime = System.currentTimeMillis();
            System.out.println("Requesting oauth code time = " + (endTime - beginTime) + " ms");
        }
        String code = request.getParameter("code");

        if (StringUtils.isBlank(code)) {
            LOGGER.log(Level.SEVERE, "doFinishLogin() code = null");
            return HttpResponses.redirectTo(this.getRootUrl() + AzureAuthFailAction.POST_LOGOUT_URL);
        }

        OAuth20Service service = getOAuthService();
        Stopwatch stopwatch = Stopwatch.createStarted();
        OAuth2AccessToken accessToken = service.getAccessToken(code);
        stopwatch.stop();
        System.out.println("Requesting access token time = " + stopwatch.elapsed(TimeUnit.MILLISECONDS) + " ms");

        if (accessToken != null) {
            AzureAuthenticationToken auth = new AzureAuthenticationToken((AzureToken) accessToken);
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
        } else {
            LOGGER.log(Level.SEVERE, "doFinishLogin() accessToken = null");
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
        Jenkins j = Jenkins.getInstance();
        assert j != null;
        if (j.hasPermission(Jenkins.READ)) {
            return super.getPostLogOutUrl(req, auth);
        }
        return req.getContextPath() + "/" + AzureLogoutAction.POST_LOGOUT_URL;
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
            StringBuffer description = new StringBuffer("Azure Active Directory User\n\n");
            description.append("Given Name: " + user.getGivenName() + "\n");
            description.append("Family Name: " + user.getFamilyName() + "\n");
            description.append("Unique Principal Name: " + user.getUniqueName() + "\n");
            description.append("Object ID: " + user.getObjectID() + "\n");
            description.append("Tenant ID: " + user.getTenantID() + "\n");
            return description.toString();
        }
        return "";
    }

}
