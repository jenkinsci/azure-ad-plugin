/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.azuread.scribe;

import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.oauth2.clientauthentication.ClientAuthentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Custom ScribeJava API for Workload Identity Federation.
 *
 * <p>During the OIDC authorization code exchange, Entra ID expects a
 * {@code client_assertion} and {@code client_assertion_type} instead of
 * the normal {@code client_secret} parameter. This class overrides the
 * default client authentication to send the federated token
 * (read from {@code AZURE_FEDERATED_TOKEN_FILE}) as a signed JWT
 * client assertion.</p>
 */
public class AzureWorkloadIdentityApi extends AzureAdApi {

    private static final Logger LOGGER = Logger.getLogger(AzureWorkloadIdentityApi.class.getName());

    AzureWorkloadIdentityApi(String tenant, String authorityHost) {
        super(tenant, authorityHost);
    }

    public static AzureWorkloadIdentityApi custom(String tenant, String authorityHost) {
        return new AzureWorkloadIdentityApi(tenant, authorityHost);
    }

    @Override
    public ClientAuthentication getClientAuthentication() {
        return new WorkloadIdentityClientAuthentication();
    }

    /**
     * Read the federated token from the file path specified by the
     * {@code AZURE_FEDERATED_TOKEN_FILE} environment variable.
     *
     * @return the JWT token string
     * @throws IOException if the env var is not set or the token file cannot be read
     */
    static String readFederatedToken() throws IOException {
        String tokenFilePath = System.getenv("AZURE_FEDERATED_TOKEN_FILE");
        if (tokenFilePath == null || tokenFilePath.isEmpty()) {
            throw new IOException("AZURE_FEDERATED_TOKEN_FILE environment variable is not set. "
                    + "Set it to the path of a JWT token file issued by your OIDC identity provider.");
        }
        return readFederatedToken(tokenFilePath);
    }

    /**
     * Read the federated token from the given file path.
     *
     * @param tokenFilePath absolute path to the JWT token file
     * @return the JWT token string, trimmed
     * @throws IOException if the file cannot be read
     */
    static String readFederatedToken(String tokenFilePath) throws IOException {
        return new String(Files.readAllBytes(Paths.get(tokenFilePath)), StandardCharsets.UTF_8).trim();
    }

    /**
     * Custom client authentication that replaces {@code client_secret} with
     * {@code client_assertion} and {@code client_assertion_type} in the
     * access token request body.
     *
     * <p>This is called by ScribeJava's {@code OAuth20Service.createAccessTokenRequest()}
     * to add client credentials to the token exchange request.</p>
     */
    static class WorkloadIdentityClientAuthentication implements ClientAuthentication {

        private static final String CLIENT_ASSERTION_TYPE =
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        @Override
        public void addClientAuthentication(OAuthRequest request, String apiKey, String apiSecret) {
            request.addBodyParameter("client_id", apiKey);
            request.addBodyParameter("client_assertion_type", CLIENT_ASSERTION_TYPE);
            try {
                request.addBodyParameter("client_assertion", readFederatedToken());
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Failed to read federated token for Workload Identity", e);
                throw new RuntimeException("Failed to read federated token for Workload Identity "
                        + "authentication. Ensure AZURE_FEDERATED_TOKEN_FILE is set and readable.", e);
            }
        }
    }
}
