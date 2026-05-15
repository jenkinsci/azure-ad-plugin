package com.microsoft.jenkins.azuread;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.microsoft.jenkins.azuread.utils.CertificateHelper;
import com.microsoft.jenkins.azuread.oauth.StateCache;
import com.thoughtworks.xstream.io.binary.BinaryStreamReader;
import com.thoughtworks.xstream.io.binary.BinaryStreamWriter;
import hudson.util.Secret;
import jakarta.servlet.http.HttpSession;
import jenkins.model.JenkinsLocationConfiguration;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest2;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AzureSecurityRealmTest {

    @AfterEach
    void tearDown() {
        StateCache.CACHE.invalidateAll();
        SecurityContextHolder.clearContext();
    }

    static Object[][] data() {
        return new Object[][]{
                {"Secret"},
                {"Certificate"}
        };
    }

    @ParameterizedTest(name = "{index}: credentialType={0}")
    @MethodSource("data")
    void testConverter(String credentialType) {
        BinaryStreamWriter writer = null;
        BinaryStreamReader reader = null;
        try {
            String secret = "secret";
            String certificate = "certificate";
            AzureSecurityRealm securityRealm = new AzureSecurityRealm("tenant", "clientId", Secret.fromString(secret), 0);
            securityRealm.setClientCertificate(certificate);
            securityRealm.setCredentialType(credentialType);
            AzureSecurityRealm.ConverterImpl converter = new AzureSecurityRealm.ConverterImpl();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            writer = new BinaryStreamWriter(outputStream);
            writer.startNode("parentNode");
            converter.marshal(securityRealm, writer, null);
            writer.endNode();
            byte[] bytes = outputStream.toByteArray();
            reader = new BinaryStreamReader(new ByteArrayInputStream(bytes));
            AzureSecurityRealm result = (AzureSecurityRealm) converter.unmarshal(reader, null);

            assertEquals(securityRealm.getTenant(), result.getTenant());
            assertEquals(securityRealm.getClientId(), result.getClientId());
            if ("Secret".equals(credentialType)) {
                assertEquals(securityRealm.getClientSecret().getPlainText(), result.getClientSecret().getPlainText());
            } else if ("Certificate".equals(credentialType)) {
                assertEquals(securityRealm.getClientCertificate().getPlainText(), result.getClientCertificate().getPlainText());
            }
            assertEquals(securityRealm.getCacheDuration(), result.getCacheDuration());
        } finally {
            if (writer != null) {
                writer.close();
            }
            if (reader != null) {
                reader.close();
            }
        }
    }

    @ParameterizedTest(name = "{index}: credentialType={0}")
    @MethodSource("data")
    void testSavedConfig() {
        BinaryStreamWriter writer = null;
        try {
            String secretString = "thisIsSpecialSecret";
            String certificateString = "thisIsSpecialCertificate";
            AzureSecurityRealm securityRealm = new AzureSecurityRealm("tenant", "clientId", Secret.fromString(secretString), 0);
            AzureSecurityRealm.ConverterImpl converter = new AzureSecurityRealm.ConverterImpl();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            writer = new BinaryStreamWriter(outputStream);
            converter.marshal(securityRealm, writer, null);
            assertFalse(outputStream.toString(StandardCharsets.UTF_8).contains(secretString));
            assertFalse(outputStream.toString(StandardCharsets.UTF_8).contains(certificateString));
        } finally {
            if (writer != null) {
                writer.close();
            }
        }
    }

    // Test certificate and private key generated with keytool (RSA 2048, CN=Test)
    private static final String TEST_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIICwTCCAamgAwIBAgIIMfYaT3KZZsUwDQYJKoZIhvcNAQEMBQAwDzENMAsGA1UE\n" +
            "AxMEVGVzdDAeFw0yNjA1MTMxOTM4MjFaFw0yNzA1MTMxOTM4MjFaMA8xDTALBgNV\n" +
            "BAMTBFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDnJgKN5pFq\n" +
            "nWU2axCG0/j4sQPU/KZ3b8V+Zsi0VHXujIJ5c2243HNX/F/6mLFWHPehrR+YVY20\n" +
            "5ej+TbRwKNPmZmSJwzltKm82lic+ppKd47Krid037aWDG+KKrkjSbjz3ReavoLwi\n" +
            "ZFyXVnz7ZNswpk6IZ0r0f4yF0j/5MXlLGd3tHl/wv/KhqfrKoeS/+JcYtckHLBIY\n" +
            "6zjTVZ7eWU47Ty4586uBEmejWz+RM7vjpb8BTLxpkeH3tJRYRKiQZuWp70VGdbsx\n" +
            "gcqKZtSwqwj1EVE7eFAYpq8qQymD+ZzjOHlukyou4X1792sxUarzBrH+JSilDxl8\n" +
            "VsmnVbKYo2KpAgMBAAGjITAfMB0GA1UdDgQWBBQFO//s6Kg2WT/kGVCy62vtdSk5\n" +
            "lTANBgkqhkiG9w0BAQwFAAOCAQEApHk5GLUtBAGVDotCmmc7KkMkwQivbsPYY3F4\n" +
            "vooTUnkjrSX3bUtqpf7MVX0LMwCbHfYbeAF6OEnW+yFLDdFDvsegcrJAhcg5xP7c\n" +
            "KVX0xIGwibid/oi62C0TA/f94wmjPcnO64JC3RqFo7/2dKmdX+Y2HlMNM1PQB+/0\n" +
            "+UWkvZQPiXOKVM6z9uOcCsEsDqHHQFkJ43cfQeAdQYOMztBVgCbUfSxZTBDhPAvc\n" +
            "T/SxSRVU0NEOolw7cNxkO3cJ1QDJOR0bE2th/DT0IpglcONpYtyvSOTIfugo11oD\n" +
            "DQ8E6L9cI2tKONchbBum+rL9XXZH2xazgfKsL/iMkgdbhfm6TQ==\n" +
            "-----END CERTIFICATE-----";

    private static final String TEST_KEY_PEM =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDnJgKN5pFqnWU2\n" +
            "axCG0/j4sQPU/KZ3b8V+Zsi0VHXujIJ5c2243HNX/F/6mLFWHPehrR+YVY205ej+\n" +
            "TbRwKNPmZmSJwzltKm82lic+ppKd47Krid037aWDG+KKrkjSbjz3ReavoLwiZFyX\n" +
            "Vnz7ZNswpk6IZ0r0f4yF0j/5MXlLGd3tHl/wv/KhqfrKoeS/+JcYtckHLBIY6zjT\n" +
            "VZ7eWU47Ty4586uBEmejWz+RM7vjpb8BTLxpkeH3tJRYRKiQZuWp70VGdbsxgcqK\n" +
            "ZtSwqwj1EVE7eFAYpq8qQymD+ZzjOHlukyou4X1792sxUarzBrH+JSilDxl8Vsmn\n" +
            "VbKYo2KpAgMBAAECggEAA2FJ6PCghbzsIvc+fvTl5Mpp3O5zh2GUs2bQs9pcUx2u\n" +
            "Nr/FBflV8nPCpN52EWVLtbXbYBXi2ZdXEzOTBOTZRxA46M7NrdamA61Ua5Ucpb8T\n" +
            "o3CDp0gMAzZ1ge5PKvc+YFCfBp3EwoKnMUtWzoeeBkBtpjmkc0jThuLD2WKrfGP1\n" +
            "qKoLooGdb/+xMEPUvrJiuvHUEqmV62OC0EgT8/ej0T+yy4+sZdERtXbLgXcH1J53\n" +
            "viVfpO32ORkYl0AQo/pNcBXL6YiA+Gj9kM3d2e+nyyzyjBftVFydl8vYiP95Crsh\n" +
            "YExeffsCLHX4mfPea5SBpAxa0tV0W29MrWEVE5ExdQKBgQDtS6cl27V68WTg7wTD\n" +
            "ZJAcgmtnXqXdZigQdZYPoEdrZi45p9FGoKTJye3k4yBoxmPJMYyGxb20nXMFWT5u\n" +
            "dXJ7IgPSQQGc0kll2wTCJWzhjfsaxPF6886knbeuxLSenMNBG3RRotQVJgqiJTFj\n" +
            "ahzXmgqP3ah2Z9jWHX+VWJXcPwKBgQD5XlEgHLiQAvTpbf78h7eGQKjaF5BKV7vk\n" +
            "IBHzfko4E610R2QHsgA4SU8tMsj7xGbRDPtNJ860amBzY6V3RElAqn66WJkdgSgE\n" +
            "Cen0rZE28P7HgP8EcBmtp9pfXQ1rY1na5IHrEFOIWt9phisLCx1ZqgETV2YkC2mH\n" +
            "yub/9aEnFwKBgQCtd+GP7mZjorXxLSnZQNmMzdaAMZOlHvno1lzFvZCYNZFTOpfl\n" +
            "PqhYj1JmQZc+oNDvklY9a667q2IbJdta2ma/FuWePUFVh/B6EjsPRlarKKTJM/Gn\n" +
            "xTVp55YQn+G+FbEzFkPZLeRGNZIOaIwLNdYx0n0oIIz3SgEcvWG4JpMe9wKBgQCg\n" +
            "0YOuGven4FBEDm0IPRpNWXvLkrC6URRaTZhmGMcSnRYazEOldtUPd6+5LWxSedn4\n" +
            "7c9PdeGnlob3Q4cdgIthSdMKqEKutXGyERaxdhIVhZw522YbXZQh2wNIxwD1hZAY\n" +
            "S4/BobjNUhWMvzsZFyTpg2rIJ3A2xKldKqyI28b/JwKBgQCouFbakhhKeyo4QuPQ\n" +
            "AvuzsMNyR0KMoaKF+43p4IWk/napw6BVIlQbqec3/RbFUYlQQSFzgg8WJ6K9aqvT\n" +
            "twFGB7vyfdXzDW2yS5ZkMnnwWhXK7w0AtKEet2TENtfz1DEvWm6/OVbkTVL46oDj\n" +
            "fvjLUPapqv+8g/k7SdTipmkpbg==\n" +
            "-----END PRIVATE KEY-----";

    private static final String COMBINED_PEM = TEST_CERT_PEM + "\n" + TEST_KEY_PEM;

    @Test
    void testGenerateClientAssertion() throws Exception {
        AzureSecurityRealm realm = new AzureSecurityRealm();

        PrivateKey privateKey = CertificateHelper.loadPrivateKeyFromString(TEST_KEY_PEM);
        X509Certificate cert = CertificateHelper.loadCertificateFromString(TEST_CERT_PEM);
        String thumbprint = realm.calculateThumbprint(cert);

        String clientId = "test-client-id";
        realm.setClientId(clientId);
        String tokenEndpoint = "https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/token";

        String jwt = realm.generateClientAssertion(privateKey, thumbprint, tokenEndpoint);

        assertNotNull(jwt);
        // JWT should have 3 parts: header.payload.signature
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);

        // Verify header
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode header = mapper.readTree(headerJson);
        assertEquals("RS256", header.get("alg").asText());
        assertEquals(thumbprint, header.get("x5t").asText());

        // Verify payload claims
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        JsonNode payload = mapper.readTree(payloadJson);
        assertEquals(tokenEndpoint, payload.get("aud").asText());
        assertEquals(clientId, payload.get("iss").asText());
        assertEquals(clientId, payload.get("sub").asText());
        assertNotNull(payload.get("jti").asText());
        assertTrue(payload.get("exp").asLong() > payload.get("iat").asLong());

        // Verify signature is valid
        String signingInput = parts[0] + "." + parts[1];
        byte[] sigBytes = Base64.getUrlDecoder().decode(parts[2]);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(cert.getPublicKey());
        sig.update(signingInput.getBytes(StandardCharsets.UTF_8));
        assertTrue(sig.verify(sigBytes));
    }

    @Test
    void testGetClientAssertion() throws Exception {
        String tokenEndpoint = "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token";

        AzureSecurityRealm realm = new AzureSecurityRealm("test-tenant", "test-client-id", Secret.fromString("unused"), 0);
        realm.setClientCertificate(COMBINED_PEM);
        realm.setCredentialType("Certificate");

        String jwt = realm.getClientAssertion(tokenEndpoint);

        assertNotNull(jwt);
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);

        // Verify payload has correct client ID and audience
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode payload = mapper.readTree(payloadJson);
        assertEquals(tokenEndpoint, payload.get("aud").asText());
        assertEquals("test-client-id", payload.get("iss").asText());
    }

    @Test
    void testGetClientAssertionUsesFirstCertificateWhenMultipleArePresent() throws Exception {
        AzureSecurityRealm realm = new AzureSecurityRealm("test-tenant", "test-client-id", Secret.fromString("unused"), 0);
        realm.setClientCertificate(TEST_CERT_PEM + "\n" + TEST_CERT_PEM + "\n" + TEST_KEY_PEM);
        realm.setCredentialType("Certificate");

        String jwt = realm.getClientAssertion("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token");

        assertNotNull(jwt);
        assertEquals(3, jwt.split("\\.").length);
    }

    @Test
    void testGetClientAssertionWrapsCertificateParsingErrors() {
        AzureSecurityRealm realm = new AzureSecurityRealm("test-tenant", "test-client-id", Secret.fromString("unused"), 0);
        realm.setClientCertificate(
                "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n" + TEST_KEY_PEM);
        realm.setCredentialType("Certificate");

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                realm.getClientAssertion("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token"));

        assertEquals("Failed to generate client assertion", exception.getMessage());
        assertNotNull(exception.getCause());
    }

    @Test
    void testGetClientAssertionMissingCertificate() throws Exception {
        AzureSecurityRealm realm = new AzureSecurityRealm("test-tenant", "test-client-id", Secret.fromString("unused"), 0);
        realm.setClientCertificate(TEST_KEY_PEM); // only key, no certificate
        realm.setCredentialType("Certificate");

        assertThrows(Exception.class, () ->
            realm.getClientAssertion("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token"));
    }

    @Test
    void testGetClientAssertionMissingKey() throws Exception {
        AzureSecurityRealm realm = new AzureSecurityRealm("test-tenant", "test-client-id", Secret.fromString("unused"), 0);
        realm.setClientCertificate(TEST_CERT_PEM); // only cert, no key
        realm.setCredentialType("Certificate");

        assertThrows(Exception.class, () ->
            realm.getClientAssertion("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token"));
    }

    @Test
    void testGetOAuthServiceBuildsSecretCredentialFlow(JenkinsRule j) {
        JenkinsLocationConfiguration.get().setUrl("http://localhost/jenkins/");
        AzureSecurityRealm realm = new AzureSecurityRealm("tenant", "client-id", Secret.fromString("secret"), 0);
        realm.setCredentialType("Secret");

        OAuth20Service service = realm.getOAuthService();

        assertNotNull(service);
        assertEquals("openid profile email", service.getDefaultScope());
    }

    @Test
    void testGetOAuthServiceBuildsCertificateCredentialFlow(JenkinsRule j) {
        JenkinsLocationConfiguration.get().setUrl("http://localhost/jenkins/");
        AzureSecurityRealm realm = new AzureSecurityRealm("tenant", "client-id", Secret.fromString("secret"), 0);
        realm.setCredentialType("Certificate");
        realm.setClientCertificate("certificate-value");

        OAuth20Service service = realm.getOAuthService();

        assertNotNull(service);
        assertEquals("openid profile email", service.getDefaultScope());
    }

    @Test
    void testDoCommenceLoginStoresSessionStateAndUsesTrimmedReferer() {
        TestAzureSecurityRealm realm = new TestAzureSecurityRealm("tenant", "client-id", Secret.fromString("secret"), 0);
        FakeOAuth20Service service = new FakeOAuth20Service("https://login.example/authorize", null);
        realm.setOAuthService(service);
        realm.setPromptAccount(true);
        realm.setDomainHint("contoso.com");

        RequestStub requestStub = new RequestStub(true);

        HttpResponse response = realm.doCommenceLogin(requestStub.request(), "http://localhost/jenkins/azureAdLogout/");

        assertInstanceOf(HttpRedirect.class, response);
        assertTrue(requestStub.originalSession().invalidated);
        assertEquals("http://localhost/jenkins/", requestStub.currentSession().attribute(AzureSecurityRealm.REFERER_ATTRIBUTE));
        assertNotNull(requestStub.currentSession().attribute(AzureSecurityRealm.TIMESTAMP_ATTRIBUTE));
        String nonce = (String) requestStub.currentSession().attribute(AzureSecurityRealm.NONCE_ATTRIBUTE);
        assertNotNull(nonce);
        assertEquals(16, nonce.length());
        assertEquals("form_post", service.lastAuthorizationParams().get("response_mode"));
        assertEquals("select_account", service.lastAuthorizationParams().get("prompt"));
        assertEquals("contoso.com", service.lastAuthorizationParams().get("domain_hint"));
        assertNotNull(service.lastAuthorizationParams().get("state"));
    }

    @Test
    void testDoFinishLoginRedirectsToContextRootWhenStateIsMissing() throws Exception {
        TestAzureSecurityRealm realm = new TestAzureSecurityRealm("tenant", "client-id", Secret.fromString("secret"), 0);
        RequestStub requestStub = new RequestStub(true);
        requestStub.setParameter("state", "missing-state");

        HttpResponse response = realm.doFinishLogin(requestStub.request());

        assertFalse(response instanceof HttpRedirect);
        assertTrue(requestStub.originalSession().invalidated);
    }

    @Test
    void testDoFinishLoginRedirectsToContextRootWhenCodeIsMissing() throws Exception {
        TestAzureSecurityRealm realm = new TestAzureSecurityRealm("tenant", "client-id", Secret.fromString("secret"), 0);
        RequestStub requestStub = new RequestStub(true);
        requestStub.setParameter("state", "state-blank-code");
        StateCache.CACHE.put("state-blank-code", new StateCache.CacheHolder("http://localhost/jenkins/job/test/", 1L, "nonce-value"));

        HttpResponse response = realm.doFinishLogin(requestStub.request());

        assertFalse(response instanceof HttpRedirect);
    }

    @Test
    void testDoFinishLoginRedirectsToContextRootWhenIdTokenIsMissing(JenkinsRule j) throws Exception {
        JenkinsLocationConfiguration.get().setUrl("http://localhost/jenkins/");
        TestAzureSecurityRealm realm = new TestAzureSecurityRealm("tenant", "client-id", Secret.fromString("secret"), 0);
        realm.setCredentialType("Secret");
        realm.setOAuthService(new FakeOAuth20Service("https://login.example/authorize", new OAuth2AccessToken("access-token", "{}")));

        RequestStub requestStub = new RequestStub(true);
        requestStub.setParameter("state", "state-no-id-token");
        requestStub.setParameter("code", "auth-code");
        StateCache.CACHE.put("state-no-id-token", new StateCache.CacheHolder("http://localhost/jenkins/job/test/", 1L, "nonce-value"));

        HttpResponse response = realm.doFinishLogin(requestStub.request());

        assertFalse(response instanceof HttpRedirect);
    }

    @Test
    void testDoFinishLoginRedirectsToSafeRefererAfterSuccessfulSecretFlow(JenkinsRule j) throws Exception {
        JenkinsLocationConfiguration.get().setUrl("http://localhost/jenkins/");
        TestAzureSecurityRealm realm = new TestAzureSecurityRealm("tenant", "client-id", Secret.fromString("secret"), 0);
        realm.setCredentialType("Secret");
        realm.setDisableGraphIntegration(true);
        realm.setOAuthService(new FakeOAuth20Service(
                "https://login.example/authorize",
                new OAuth2AccessToken("access-token", "{\"id_token\":\"token-value\"}")));
        realm.setValidatedClaims(createValidClaims());

        RequestStub requestStub = new RequestStub(true);
        requestStub.setParameter("state", "state-success");
        requestStub.setParameter("code", "auth-code");
        StateCache.CACHE.put(
                "state-success",
                new StateCache.CacheHolder("http://localhost/jenkins/job/test/", 1L, "nonce-value"));

        HttpResponse response = realm.doFinishLogin(requestStub.request());

        assertInstanceOf(HttpRedirect.class, response);
    }

    private static JwtClaims createValidClaims() {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("name", "Test User");
        claims.setClaim("preferred_username", "user@example.com");
        claims.setClaim("tid", "tenant-id");
        claims.setClaim("oid", "12345678-1234-1234-1234-123456789012");
        claims.setClaim("email", "user@example.com");
        claims.setStringListClaim("groups", List.of());
        return claims;
    }

    private static final class TestAzureSecurityRealm extends AzureSecurityRealm {

        private OAuth20Service oAuthService;
        private JwtClaims validatedClaims;

        private TestAzureSecurityRealm(String tenant, String clientId, Secret clientSecret, int cacheDuration) {
            super(tenant, clientId, clientSecret, cacheDuration);
        }

        private void setOAuthService(OAuth20Service oAuthService) {
            this.oAuthService = oAuthService;
        }

        private void setValidatedClaims(JwtClaims validatedClaims) {
            this.validatedClaims = validatedClaims;
        }

        @Override
        OAuth20Service getOAuthService() {
            return oAuthService != null ? oAuthService : super.getOAuthService();
        }

        @Override
        JwtClaims validateIdToken(String expectedNonce, String idToken) throws InvalidJwtException {
            return validatedClaims != null ? validatedClaims : super.validateIdToken(expectedNonce, idToken);
        }
    }

    private static final class FakeOAuth20Service extends OAuth20Service {

        private final String authorizationUrl;
        private final OAuth2AccessToken accessToken;
        private Map<String, String> lastAuthorizationParams = Map.of();

        private FakeOAuth20Service(String authorizationUrl, OAuth2AccessToken accessToken) {
            super(new FakeApi20(), "client-id", "client-secret", "http://localhost/jenkins" + AzureSecurityRealm.CALLBACK_URL,
                    "openid profile email", "code", OutputStream.nullOutputStream(), null, null, null);
            this.authorizationUrl = authorizationUrl;
            this.accessToken = accessToken;
        }

        @Override
        public String getAuthorizationUrl(Map<String, String> additionalParams) {
            this.lastAuthorizationParams = new HashMap<>(additionalParams);
            return authorizationUrl;
        }

        @Override
        public OAuth2AccessToken getAccessToken(String authorizationCode) {
            return accessToken;
        }

        private Map<String, String> lastAuthorizationParams() {
            return lastAuthorizationParams;
        }
    }

    private static final class FakeApi20 extends DefaultApi20 {

        @Override
        public String getAccessTokenEndpoint() {
            return "https://login.example/token";
        }

        @Override
        protected String getAuthorizationBaseUrl() {
            return "https://login.example/authorize";
        }
    }

    private static final class RequestStub {

        private SessionStub currentSession;
        private final SessionStub originalSession;
        private final Map<String, String> parameters = new HashMap<>();
        private final StaplerRequest2 request;

        private RequestStub(boolean withExistingSession) {
            this.originalSession = withExistingSession ? new SessionStub() : null;
            this.currentSession = originalSession;
            this.request = (StaplerRequest2) Proxy.newProxyInstance(
                    StaplerRequest2.class.getClassLoader(),
                    new Class<?>[] {StaplerRequest2.class},
                    (proxy, method, args) -> {
                        switch (method.getName()) {
                            case "getSession":
                                if (args == null || args.length == 0) {
                                    return getOrCreateSession(true).proxy();
                                }
                                return getOrCreateSession((Boolean) args[0]).proxyOrNull();
                            case "getParameter":
                                return parameters.get((String) args[0]);
                            case "getContextPath":
                                return "";
                            default:
                                return defaultValue(method.getReturnType());
                        }
                    });
        }

        private StaplerRequest2 request() {
            return request;
        }

        private void setParameter(String name, String value) {
            parameters.put(name, value);
        }

        private SessionStub originalSession() {
            return originalSession;
        }

        private SessionStub currentSession() {
            return currentSession;
        }

        private SessionStub getOrCreateSession(boolean create) {
            if (currentSession == null || currentSession.invalidated) {
                if (!create) {
                    return SessionStub.nullSession();
                }
                currentSession = new SessionStub();
            }
            return currentSession;
        }
    }

    private static final class SessionStub {

        private static final SessionStub NULL_SESSION = new SessionStub(true);

        private final Map<String, Object> attributes = new HashMap<>();
        private final HttpSession proxy;
        private boolean invalidated;
        private final boolean nullSession;

        private SessionStub() {
            this(false);
        }

        private SessionStub(boolean nullSession) {
            this.nullSession = nullSession;
            this.proxy = nullSession ? null : (HttpSession) Proxy.newProxyInstance(
                    HttpSession.class.getClassLoader(),
                    new Class<?>[] {HttpSession.class},
                    (proxyInstance, method, args) -> {
                        switch (method.getName()) {
                            case "getAttribute":
                                return attributes.get((String) args[0]);
                            case "setAttribute":
                                attributes.put((String) args[0], args[1]);
                                return null;
                            case "invalidate":
                                invalidated = true;
                                return null;
                            case "removeAttribute":
                                attributes.remove((String) args[0]);
                                return null;
                            case "getId":
                                return "session-id";
                            case "isNew":
                                return false;
                            default:
                                return defaultValue(method.getReturnType());
                        }
                    });
        }

        private static SessionStub nullSession() {
            return NULL_SESSION;
        }

        private HttpSession proxy() {
            return proxy;
        }

        private HttpSession proxyOrNull() {
            return nullSession ? null : proxy;
        }

        private Object attribute(String name) {
            return attributes.get(name);
        }
    }

    private static Object defaultValue(Class<?> returnType) {
        if (!returnType.isPrimitive()) {
            return null;
        }
        if (returnType == boolean.class) {
            return false;
        }
        if (returnType == byte.class) {
            return (byte) 0;
        }
        if (returnType == short.class) {
            return (short) 0;
        }
        if (returnType == int.class) {
            return 0;
        }
        if (returnType == long.class) {
            return 0L;
        }
        if (returnType == float.class) {
            return 0F;
        }
        if (returnType == double.class) {
            return 0D;
        }
        if (returnType == char.class) {
            return '\0';
        }
        return null;
    }
}