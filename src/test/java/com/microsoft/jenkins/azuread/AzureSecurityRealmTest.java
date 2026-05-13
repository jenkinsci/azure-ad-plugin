package com.microsoft.jenkins.azuread;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.xstream.io.binary.BinaryStreamReader;
import com.thoughtworks.xstream.io.binary.BinaryStreamWriter;
import hudson.util.Secret;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class AzureSecurityRealmTest {

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
    void testLoadCertificateFromString() throws Exception {
        AzureSecurityRealm realm = new AzureSecurityRealm();
        Method method = AzureSecurityRealm.class.getDeclaredMethod("loadCertificateFromString", String.class);
        method.setAccessible(true);

        X509Certificate cert = (X509Certificate) method.invoke(realm, TEST_CERT_PEM);

        assertNotNull(cert);
        assertEquals("X.509", cert.getType());
        assertTrue(cert.getSubjectX500Principal().getName().contains("CN=Test"));
    }

    @Test
    void testLoadCertificateFromStringInvalid() throws Exception {
        AzureSecurityRealm realm = new AzureSecurityRealm();
        Method method = AzureSecurityRealm.class.getDeclaredMethod("loadCertificateFromString", String.class);
        method.setAccessible(true);

        assertThrows(Exception.class, () -> method.invoke(realm, "not-a-valid-pem"));
    }

    @Test
    void testLoadPrivateKeyFromString() throws Exception {
        AzureSecurityRealm realm = new AzureSecurityRealm();
        Method method = AzureSecurityRealm.class.getDeclaredMethod("loadPrivateKeyFromString", String.class);
        method.setAccessible(true);

        PrivateKey key = (PrivateKey) method.invoke(realm, TEST_KEY_PEM);

        assertNotNull(key);
        assertEquals("RSA", key.getAlgorithm());
        assertEquals("PKCS#8", key.getFormat());
    }

    @Test
    void testLoadPrivateKeyFromStringInvalid() throws Exception {
        AzureSecurityRealm realm = new AzureSecurityRealm();
        Method method = AzureSecurityRealm.class.getDeclaredMethod("loadPrivateKeyFromString", String.class);
        method.setAccessible(true);

        assertThrows(Exception.class, () -> method.invoke(realm, "not-a-valid-key"));
    }

    @Test
    void testGenerateClientAssertion() throws Exception {
        AzureSecurityRealm realm = new AzureSecurityRealm();

        // Load the private key and cert for the test
        Method loadKey = AzureSecurityRealm.class.getDeclaredMethod("loadPrivateKeyFromString", String.class);
        loadKey.setAccessible(true);
        PrivateKey privateKey = (PrivateKey) loadKey.invoke(realm, TEST_KEY_PEM);

        Method loadCert = AzureSecurityRealm.class.getDeclaredMethod("loadCertificateFromString", String.class);
        loadCert.setAccessible(true);
        X509Certificate cert = (X509Certificate) loadCert.invoke(realm, TEST_CERT_PEM);

        Method calcThumbprint = AzureSecurityRealm.class.getDeclaredMethod("calculateThumbprint", X509Certificate.class);
        calcThumbprint.setAccessible(true);
        String thumbprint = (String) calcThumbprint.invoke(realm, cert);

        Method generateAssertion = AzureSecurityRealm.class.getDeclaredMethod(
                "generateClientAssertion", String.class, String.class, PrivateKey.class, String.class, String.class);
        generateAssertion.setAccessible(true);

        String clientId = "test-client-id";
        String tenantId = "test-tenant-id";
        String tokenEndpoint = "https://login.microsoftonline.com/test-tenant-id/oauth2/v2.0/token";

        String jwt = (String) generateAssertion.invoke(realm, clientId, tenantId, privateKey, thumbprint, tokenEndpoint);

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

        Method method = AzureSecurityRealm.class.getDeclaredMethod("getClientAssertion", String.class);
        method.setAccessible(true);

        String jwt = (String) method.invoke(realm, tokenEndpoint);

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
    void testGetClientAssertionMissingCertificate() throws Exception {
        AzureSecurityRealm realm = new AzureSecurityRealm("test-tenant", "test-client-id", Secret.fromString("unused"), 0);
        realm.setClientCertificate(TEST_KEY_PEM); // only key, no certificate
        realm.setCredentialType("Certificate");

        Method method = AzureSecurityRealm.class.getDeclaredMethod("getClientAssertion", String.class);
        method.setAccessible(true);

        assertThrows(Exception.class, () ->
                method.invoke(realm, "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token"));
    }

    @Test
    void testGetClientAssertionMissingKey() throws Exception {
        AzureSecurityRealm realm = new AzureSecurityRealm("test-tenant", "test-client-id", Secret.fromString("unused"), 0);
        realm.setClientCertificate(TEST_CERT_PEM); // only cert, no key
        realm.setCredentialType("Certificate");

        Method method = AzureSecurityRealm.class.getDeclaredMethod("getClientAssertion", String.class);
        method.setAccessible(true);

        assertThrows(Exception.class, () ->
                method.invoke(realm, "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token"));
    }
}