package com.microsoft.jenkins.azuread;

import com.thoughtworks.xstream.io.binary.BinaryStreamReader;
import com.thoughtworks.xstream.io.binary.BinaryStreamWriter;
import hudson.util.Secret;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

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
}