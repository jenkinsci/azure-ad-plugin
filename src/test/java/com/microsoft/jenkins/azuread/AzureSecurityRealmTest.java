package com.microsoft.jenkins.azuread;

import com.thoughtworks.xstream.io.binary.BinaryStreamReader;
import com.thoughtworks.xstream.io.binary.BinaryStreamWriter;
import hudson.util.Secret;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertFalse;

@RunWith(Parameterized.class)
public class AzureSecurityRealmTest {
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Parameterized.Parameter(0)
    public String credentialType;

    @Parameters(name = "{index}: credentialType={0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                {"Secret"},
                {"Certificate"}
        });
    }

    @Before
    public void init() throws Exception {
        j.recipe();
    }

    @Test
    public void testConverter() {
        BinaryStreamWriter writer = null;
        BinaryStreamReader reader = null;
        try {
            String secret = "secret";
            String certificate = "certificate";
            AzureSecurityRealm securityRealm = new AzureSecurityRealm("tenant", "clientId", Secret.fromString(secret), Secret.fromString(certificate), credentialType, 0);
            AzureSecurityRealm.ConverterImpl converter = new AzureSecurityRealm.ConverterImpl();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            writer = new BinaryStreamWriter(outputStream);
            writer.startNode("parentNode");
            converter.marshal(securityRealm, writer, null);
            writer.endNode();
            byte[] bytes = outputStream.toByteArray();
            reader = new BinaryStreamReader(new ByteArrayInputStream(bytes));
            AzureSecurityRealm result = (AzureSecurityRealm) converter.unmarshal(reader, null);

            Assert.assertEquals(securityRealm.getTenant(), result.getTenant());
            Assert.assertEquals(securityRealm.getClientId(), result.getClientId());
            if ("Secret".equals(credentialType)) {
                Assert.assertEquals(securityRealm.getClientSecret().getPlainText(), result.getClientSecret().getPlainText());
            } else if ("Certificate".equals(credentialType)) {
                Assert.assertEquals(securityRealm.getClientCertificate().getPlainText(), result.getClientCertificate().getPlainText());
            }
            Assert.assertEquals(securityRealm.getCacheDuration(), result.getCacheDuration());
        } finally {
            if (writer != null) {
                writer.close();
            }
            if (reader != null) {
                reader.close();
            }
        }
    }

    @Test
    public void testSavedConfig() {
        BinaryStreamWriter writer = null;
        try {
            String secretString = "thisIsSpecialSecret";
            String certificateString = "thisIsSpecialCertificate";
            AzureSecurityRealm securityRealm = new AzureSecurityRealm("tenant", "clientId", Secret.fromString(secretString), Secret.fromString(certificateString), credentialType, 0);

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