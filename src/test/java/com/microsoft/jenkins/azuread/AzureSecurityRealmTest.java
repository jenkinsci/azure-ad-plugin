package com.microsoft.jenkins.azuread;

import com.thoughtworks.xstream.io.binary.BinaryStreamReader;
import com.thoughtworks.xstream.io.binary.BinaryStreamWriter;
import hudson.util.Secret;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;

import static org.junit.Assert.assertFalse;

public class AzureSecurityRealmTest {
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Before
    public void init() throws Exception {
        j.recipe();
    }

    @Test
    public void testConverter() throws InterruptedException, ExecutionException, IOException {
        BinaryStreamWriter writer = null;
        BinaryStreamReader reader = null;
        try {

            AzureSecurityRealm securityRealm = new AzureSecurityRealm("tenant", "clientId", Secret.fromString("secret"), 0);
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
            Assert.assertEquals(securityRealm.getClientSecret().getPlainText(), result.getClientSecret().getPlainText());
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
    public void testSavedConfig() throws InterruptedException, ExecutionException, IOException {
        BinaryStreamWriter writer = null;
        try {
            String secretString = "thisIsSpecialSecret";
            AzureSecurityRealm securityRealm = new AzureSecurityRealm("tenant", "clientId", Secret.fromString(secretString), 0);

            AzureSecurityRealm.ConverterImpl converter = new AzureSecurityRealm.ConverterImpl();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            writer = new BinaryStreamWriter(outputStream);
            converter.marshal(securityRealm, writer, null);
            assertFalse(outputStream.toString(StandardCharsets.UTF_8).contains(secretString));
        } finally {
            if (writer != null) {
                writer.close();
            }
        }
    }
}
