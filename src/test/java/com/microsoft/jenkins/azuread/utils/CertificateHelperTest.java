package com.microsoft.jenkins.azuread.utils;

import com.microsoft.jenkins.azuread.TestPemFixtures;

import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateHelperTest {

    @Test
    void testLoadCertificateFromString() throws Exception {
        X509Certificate cert = CertificateHelper.loadCertificateFromString(TestPemFixtures.certificatePem());

        assertNotNull(cert);
        assertEquals("X.509", cert.getType());
        assertTrue(cert.getSubjectX500Principal().getName().contains("CN=Test"));
    }

    @Test
    void testLoadCertificateFromStringInvalid() {
        assertThrows(Exception.class, () -> CertificateHelper.loadCertificateFromString("not-a-valid-pem"));
    }

    @Test
    void testLoadPrivateKeyFromString() throws Exception {
        PrivateKey key = CertificateHelper.loadPrivateKeyFromString(TestPemFixtures.pkcs8PrivateKeyPem());

        assertNotNull(key);
        assertEquals("RSA", key.getAlgorithm());
        assertEquals("PKCS#8", key.getFormat());
    }

    @Test
    void testLoadRsaPrivateKeyFromString() throws Exception {
        PrivateKey key = CertificateHelper.loadPrivateKeyFromString(TestPemFixtures.pkcs1PrivateKeyPem());

        assertNotNull(key);
        assertEquals("RSA", key.getAlgorithm());
        assertEquals("PKCS#8", key.getFormat());
    }

    @Test
    void testLoadPrivateKeyFromStringUnsupportedFormat() {
        assertThrows(IllegalArgumentException.class,
                () -> CertificateHelper.loadPrivateKeyFromString("not-a-valid-pem"));
    }
}