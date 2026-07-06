package com.microsoft.jenkins.azuread.utils;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public final class CertificateHelper {

    private CertificateHelper() {
    }

    private static final String PKCS8_PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PKCS8_PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";
    private static final String PKCS1_RSA_PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String PKCS1_RSA_PRIVATE_KEY_FOOTER = "-----END RSA PRIVATE KEY-----";

    // Load certificate from PEM string (single-line or multi-line)
    public static X509Certificate loadCertificateFromString(String certPem) throws GeneralSecurityException {
        byte[] certBytes = decodeBase64Body(certPem, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
    }

    // Load private key from PEM string (PKCS#8 or PKCS#1 RSA format, single-line or multi-line)
    public static PrivateKey loadPrivateKeyFromString(String keyPem) throws GeneralSecurityException {
        String normalizedPem = keyPem.trim();

        if (normalizedPem.contains(PKCS8_PRIVATE_KEY_HEADER)) {
            byte[] keyBytes = decodeBase64Body(normalizedPem, PKCS8_PRIVATE_KEY_HEADER, PKCS8_PRIVATE_KEY_FOOTER);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        }

        if (normalizedPem.contains(PKCS1_RSA_PRIVATE_KEY_HEADER)) {
            byte[] pkcs1Bytes = decodeBase64Body(
                    normalizedPem, PKCS1_RSA_PRIVATE_KEY_HEADER, PKCS1_RSA_PRIVATE_KEY_FOOTER);
            byte[] pkcs8Bytes = wrapPkcs1RsaKey(pkcs1Bytes);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
        }

        throw new IllegalArgumentException("Unsupported private key format. Expected PKCS#8 or PKCS#1 RSA PEM.");
    }

    private static byte[] decodeBase64Body(String pem, String header, String footer) {
        String clean = pem.replace(header, "")
                .replace(footer, "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(clean);
    }

    static byte[] wrapPkcs1RsaKey(byte[] pkcs1Bytes) throws GeneralSecurityException {
        try {
            return new PrivateKeyInfo(
                            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                            RSAPrivateKey.getInstance(pkcs1Bytes))
                    .getEncoded();
        } catch (IOException e) {
            throw new GeneralSecurityException("Failed to convert PKCS#1 RSA key to PKCS#8", e);
        }
    }
}
