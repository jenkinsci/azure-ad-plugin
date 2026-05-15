package com.microsoft.jenkins.azuread.utils;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.util.Base64;

public final class CertificateHelper {

    private static final String PKCS8_PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PKCS8_PRIVATE_KEY_FOOTER = "-----END PRIVATE KEY-----";
    private static final String PKCS1_RSA_PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String PKCS1_RSA_PRIVATE_KEY_FOOTER = "-----END RSA PRIVATE KEY-----";

    // Load certificate from PEM string (single-line or multi-line)
    public static X509Certificate loadCertificateFromString(String certPem) throws GeneralSecurityException {
        String certClean = certPem.replaceAll("-----BEGIN CERTIFICATE-----", "")
                                 .replaceAll("-----END CERTIFICATE-----", "")
                                 .replaceAll("\\s+", "");
        byte[] certBytes = Base64.getDecoder().decode(certClean);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
    }

    // Load private key from PEM string (PKCS#8 format, base64-encoded, single-line or multi-line)
    public static PrivateKey loadPrivateKeyFromString(String keyPem) throws GeneralSecurityException {
        String normalizedPem = keyPem.trim();

        if (normalizedPem.contains(PKCS8_PRIVATE_KEY_HEADER)) {
            String keyClean = normalizedPem
                    .replace(PKCS8_PRIVATE_KEY_HEADER, "")
                    .replace(PKCS8_PRIVATE_KEY_FOOTER, "")
                    .replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(keyClean);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        }

        if (normalizedPem.contains(PKCS1_RSA_PRIVATE_KEY_HEADER)) {
            String keyClean = normalizedPem
                    .replace(PKCS1_RSA_PRIVATE_KEY_HEADER, "")
                    .replace(PKCS1_RSA_PRIVATE_KEY_FOOTER, "")
                    .replaceAll("\\s+", "");
            byte[] pkcs1Bytes = Base64.getDecoder().decode(keyClean);
            byte[] pkcs8Bytes = wrapPkcs1RsaKey(pkcs1Bytes);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
        }

        throw new IllegalArgumentException("Unsupported private key format. Expected PKCS#8 or PKCS#1 RSA PEM.");
    }

    private static byte[] wrapPkcs1RsaKey(byte[] pkcs1Bytes) {
        byte[] rsaAlgorithmIdentifier = new byte[] {
            0x30, 0x0D,
            0x06, 0x09,
            0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01,
            0x05, 0x00
        };

        byte[] version = new byte[] {0x02, 0x01, 0x00};
        byte[] privateKeyOctetString = derEncodeOctetString(pkcs1Bytes);

        int totalLength = version.length + rsaAlgorithmIdentifier.length + privateKeyOctetString.length;
        return concat(derEncodeSequenceHeader(totalLength), version, rsaAlgorithmIdentifier, privateKeyOctetString);
    }

    private static byte[] derEncodeOctetString(byte[] value) {
        return concat(new byte[] {0x04}, derEncodeLength(value.length), value);
    }

    private static  byte[] derEncodeSequenceHeader(int length) {
        return concat(new byte[] {0x30}, derEncodeLength(length));
    }

    private static  byte[] derEncodeLength(int length) {
        if (length < 128) {
            return new byte[] {(byte) length};
        } else if (length < 256) {
            return new byte[] {(byte) 0x81, (byte) length};
        } else {
            return new byte[] {(byte) 0x82, (byte) (length >> 8), (byte) length};
        }
    }

    private static  byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] array : arrays) {
            total += array.length;
        }

        byte[] result = new byte[total];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }    
}
