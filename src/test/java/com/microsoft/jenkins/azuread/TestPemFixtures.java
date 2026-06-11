package com.microsoft.jenkins.azuread;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;

public final class TestPemFixtures {

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

    private static final GeneratedFixture GENERATED_FIXTURE = GeneratedFixture.create();

    private TestPemFixtures() {
    }

    public static String certificatePem() {
        return TEST_CERT_PEM;
    }

    public static String pkcs8PrivateKeyPem() {
        return GENERATED_FIXTURE.pkcs8PrivateKeyPem;
    }

    public static String pkcs1PrivateKeyPem() {
        return GENERATED_FIXTURE.pkcs1PrivateKeyPem;
    }

    public static String combinedPem() {
        return certificatePem() + "\n" + pkcs8PrivateKeyPem();
    }

    public static PrivateKey privateKey() {
        return GENERATED_FIXTURE.keyPair.getPrivate();
    }

    public static PublicKey publicKey() {
        return GENERATED_FIXTURE.keyPair.getPublic();
    }

    private static final class GeneratedFixture {

        private final KeyPair keyPair;
        private final String pkcs8PrivateKeyPem;
        private final String pkcs1PrivateKeyPem;

        private GeneratedFixture(KeyPair keyPair, String pkcs8PrivateKeyPem, String pkcs1PrivateKeyPem) {
            this.keyPair = keyPair;
            this.pkcs8PrivateKeyPem = pkcs8PrivateKeyPem;
            this.pkcs1PrivateKeyPem = pkcs1PrivateKeyPem;
        }

        private static GeneratedFixture create() {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                String pkcs8Pem = toPem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
                String pkcs1Pem = toPem("RSA PRIVATE KEY", toPkcs1((RSAPrivateCrtKey) keyPair.getPrivate()));
                return new GeneratedFixture(keyPair, pkcs8Pem, pkcs1Pem);
            } catch (GeneralSecurityException e) {
                throw new ExceptionInInitializerError(e);
            }
        }
    }

    private static byte[] toPkcs1(RSAPrivateCrtKey privateKey) {
        return derSequence(
                derInteger(BigInteger.ZERO),
                derInteger(privateKey.getModulus()),
                derInteger(privateKey.getPublicExponent()),
                derInteger(privateKey.getPrivateExponent()),
                derInteger(privateKey.getPrimeP()),
                derInteger(privateKey.getPrimeQ()),
                derInteger(privateKey.getPrimeExponentP()),
                derInteger(privateKey.getPrimeExponentQ()),
                derInteger(privateKey.getCrtCoefficient()));
    }

    private static byte[] derSequence(byte[]... values) {
        return concat(new byte[] {0x30}, derLength(totalLength(values)), concat(values));
    }

    private static byte[] derInteger(BigInteger value) {
        byte[] encoded = value.toByteArray();
        return concat(new byte[] {0x02}, derLength(encoded.length), encoded);
    }

    private static byte[] derLength(int length) {
        if (length < 128) {
            return new byte[] {(byte) length};
        }

        int size = 0;
        int remaining = length;
        while (remaining > 0) {
            size++;
            remaining >>= 8;
        }

        byte[] encoded = new byte[1 + size];
        encoded[0] = (byte) (0x80 | size);
        for (int index = size; index > 0; index--) {
            encoded[index] = (byte) (length & 0xFF);
            length >>= 8;
        }
        return encoded;
    }

    private static int totalLength(byte[]... values) {
        int total = 0;
        for (byte[] value : values) {
            total += value.length;
        }
        return total;
    }

    private static byte[] concat(byte[]... values) {
        byte[] concatenated = new byte[totalLength(values)];
        int offset = 0;
        for (byte[] value : values) {
            System.arraycopy(value, 0, concatenated, offset, value.length);
            offset += value.length;
        }
        return concatenated;
    }

    private static String toPem(String type, byte[] encoded) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        return "-----BEGIN " + type + "-----\n"
                + base64
                + "\n-----END " + type + "-----";
    }
}