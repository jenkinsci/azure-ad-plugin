package com.microsoft.jenkins.azuread.utils;

import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateHelperTest {

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

    private static final String TEST_RSA_PRIVATE_KEY_PEM =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEpAIBAAKCAQEAsT5ugsHmREpG76ceVRyca/KHpHJwDWJbmezDr2XJcIAv9bLX\n" +
            "Q1SCs8rTxQilzwCYdXugcOa/6VleHYz0T3MCjUafOBwYqMUKSDxhxfzeu4NFjdO0\n" +
            "moYPZrH30C7f/ZpPaPDa6OC6SiM+EGGmHL1zcQqbVRWiQwRuVWjeS2SKk1kEQrmW\n" +
            "D7yQ/pQsdxSaZtVIgtnR42q58iRNkEVflffz3oCeMeswwIioTBt9vmy+MMPHARAB\n" +
            "Lug8S6pQ6bEk8261PrFI/0PmtcmhS35XoZ5KpXnbecWAT+O/MvH2HaGsZOMeueuS\n" +
            "hlgwuKgVIZstuN4nZuuNYLBR/C4rAh4e16AzMwIDAQABAoIBAQCo7thlyGmwrRrv\n" +
            "UFmYxaxRNtgR5QDnwNeN3hylEF7u2z7a75o8klABDVDKe3ON2QN29l31Pfmsb4FE\n" +
            "qRQypWvJO4aF9EGMmkEymFqYWmvwTS39/8ojfaMwPm/z/LmA/ZKyct4zF/52qyB8\n" +
            "fJXWzrs5AuMKNZRyS8bdoRY+xZVO2fMDmsWczv/Iyp0V0z14D5z0C7zd7yvPlJvs\n" +
            "qPLpiV80TKiSdVYHatwQ7QxPkCBLKbYG5sbVYIPCYhsmsrVIzcHP4RmRBL2/J4xT\n" +
            "aOt2Wh9G1hOBVFC9V0LOQUa81u6EAh4mmO4ulygLztK8mjj+NE8rSToctR1W9PWh\n" +
            "FlrD92ABAoGBANqtxOse4gBy0wKH4vvpDj7uQ3piP5ZpqtVyOV70wtkiQgMyCdRh\n" +
            "rmv5TEpa2QUYUSjC06sF+oIVR01IvO7sb1IiBzKRZwP7B/3hIisH5vzdBGkMkpTg\n" +
            "7qvMvKTl5YYtHXHoXb8pjL0YHDmXN7jB9PqH7nhvSeCZELp9m0qNbfyVAoGBAM9+\n" +
            "V4PktCcBe4AYs2BH9BDo4ShiCYZsaD3h9hpCRZfcEJXjbgwfHHNsNvMj/C7BD/2E\n" +
            "7/PQot7KbaWw5auNzgg8hXVv1kSMs7CNBu7VO++/D05lbdysK6HvHA0HWd+M0ZnE\n" +
            "NqiT2tWVCvINFujMfuQV+HgyhKGZmO3N55FL9TanAoGBAI8J4yi4hrQsZ4HcSMjm\n" +
            "ZP8c8t52rYlBjREZKhXGnD1Tf0J/1JYrXuAZraFlU1dV1KCI79OKkZXNPVp8Hbla\n" +
            "xmY/A9475dpgtZWHUcY74Qe9ukjMhIUFrJiLz0k9Z6kgkYYUrF2CXCDESJITK8ua\n" +
            "cxf9GiuFABn9hUe3KYDWif8RAoGAAJODPrSF443Xf/WRmfTZMqrS5T/QcvUeHP3h\n" +
            "pxUECHXt/dyR06rKc2+bf3VcH+0dVEDoQa8UpLW/NDSXjrBoIBG69SaIW8xgO19I\n" +
            "46Tn87R+IGObuH8p59s4IrkggMRtWJX46OLwOqOdUirDI4Zd29hLxlmtkJ1SlWZ6\n" +
            "/CZP2gUCgYABovbymdjairK5gUWRvCQ6RhHEuuhQJ8mhPpmdwhrPaLPxFvB+bVuo\n" +
            "QBRchS2A9LEfS80TiTqtqn4SHHDcQVGba2FY5ppZdKspL8sOs/1s0AAbocC6d2a3\n" +
            "0GH7mCazBo5jba6DdmFLqT8JMO5ZFyTOk/G1Q0WAAm9hFYDnk47n+w==\n" +
            "-----END RSA PRIVATE KEY-----";

    @Test
    void testLoadCertificateFromString() throws Exception {
        X509Certificate cert = CertificateHelper.loadCertificateFromString(TEST_CERT_PEM);

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
        PrivateKey key = CertificateHelper.loadPrivateKeyFromString(TEST_KEY_PEM);

        assertNotNull(key);
        assertEquals("RSA", key.getAlgorithm());
        assertEquals("PKCS#8", key.getFormat());
    }

    @Test
    void testLoadRsaPrivateKeyFromString() throws Exception {
        PrivateKey key = CertificateHelper.loadPrivateKeyFromString(TEST_RSA_PRIVATE_KEY_PEM);

        assertNotNull(key);
        assertEquals("RSA", key.getAlgorithm());
        assertEquals("PKCS#8", key.getFormat());
    }

    @Test
    void testLoadPrivateKeyFromStringInvalid() {
        assertThrows(Exception.class, () -> CertificateHelper.loadPrivateKeyFromString("not-a-valid-key"));
    }
}