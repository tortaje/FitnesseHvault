package io.github.tortaje.hvault.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.tortaje.hvault.testsupport.Pems;
import org.junit.jupiter.api.Test;

class PemReaderTest {

    @Test
    void readsEd25519Pkcs8Key() {
        assertEquals("EdDSA", PemReader.privateKey(Pems.read("client-ed25519.key"), "k").getAlgorithm());
    }

    @Test
    void readsRsaPssPkcs8Key() {
        assertEquals("RSASSA-PSS", PemReader.privateKey(Pems.read("client-rsapss.key"), "k").getAlgorithm());
    }

    @Test
    void stillReadsRsaAndEc() {
        assertEquals("RSA", PemReader.privateKey(Pems.read("client-rsa-pkcs8.key"), "k").getAlgorithm());
        assertEquals("RSA", PemReader.privateKey(Pems.read("client-rsa-pkcs1.key"), "k").getAlgorithm());
        assertEquals("EC", PemReader.privateKey(Pems.read("client-ec-pkcs8.key"), "k").getAlgorithm());
    }

    @Test
    void pemWithoutCertificate() {
        assertEquals("No certificate found in PEM value",
                assertThrows(IllegalStateException.class, () -> PemReader.certificates("")).getMessage());
        assertEquals("Invalid certificate PEM value",
                assertThrows(IllegalStateException.class, () -> PemReader.certificates("not a pem")).getMessage());
        assertEquals("Invalid certificate PEM value", assertThrows(IllegalStateException.class,
                () -> PemReader.certificates(Pems.read("client-rsa-pkcs8.key"))).getMessage());
    }

    @Test
    void malformedKeyBodies() {
        String badBase64 = "-----BEGIN PRIVATE KEY-----\n@@@not base64@@@\n-----END PRIVATE KEY-----\n";
        String noEnd = "-----BEGIN PRIVATE KEY-----\nMIIB\n";
        String validBase64NotAKey = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        for (String pem : new String[] {badBase64, noEnd, validBase64NotAKey}) {
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> PemReader.privateKey(pem, "k"));
            assertEquals("Unsupported key format in 'k'", e.getMessage());
        }
    }

    @Test
    void pkcs1WrappingUsesShortDerLengthsForSmallKeys() {
        byte[] out = PemReader.pkcs1ToPkcs8(new byte[] {1, 2, 3});
        // SEQUENCE (0x30) of 3 (version) + 15 (algorithm id) + 5 (OCTET STRING header + 3 bytes) = 23 bytes
        assertEquals(25, out.length);
        assertEquals(0x30, out[0]);
        assertEquals(23, out[1]);
        assertEquals(0x04, out[20]);
        assertEquals(3, out[21]);
    }
}
