package io.github.tortaje.hvault.registry;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** Minimal PEM parsing for certificates and unencrypted RSA, RSA-PSS, EC and EdDSA private keys. */
final class PemReader {

    private static final String PKCS8_BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String PKCS8_END = "-----END PRIVATE KEY-----";
    private static final String PKCS1_BEGIN = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String PKCS1_END = "-----END RSA PRIVATE KEY-----";
    // PKCS#8 key types usable for a TLS client certificate (EdDSA covers Ed25519 and Ed448)
    private static final String[] KEY_ALGORITHMS = {"RSA", "EC", "RSASSA-PSS", "EdDSA"};

    private PemReader() {
    }

    static List<X509Certificate> certificates(String pem) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> result = new ArrayList<>();
            for (var c : factory.generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)))) {
                result.add((X509Certificate) c);
            }
            if (result.isEmpty()) {
                throw new IllegalStateException("No certificate found in PEM value");
            }
            return result;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Invalid certificate PEM value");
        }
    }

    static PrivateKey privateKey(String pem, String varName) {
        IllegalStateException unsupported =
                new IllegalStateException("Unsupported key format in '" + varName + "'");
        try {
            byte[] pkcs8;
            if (pem.contains(PKCS8_BEGIN)) {
                pkcs8 = body(pem, PKCS8_BEGIN, PKCS8_END);
            } else if (pem.contains(PKCS1_BEGIN)) {
                pkcs8 = pkcs1ToPkcs8(body(pem, PKCS1_BEGIN, PKCS1_END));
            } else {
                throw unsupported;
            }
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
            for (String algorithm : KEY_ALGORITHMS) {
                try {
                    return KeyFactory.getInstance(algorithm).generatePrivate(spec);
                } catch (GeneralSecurityException ignored) {
                    // try next algorithm
                }
            }
        } catch (IllegalArgumentException | IndexOutOfBoundsException e) {
            // fall through: malformed base64 or markers
        }
        throw unsupported;
    }

    private static byte[] body(String pem, String begin, String end) {
        int from = pem.indexOf(begin) + begin.length();
        int to = pem.indexOf(end, from);
        String base64 = pem.substring(from, to).replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    // PrivateKeyInfo ::= SEQUENCE { INTEGER 0, SEQUENCE { OID rsaEncryption, NULL }, OCTET STRING pkcs1 }
    static byte[] pkcs1ToPkcs8(byte[] pkcs1) {
        byte[] algId = {0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d,
            0x01, 0x01, 0x01, 0x05, 0x00};
        byte[] version = {0x02, 0x01, 0x00};
        byte[] octet = concat(new byte[] {0x04}, derLength(pkcs1.length), pkcs1);
        byte[] body = concat(version, algId, octet);
        return concat(new byte[] {0x30}, derLength(body.length), body);
    }

    private static byte[] derLength(int n) {
        if (n < 128) {
            return new byte[] {(byte) n};
        }
        int count = 0;
        for (int v = n; v > 0; v >>>= 8) {
            count++;
        }
        byte[] out = new byte[count + 1];
        out[0] = (byte) (0x80 | count);
        for (int i = count; i >= 1; i--) {
            out[i] = (byte) n;
            n >>>= 8;
        }
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] p : parts) {
            length += p.length;
        }
        byte[] out = new byte[length];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }
}
