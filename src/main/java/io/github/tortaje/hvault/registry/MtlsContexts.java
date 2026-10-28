package io.github.tortaje.hvault.registry;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Builds {@link SSLContext}s from PEM values held in the {@link SecretRegistry}. */
public final class MtlsContexts {

    private MtlsContexts() {
    }

    /**
     * Builds a mutual-TLS context. Accepts a certificate chain and a PKCS#8 (RSA or EC) or PKCS#1 (RSA)
     * private key.
     *
     * @param caVar registry variable holding trusted CA certificates, or null for the JVM truststore
     */
    public static SSLContext fromRegistry(String certVar, String keyVar, String caVar) {
        String certPem = SecretRegistry.get(certVar);
        String keyPem = SecretRegistry.get(keyVar);
        String caPem = caVar == null ? null : SecretRegistry.get(caVar);
        List<X509Certificate> chain = PemReader.certificates(certPem);
        PrivateKey key = PemReader.privateKey(keyPem, keyVar);
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("client", key, new char[0], chain.toArray(new Certificate[0]));
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, new char[0]);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), trustManagers(caPem), null);
            return context;
        } catch (GeneralSecurityException | java.io.IOException e) {
            throw new IllegalStateException("Unable to build TLS context from '" + certVar + "'");
        }
    }

    /** Builds a context that trusts only the given CA certificates and presents no client certificate. */
    public static SSLContext trustingOnly(String caPem) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustManagers(caPem), null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to build TLS context from CA certificates");
        }
    }

    private static javax.net.ssl.TrustManager[] trustManagers(String caPem) throws GeneralSecurityException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        if (caPem == null) {
            tmf.init((KeyStore) null);
        } else {
            try {
                KeyStore trust = KeyStore.getInstance("PKCS12");
                trust.load(null, null);
                int i = 0;
                for (X509Certificate cert : PemReader.certificates(caPem)) {
                    trust.setCertificateEntry("ca-" + i++, cert);
                }
                tmf.init(trust);
            } catch (java.io.IOException e) {
                throw new GeneralSecurityException(e);
            }
        }
        return tmf.getTrustManagers();
    }
}
