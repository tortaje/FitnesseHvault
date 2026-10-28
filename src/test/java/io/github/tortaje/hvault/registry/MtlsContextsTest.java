package io.github.tortaje.hvault.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.tortaje.hvault.testsupport.Pems;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class MtlsContextsTest {

    @AfterEach
    void cleanUp() {
        SecretRegistry.clear();
    }

    private void load(String cert, String key, String ca) {
        SecretRegistry.put("c", Pems.read(cert));
        SecretRegistry.put("k", Pems.read(key));
        if (ca != null) {
            SecretRegistry.put("ca", Pems.read(ca));
        }
    }

    @Test
    void rsaPkcs8() {
        load("client-rsa.pem", "client-rsa-pkcs8.key", "ca.pem");
        assertNotNull(MtlsContexts.fromRegistry("c", "k", "ca"));
    }

    @Test
    void rsaPkcs1IsConverted() {
        load("client-rsa.pem", "client-rsa-pkcs1.key", "ca.pem");
        assertNotNull(MtlsContexts.fromRegistry("c", "k", "ca"));
    }

    @Test
    void ecPkcs8() {
        load("client-ec.pem", "client-ec-pkcs8.key", "ca.pem");
        assertNotNull(MtlsContexts.fromRegistry("c", "k", "ca"));
    }

    @Test
    void certificateChainAccepted() {
        load("client-chain.pem", "client-rsa-pkcs8.key", "ca.pem");
        assertNotNull(MtlsContexts.fromRegistry("c", "k", "ca"));
    }

    @Test
    void nullCaUsesJvmTruststore() {
        load("client-rsa.pem", "client-rsa-pkcs8.key", null);
        assertNotNull(MtlsContexts.fromRegistry("c", "k", null));
    }

    private void assertUnsupported() {
        var e = assertThrows(IllegalStateException.class, () -> MtlsContexts.fromRegistry("c", "k", "ca"));
        assertEquals("Unsupported key format in 'k'", e.getMessage());
    }

    @Test
    void ecSec1Rejected() {
        load("client-ec.pem", "client-ec-sec1.key", "ca.pem");
        assertUnsupported();
    }

    @Test
    void encryptedKeyRejected() {
        load("client-rsa.pem", "client-encrypted.key", "ca.pem");
        assertUnsupported();
    }

    @Test
    void garbageKeyRejected() {
        load("client-rsa.pem", "client-rsa-pkcs8.key", "ca.pem");
        SecretRegistry.put("k", "not a pem");
        assertUnsupported();
        var e = assertThrows(IllegalStateException.class, () -> MtlsContexts.fromRegistry("c", "k", "ca"));
        assertFalse(e.getMessage().contains("not a pem"));
    }

    @Test
    void missingVariable() {
        SecretRegistry.put("c", Pems.read("client-rsa.pem"));
        var e = assertThrows(IllegalStateException.class, () -> MtlsContexts.fromRegistry("c", "k", null));
        assertEquals("Registry variable 'k' missing", e.getMessage());
    }

    /** Runs a TLS echo server on a background thread; returns the sockets' peer certificate seen by the server. */
    private static final class Server implements AutoCloseable {
        final SSLServerSocket socket;
        final AtomicReference<X509Certificate> clientCert = new AtomicReference<>();
        final Thread thread;

        Server(boolean needClientAuth) throws IOException {
            SecretRegistry.put("s.c", Pems.read("server.pem"));
            SecretRegistry.put("s.k", Pems.read("server.key"));
            SecretRegistry.put("s.ca", Pems.read("ca.pem"));
            SSLContext ctx = MtlsContexts.fromRegistry("s.c", "s.k", "s.ca");
            socket = (SSLServerSocket) ctx.getServerSocketFactory()
                    .createServerSocket(0, 5, InetAddress.getByName("127.0.0.1"));
            socket.setNeedClientAuth(needClientAuth);
            socket.setSoTimeout(5000);
            thread = new Thread(this::serve);
            thread.setDaemon(true);
            thread.start();
        }

        private void serve() {
            try (SSLSocket s = (SSLSocket) socket.accept()) {
                s.setSoTimeout(5000);
                s.startHandshake();
                try {
                    clientCert.set((X509Certificate) s.getSession().getPeerCertificates()[0]);
                } catch (SSLException ignored) {
                    // no client certificate
                }
                int b = s.getInputStream().read();
                s.getOutputStream().write(b);
                s.getOutputStream().flush();
            } catch (IOException ignored) {
                // handshake failures are asserted on the client side
            }
        }

        int port() {
            return socket.getLocalPort();
        }

        @Override
        public void close() throws Exception {
            socket.close();
            thread.join(5000);
        }
    }

    /** Connects, then does a one-byte exchange so TLS 1.3 post-handshake rejections surface. */
    private static void connectAndExchange(SSLContext ctx, int port) throws IOException {
        try (SSLSocket c = (SSLSocket) ctx.getSocketFactory().createSocket()) {
            c.setSoTimeout(5000);
            c.connect(new InetSocketAddress("127.0.0.1", port), 5000);
            c.startHandshake();
            c.getOutputStream().write(42);
            c.getOutputStream().flush();
            assertEquals(42, c.getInputStream().read());
        }
    }

    @Test
    void mutualTlsHandshake() throws Exception {
        try (Server server = new Server(true)) {
            load("client-rsa.pem", "client-rsa-pkcs1.key", "ca.pem");
            connectAndExchange(MtlsContexts.fromRegistry("c", "k", "ca"), server.port());
            server.thread.join(5000);
            assertNotNull(server.clientCert.get());
            assertTrue(server.clientCert.get().getSubjectX500Principal().getName().contains("client-rsa"));
        }
    }

    @Test
    void handshakeFailsWithUnrelatedCa() throws Exception {
        try (Server server = new Server(true)) {
            load("client-rsa.pem", "client-rsa-pkcs8.key", "other-ca.pem");
            SSLContext ctx = MtlsContexts.fromRegistry("c", "k", "ca");
            assertThrows(SSLHandshakeException.class, () -> connectAndExchange(ctx, server.port()));
        }
    }

    @Test
    void trustingOnly() throws Exception {
        try (Server server = new Server(false)) {
            connectAndExchange(MtlsContexts.trustingOnly(Pems.read("ca.pem")), server.port());
        }
        try (Server server = new Server(false)) {
            SSLContext untrusting = MtlsContexts.trustingOnly(Pems.read("other-ca.pem"));
            assertThrows(SSLHandshakeException.class, () -> connectAndExchange(untrusting, server.port()));
        }
    }
}
