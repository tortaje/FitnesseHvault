package io.github.tortaje.hvault.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.tortaje.hvault.VaultFixtureException;
import io.github.tortaje.hvault.config.VaultConfig;
import io.github.tortaje.hvault.testsupport.FakeVault;
import io.github.tortaje.hvault.testsupport.Pems;
import io.opentelemetry.api.common.Attributes;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import io.github.tortaje.hvault.testsupport.LogCapture;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.Test;

class VaultHttpClientTest {

    private final List<Duration> sleeps = new ArrayList<>();

    private RetryPolicy policy() {
        return new RetryPolicy(3, Duration.ofMillis(1000), sleeps::add, () -> 0);
    }

    private VaultHttpClient client(VaultConfig.Builder b) {
        return new VaultHttpClient(b.build(), policy());
    }

    private String get(VaultHttpClient c, String token) {
        return c.get("/v1/secret/data/a", "GET /v1/{mount}/data/{path}", Attributes.empty(), token,
                r -> r.status() + ":" + r.body());
    }

    @Test
    void sendsHeadersAndReturnsHandlerResult() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", "/v1/secret/data/a", 200, "{\"ok\":1}");
            v.enqueue("GET", "/v1/secret/data/a", 200, "{\"ok\":2}");
            assertEquals("200:{\"ok\":1}", get(client(VaultConfig.builder(v.url()).namespace("team-a")), "tok"));
            assertEquals("200:{\"ok\":2}", get(client(VaultConfig.builder(v.url())), "tok"));
            var first = v.requests().get(0).headers();
            assertEquals("tok", first.get("x-vault-token"));
            assertEquals("team-a", first.get("x-vault-namespace"));
            assertFalse(v.requests().get(1).headers().containsKey("x-vault-namespace"));
        }
    }

    @Test
    void noDoubleSlashWithTrailingSlashAddr() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", "/v1/secret/data/a", 200, "{}");
            assertEquals("200:{}", get(client(VaultConfig.builder(v.url() + "/")), "t"));
            assertEquals("/v1/secret/data/a", v.requests().get(0).path());
        }
    }

    @Test
    void retriesOn503ThenSucceeds() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", "/v1/secret/data/a", 503, "{}");
            v.enqueue("GET", "/v1/secret/data/a", 503, "{}");
            v.enqueue("GET", "/v1/secret/data/a", 200, "{}");
            assertEquals("200:{}", get(client(VaultConfig.builder(v.url())), "t"));
            assertEquals(3, v.requests().size());
            assertEquals(List.of(Duration.ofMillis(1000), Duration.ofMillis(2000)), sleeps);
        }
    }

    @Test
    void doesNotRetryOn404() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", "/v1/secret/data/a", 404, "{}");
            assertEquals("404:{}", get(client(VaultConfig.builder(v.url())), "t"));
            assertEquals(1, v.requests().size());
            assertTrue(sleeps.isEmpty());
        }
    }

    @Test
    void exhaustedStatus() {
        try (FakeVault v = FakeVault.http()) {
            for (int i = 0; i < 3; i++) {
                v.enqueue("GET", "/v1/secret/data/a", 503, "{\"errors\":[\"Vault is sealed\"]}");
            }
            VaultHttpClient c = client(VaultConfig.builder(v.url()));
            VaultFixtureException e = assertThrows(VaultFixtureException.class, () -> c.get("/v1/secret/data/a",
                    "s", Attributes.empty(), "t", r -> {
                        throw new AssertionError("handler must not be called");
                    }));
            assertEquals("Vault unreachable after 3 attempts: HTTP 503 Vault is sealed", e.getMessage());
        }
    }

    private static String closedPortUrl() throws IOException {
        try (ServerSocket s = new ServerSocket(0)) {
            return "http://127.0.0.1:" + s.getLocalPort();
        }
    }

    @Test
    void networkErrorsExhausted() throws IOException {
        VaultHttpClient c = client(VaultConfig.builder(closedPortUrl()).requestTimeout(Duration.ofMillis(300)));
        VaultFixtureException e = assertThrows(VaultFixtureException.class, () -> get(c, "t"));
        assertTrue(e.getMessage().startsWith("Vault unreachable after 3 attempts: "), e.getMessage());
        assertNotNull(e.getCause());
        assertEquals(2, sleeps.size());
    }

    @Test
    void requestTimeoutIsRetried() {
        try (FakeVault v = FakeVault.http()) {
            for (int i = 0; i < 3; i++) {
                v.enqueueDelay("GET", "/v1/secret/data/a", Duration.ofSeconds(1));
            }
            VaultHttpClient c = client(VaultConfig.builder(v.url()).requestTimeout(Duration.ofMillis(200)));
            VaultFixtureException e = assertThrows(VaultFixtureException.class, () -> get(c, "t"));
            assertTrue(e.getMessage().startsWith("Vault unreachable after 3 attempts: "), e.getMessage());
        }
    }

    @Test
    void tlsWithCaCert() throws IOException {
        Path ca = Files.createTempFile("ca", ".pem");
        try (FakeVault v = FakeVault.https(Pems.read("server.pem"), Pems.read("server.key"))) {
            Files.writeString(ca, Pems.read("ca.pem"));
            v.enqueue("GET", "/v1/secret/data/a", 200, "{}");
            assertEquals("200:{}", get(client(VaultConfig.builder(v.url()).caCert(ca)), "t"));
        } finally {
            Files.deleteIfExists(ca);
        }
    }

    @Test
    void tlsErrorNotRetried() {
        try (FakeVault v = FakeVault.https(Pems.read("server.pem"), Pems.read("server.key"))) {
            VaultHttpClient c = client(VaultConfig.builder(v.url()).requestTimeout(Duration.ofSeconds(2)));
            VaultFixtureException e = assertThrows(VaultFixtureException.class, () -> get(c, "t"));
            assertEquals("TLS error to Vault: check VAULT_CACERT", e.getMessage());
            assertTrue(sleeps.isEmpty());
        }
    }

    @Test
    void postSendsJsonBody() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", "/v1/auth/k/login", 200, "{}");
            VaultHttpClient c = client(VaultConfig.builder(v.url()));
            String body = "{\"role\":\"r\",\"jwt\":\"j\"}";
            c.post("/v1/auth/k/login", "POST /v1/auth/{mount}/login", Attributes.empty(), null, body,
                    r -> r.status());
            var rec = v.requests().get(0);
            assertEquals(body, rec.body());
            assertEquals("application/json", rec.headers().get("content-type"));
            assertFalse(rec.headers().containsKey("x-vault-token"));
        }
    }

    @Test
    void invalidCaCertFile() throws IOException {
        Path junk = Files.createTempFile("not-pem", ".pem");
        Files.writeString(junk, "this is not a certificate");
        Path missing = junk.resolveSibling("does-not-exist.pem");
        try {
            for (Path p : new Path[] {junk, missing}) {
                VaultFixtureException e = assertThrows(VaultFixtureException.class,
                        () -> new VaultHttpClient(VaultConfig.builder("https://localhost:1").caCert(p).build(), policy()));
                assertEquals("Invalid VAULT_CACERT file " + p, e.getMessage());
            }
        } finally {
            Files.deleteIfExists(junk);
        }
    }

    @Test
    void logsEachFailedAttempt() {
        try (FakeVault v = FakeVault.http(); LogCapture logs = LogCapture.on(VaultHttpClient.class.getName())) {
            for (int i = 0; i < 3; i++) v.enqueue("GET", "/v1/secret/data/a", 503, "{}");
            assertThrows(VaultFixtureException.class, () -> get(client(VaultConfig.builder(v.url())), "t"));
            assertEquals(List.of(
                    "Vault GET /v1/secret/data/a: attempt 1/3 failed (HTTP 503), retrying in 1000 ms",
                    "Vault GET /v1/secret/data/a: attempt 2/3 failed (HTTP 503), retrying in 2000 ms",
                    "Vault GET /v1/secret/data/a: attempt 3/3 failed (HTTP 503), giving up"),
                    messages(logs, Level.WARNING));
        }
    }

    @Test
    void logsNetworkFailures() throws IOException {
        try (LogCapture logs = LogCapture.on(VaultHttpClient.class.getName())) {
            VaultHttpClient c = client(VaultConfig.builder(closedPortUrl()));
            assertThrows(VaultFixtureException.class, () -> get(c, "t"));
            List<String> warnings = messages(logs, Level.WARNING);
            assertEquals(3, warnings.size());
            assertTrue(warnings.get(0).startsWith("Vault GET /v1/secret/data/a: attempt 1/3 failed (java.net.ConnectException"),
                    warnings.get(0));
            assertTrue(warnings.get(0).endsWith("), retrying in 1000 ms"), warnings.get(0));
            assertTrue(warnings.get(2).endsWith("), giving up"), warnings.get(2));
        }
    }

    @Test
    void noLogWhenFirstAttemptSucceeds() {
        try (FakeVault v = FakeVault.http(); LogCapture logs = LogCapture.on(VaultHttpClient.class.getName())) {
            v.enqueue("GET", "/v1/secret/data/a", 200, "{}");
            get(client(VaultConfig.builder(v.url())), "t");
            assertTrue(logs.records().isEmpty());
        }
    }

    private static List<String> messages(LogCapture logs, Level level) {
        return logs.records().stream().filter(r -> r.getLevel() == level).map(LogRecord::getMessage).toList();
    }

    @Test
    void followsRedirectToActiveNodeWithToken() {
        try (FakeVault standby = FakeVault.http(); FakeVault active = FakeVault.http()) {
            standby.enqueueRedirect("GET", "/v1/secret/data/a", active.url() + "/v1/secret/data/a");
            active.enqueue("GET", "/v1/secret/data/a", 200, "{\"ok\":1}");
            assertEquals("200:{\"ok\":1}", get(client(VaultConfig.builder(standby.url())), "tok"));
            assertEquals("tok", active.requests().get(0).headers().get("x-vault-token"));
        }
    }

    @Test
    void doesNotFollowRedirectFromHttpsToHttp() throws IOException {
        Path ca = Files.createTempFile("ca", ".pem");
        Files.writeString(ca, Pems.read("ca.pem"));
        try (FakeVault tls = FakeVault.https(Pems.read("server.pem"), Pems.read("server.key"));
             FakeVault plain = FakeVault.http()) {
            tls.enqueueRedirect("GET", "/v1/secret/data/a", plain.url() + "/v1/secret/data/a");
            assertEquals("307:", get(client(VaultConfig.builder(tls.url()).caCert(ca)), "tok"));
            assertTrue(plain.requests().isEmpty());
        } finally {
            Files.deleteIfExists(ca);
        }
    }

    @Test
    void warnsAboutPlainHttpToRemoteHost() {
        String name = VaultHttpClient.class.getName();
        try (LogCapture logs = LogCapture.on(name)) {
            client(VaultConfig.builder("http://vault.example.com:8200"));
            assertEquals(List.of("VAULT_ADDR uses plain HTTP to vault.example.com: the Vault token and secrets "
                    + "are sent unencrypted"), messages(logs, Level.WARNING));
        }
        for (String quiet : new String[] {"http://127.0.0.1:8200", "http://localhost:8200", "https://vault.example.com"}) {
            try (LogCapture logs = LogCapture.on(name)) {
                client(VaultConfig.builder(quiet));
                assertTrue(logs.records().isEmpty(), quiet);
            }
        }
    }
}
