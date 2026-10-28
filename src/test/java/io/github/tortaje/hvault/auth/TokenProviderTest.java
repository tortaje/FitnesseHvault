package io.github.tortaje.hvault.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.tortaje.hvault.VaultFixtureException;
import io.github.tortaje.hvault.client.RetryPolicy;
import io.github.tortaje.hvault.client.VaultHttpClient;
import io.github.tortaje.hvault.config.VaultConfig;
import io.github.tortaje.hvault.testsupport.FakeVault;
import io.github.tortaje.hvault.testsupport.LogCapture;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.json.JSONObject;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TokenProviderTest {

    private static final String LOGIN = "/v1/auth/kubernetes/login";

    @TempDir
    Path tmp;

    private static final class MutableClock extends Clock {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    private final MutableClock clock = new MutableClock();

    private Path jwt(String content) throws IOException {
        Path p = tmp.resolve("jwt");
        Files.writeString(p, content);
        return p;
    }

    private TokenProvider provider(VaultConfig cfg) {
        RetryPolicy retry = new RetryPolicy(3, Duration.ofMillis(1), d -> { }, () -> 0);
        return new TokenProvider(cfg, new VaultHttpClient(cfg, retry), clock);
    }

    private static String loginBody(String token, int lease) {
        return "{\"auth\":{\"client_token\":\"" + token + "\",\"lease_duration\":" + lease + "}}";
    }

    @Test
    void staticTokenUsedWithoutLogin() {
        try (FakeVault v = FakeVault.http()) {
            TokenProvider tp = provider(VaultConfig.builder(v.url()).token("hvs.STATIC").build());
            assertEquals("hvs.STATIC", tp.token());
            assertEquals(0, v.requests().size());
            assertFalse(tp.canRelogin());
            assertEquals("the provided token", tp.authDescription());
        }
    }

    @Test
    void kubernetesLogin() throws IOException {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", LOGIN, 200, loginBody("hvs.K8S", 3600));
            TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt("my.jwt\n")).build());
            assertEquals("hvs.K8S", tp.token());
            assertEquals("hvs.K8S", tp.token());
            assertEquals(1, v.requests().size());
            JSONObject sent = new JSONObject(v.requests().get(0).body());
            assertEquals("r", sent.getString("role"));
            assertEquals("my.jwt", sent.getString("jwt"));
            assertTrue(tp.canRelogin());
            assertEquals("role 'r'", tp.authDescription());
        }
    }

    @Test
    void customK8sAuthPath() throws IOException {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", "/v1/auth/k8s-roks/login", 200, loginBody("t", 3600));
            TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sAuthPath("k8s-roks")
                    .k8sTokenPath(jwt("j")).build());
            assertEquals("t", tp.token());
            assertEquals("/v1/auth/k8s-roks/login", v.requests().get(0).path());
        }
    }

    @Test
    void reloginWhenLeaseNearlyExpired() throws IOException {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", LOGIN, 200, loginBody("t1", 3600));
            v.enqueue("POST", LOGIN, 200, loginBody("t2", 3600));
            TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt("j")).build());
            assertEquals("t1", tp.token());
            clock.now = clock.now.plusSeconds(3569);
            assertEquals("t1", tp.token());
            assertEquals(1, v.requests().size());
            clock.now = clock.now.plusSeconds(2);
            assertEquals("t2", tp.token());
            assertEquals(2, v.requests().size());
        }
    }

    @Test
    void zeroLeaseNeverExpires() throws IOException {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", LOGIN, 200, loginBody("t1", 0));
            TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt("j")).build());
            tp.token();
            clock.now = clock.now.plus(Duration.ofDays(10));
            assertEquals("t1", tp.token());
            assertEquals(1, v.requests().size());
        }
    }

    @Test
    void invalidateForcesLoginAndRereadsJwt() throws IOException {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", LOGIN, 200, loginBody("t1", 3600));
            v.enqueue("POST", LOGIN, 200, loginBody("t2", 3600));
            Path p = jwt("jwt-one");
            TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(p).build());
            tp.token();
            Files.writeString(p, "jwt-two");
            tp.invalidate();
            assertEquals("t2", tp.token());
            assertEquals("jwt-two", new JSONObject(v.requests().get(1).body()).getString("jwt"));
        }
    }

    @Test
    void loginRejected() throws IOException {
        for (int code : new int[] {403, 400}) {
            try (FakeVault v = FakeVault.http()) {
                v.enqueue("POST", LOGIN, code, "{\"errors\":[\"nope\"]}");
                TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt("j")).build());
                VaultFixtureException e = assertThrows(VaultFixtureException.class, tp::token);
                assertEquals("Kubernetes login rejected for role 'r' (HTTP " + code + ")", e.getMessage());
                assertEquals(1, v.requests().size());
            }
        }
    }

    @Test
    void noAuthAvailable() {
        String msg = "No Vault auth available: set VAULT_TOKEN, or VAULT_ROLE with a mounted service account token";
        try (FakeVault v = FakeVault.http()) {
            TokenProvider none = provider(VaultConfig.builder(v.url()).build());
            assertEquals(msg, assertThrows(VaultFixtureException.class, none::token).getMessage());
            TokenProvider noFile = provider(VaultConfig.builder(v.url()).role("r")
                    .k8sTokenPath(tmp.resolve("absent")).build());
            assertEquals(msg, assertThrows(VaultFixtureException.class, noFile::token).getMessage());
        }
    }

    @Test
    void concurrentFirstCallsLoginOnce() throws Exception {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", LOGIN, 200, loginBody("t1", 3600));
            TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt("j")).build());
            ExecutorService ex = Executors.newFixedThreadPool(8);
            CountDownLatch go = new CountDownLatch(1);
            List<Future<String>> fs = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                fs.add(ex.submit(() -> {
                    go.await();
                    return tp.token();
                }));
            }
            go.countDown();
            for (Future<String> f : fs) assertEquals("t1", f.get());
            ex.shutdown();
            assertEquals(1, v.requests().size());
        }
    }

    @Test
    void jwtNeverLogged() throws IOException {
        try (FakeVault v = FakeVault.http(); LogCapture logs = LogCapture.on("io.github.tortaje.hvault")) {
            v.enqueue("POST", LOGIN, 200, loginBody("CLIENT-TOKEN-XYZ", 3600));
            TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt("SECRET-JWT-ABC")).build());
            tp.token();
            assertFalse(logs.allText().contains("SECRET-JWT-ABC"));
            assertFalse(logs.allText().contains("CLIENT-TOKEN-XYZ"));
        }
    }

    @Test
    void logsStaticMode() {
        try (FakeVault v = FakeVault.http(); LogCapture logs = LogCapture.on(TokenProvider.class.getName())) {
            TokenProvider tp = provider(VaultConfig.builder(v.url()).token("hvs.STATIC").build());
            tp.token();
            tp.token();
            assertEquals(List.of("Vault auth: static token"), messages(logs, Level.INFO));
        }
    }

    @Test
    void logsKubernetesLoginAndRenewal() throws IOException {
        try (FakeVault v = FakeVault.http(); LogCapture logs = LogCapture.on(TokenProvider.class.getName())) {
            v.enqueue("POST", LOGIN, 200, loginBody("t1", 3600));
            v.enqueue("POST", LOGIN, 200, loginBody("t2", 0));
            TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt("j")).build());
            tp.token();
            clock.now = clock.now.plusSeconds(3571);
            tp.token();
            assertEquals(List.of(
                    "Vault auth: Kubernetes login with role 'r' (auth path kubernetes)",
                    "Kubernetes login succeeded for role 'r', Vault token valid for 3600 s",
                    "Vault token for role 'r' expires soon, logging in again",
                    "Kubernetes login succeeded for role 'r', Vault token does not expire"),
                    messages(logs, Level.INFO));
        }
    }

    private static List<String> messages(LogCapture logs, Level level) {
        return logs.records().stream().filter(r -> r.getLevel() == level).map(LogRecord::getMessage).toList();
    }

    @Test
    void shortLeaseKeepsTokenForHalfItsLifetime() throws IOException {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", LOGIN, 200, loginBody("t1", 20));
            v.enqueue("POST", LOGIN, 200, loginBody("t2", 20));
            TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt("j")).build());
            assertEquals("t1", tp.token());
            clock.now = clock.now.plusSeconds(9);
            assertEquals("t1", tp.token());
            assertEquals(1, v.requests().size());
            clock.now = clock.now.plusSeconds(1);
            assertEquals("t2", tp.token());
            assertEquals(2, v.requests().size());
        }
    }

    @Test
    void loginWithOtherErrorStatus() throws IOException {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", LOGIN, 404, "{\"errors\":[\"no handler for route\"]}");
            TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt("j")).build());
            VaultFixtureException e = assertThrows(VaultFixtureException.class, tp::token);
            assertEquals("Vault error on auth/kubernetes/login (HTTP 404): no handler for route", e.getMessage());
        }
    }

    @Test
    void loginWithErrorStatusAndNoMessage() throws IOException {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", LOGIN, 405, "");
            TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt("j")).build());
            assertEquals("Vault error on auth/kubernetes/login (HTTP 405)",
                    assertThrows(VaultFixtureException.class, tp::token).getMessage());
        }
    }

    @Test
    void loginWithUnexpectedBody() throws IOException {
        for (String body : new String[] {"not json", "{}", "{\"auth\":{\"lease_duration\":60}}"}) {
            try (FakeVault v = FakeVault.http()) {
                v.enqueue("POST", LOGIN, 200, body);
                TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt("j")).build());
                assertEquals("Vault error on auth/kubernetes/login (HTTP 200): unexpected response",
                        assertThrows(VaultFixtureException.class, tp::token).getMessage(), body);
            }
        }
    }

    @Test
    void jwtFileRemovedBeforeRelogin() throws IOException {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", LOGIN, 200, loginBody("t1", 3600));
            Path file = jwt("j");
            TokenProvider tp = provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(file).build());
            assertEquals("t1", tp.token());
            Files.delete(file);
            tp.invalidate();
            VaultFixtureException e = assertThrows(VaultFixtureException.class, tp::token);
            assertEquals("No Vault auth available: set VAULT_TOKEN, or VAULT_ROLE with a mounted service account token",
                    e.getMessage());
            assertEquals(1, v.requests().size());
        }
    }

    @Test
    void canReloginBeforeFirstToken() throws IOException {
        try (FakeVault v = FakeVault.http()) {
            assertTrue(provider(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt("j")).build()).canRelogin());
            assertFalse(provider(VaultConfig.builder(v.url()).build()).canRelogin());
            assertEquals("the provided token", provider(VaultConfig.builder(v.url()).build()).authDescription());
            assertEquals(0, v.requests().size());
        }
    }
}
