package io.github.tortaje.hvault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.tortaje.hvault.client.Sleeper;
import io.github.tortaje.hvault.config.VaultConfig;
import io.github.tortaje.hvault.registry.SecretRegistry;
import io.github.tortaje.hvault.testsupport.FakeVault;
import io.github.tortaje.hvault.testsupport.LogCapture;
import java.time.Clock;
import java.util.Properties;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HVaultTest {

    private static final String SECRET = "s3cr3t-VALUE-42";
    private static final String TOKEN = "hvs.TEST-TOKEN";
    private static final String PATH = "/v1/secret/data/app/oauth";

    private LogCapture logs;

    @BeforeEach
    void setUp() {
        SecretRegistry.clear();
        logs = LogCapture.on("io.github.tortaje.hvault");
    }

    @AfterEach
    void tearDown() {
        logs.close();
        SecretRegistry.clear();
    }

    private HVault fixture(FakeVault v) {
        Sleeper noSleep = d -> { };
        VaultConfig cfg = VaultConfig.builder(v.url()).token(TOKEN).retryMaxAttempts(1).build();
        return new HVault(() -> VaultRuntime.create(cfg, noSleep, Clock.systemUTC()));
    }

    private static String kv(String dataJson) {
        return "{\"data\":{\"data\":" + dataJson + ",\"metadata\":{}}}";
    }

    private void assertNoLeak(String text) {
        assertFalse(text.contains(SECRET), "secret leaked: " + text);
        assertFalse(text.contains(TOKEN), "token leaked: " + text);
    }

    private void assertNoLeak(Throwable t) {
        for (; t != null; t = t.getCause()) {
            assertNoLeak(String.valueOf(t.getMessage()));
        }
        assertNoLeak(logs.allText());
    }

    @Test
    void readSecretStoresAndMasks() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", PATH, 200, kv("{\"client_secret\":\"" + SECRET + "\"}"));
            String out = fixture(v).readSecretKeyInto("app/oauth", "client_secret", "clientSecret");
            assertEquals("******** [STORED SAFELY IN clientSecret]", out);
            assertEquals(SECRET, SecretRegistry.get("clientSecret"));
            assertNoLeak(out);
            assertNoLeak(logs.allText());
        }
    }

    @Test
    void readAllWithPrefix() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", "/v1/secret/data/app/mtls", 200,
                    kv("{\"cert\":\"c\",\"key\":\"" + SECRET + "\",\"ca\":\"a\"}"));
            String out = fixture(v).readAllSecretsFromWithPrefix("app/mtls", "mtls.");
            assertEquals("******** [3 SECRETS STORED WITH PREFIX mtls.]", out);
            assertEquals("c", SecretRegistry.get("mtls.cert"));
            assertEquals(SECRET, SecretRegistry.get("mtls.key"));
            assertEquals("a", SecretRegistry.get("mtls.ca"));
            assertNoLeak(out);
            assertNoLeak(logs.allText());
        }
    }

    @Test
    void readAllEmptySecret() {
        try (FakeVault v = FakeVault.http()) {
            SecretRegistry.put("keep", "x");
            v.enqueue("GET", "/v1/secret/data/app/empty", 200, kv("{}"));
            String out = fixture(v).readAllSecretsFromWithPrefix("app/empty", "p.");
            assertEquals("******** [0 SECRETS STORED WITH PREFIX p.]", out);
            assertEquals("x", SecretRegistry.get("keep"));
            assertFalse(SecretRegistry.contains("p."));
        }
    }

    @Test
    void pathNormalized() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", PATH, 200, kv("{\"k\":\"" + SECRET + "\"}"));
            fixture(v).readSecretKeyInto(" /app/oauth/ ", "k", "var");
            assertEquals(1, v.requests().size());
            assertEquals("GET", v.requests().get(0).method());
            assertEquals(PATH, v.requests().get(0).path());
        }
    }

    @Test
    void missingKey() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", PATH, 200, kv("{\"client_id\":\"" + SECRET + "\",\"scope\":\"x\"}"));
            VaultFixtureException e = assertThrows(VaultFixtureException.class,
                    () -> fixture(v).readSecretKeyInto("app/oauth", "client_secret", "clientSecret"));
            assertEquals("Key 'client_secret' not found in secret/app/oauth (available keys: client_id, scope)",
                    e.getMessage());
            assertFalse(SecretRegistry.contains("clientSecret"));
            assertNoLeak(e);
        }
    }

    @Test
    void failedReadKeepsPreviousValue() {
        try (FakeVault v = FakeVault.http()) {
            SecretRegistry.put("clientSecret", "old");
            v.enqueue("GET", PATH, 404, "{\"errors\":[]}");
            VaultFixtureException e = assertThrows(VaultFixtureException.class,
                    () -> fixture(v).readSecretKeyInto("app/oauth", "client_secret", "clientSecret"));
            assertEquals("Secret not found: secret/app/oauth", e.getMessage());
            assertEquals("old", SecretRegistry.get("clientSecret"));
            assertNoLeak(e);
        }
    }

    @Test
    void readAllIsAllOrNothing() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", "/v1/secret/data/app/mtls", 404, "{\"errors\":[]}");
            VaultFixtureException e = assertThrows(VaultFixtureException.class,
                    () -> fixture(v).readAllSecretsFromWithPrefix("app/mtls", "mtls."));
            assertFalse(SecretRegistry.contains("mtls.cert"));
            assertNoLeak(e);
        }
    }

    @Test
    void clearSecrets() {
        SecretRegistry.put("a", "b");
        HVault h = new HVault(() -> {
            throw new IllegalStateException("must not be called");
        });
        assertTrue(h.clearSecrets());
        assertFalse(SecretRegistry.contains("a"));
    }

    @Test
    void configErrorSurfacesOnFirstCallNotConstructor() {
        Sleeper noSleep = d -> { };
        HVault h = new HVault(() -> VaultRuntime.create(
                VaultConfig.load(n -> null, new Properties(), new Properties()), noSleep, Clock.systemUTC()));
        VaultFixtureException e = assertThrows(VaultFixtureException.class,
                () -> h.readSecretKeyInto("app/oauth", "k", "v"));
        assertEquals("Vault not configured: VAULT_ADDR missing (env, -D or hvault.properties)", e.getMessage());
    }

    @Test
    void failedRuntimeIsNotCached() {
        try (FakeVault v = FakeVault.http()) {
            int[] calls = {0};
            Sleeper noSleep = d -> { };
            VaultConfig cfg = VaultConfig.builder(v.url()).token(TOKEN).retryMaxAttempts(1).build();
            HVault h = new HVault(() -> {
                if (calls[0]++ == 0) throw new VaultFixtureException("boom");
                return VaultRuntime.create(cfg, noSleep, Clock.systemUTC());
            });
            assertThrows(VaultFixtureException.class, () -> h.readSecretKeyInto("app/oauth", "k", "v"));
            v.enqueue("GET", PATH, 200, kv("{\"k\":\"" + SECRET + "\"}"));
            h.readSecretKeyInto("app/oauth", "k", "v");
            assertEquals(SECRET, SecretRegistry.get("v"));
        }
    }

    @Test
    void noLeakAnywhere() {
        try (FakeVault v = FakeVault.http()) {
            HVault h = fixture(v);
            v.enqueue("GET", PATH, 200, kv("{\"client_secret\":\"" + SECRET + "\"}"));
            assertNoLeak(h.readSecretKeyInto("app/oauth", "client_secret", "cs"));
            v.enqueue("GET", PATH, 404, "{\"errors\":[\"" + SECRET + "\"]}");
            Throwable notFound = assertThrows(VaultFixtureException.class,
                    () -> h.readSecretKeyInto("app/oauth", "client_secret", "cs"));
            assertNoLeak(notFound);
            v.enqueue("GET", PATH, 200, kv("{\"other\":\"" + SECRET + "\"}"));
            Throwable missing = assertThrows(VaultFixtureException.class,
                    () -> h.readSecretKeyInto("app/oauth", "client_secret", "cs"));
            assertNoLeak(missing);
            assertNoLeak(logs.allText());
        }
    }

    @Test
    void unsafePathRejectedBeforeAnyCall() {
        for (String bad : new String[] {"app/a#b", "app/a?x", "app/a b", "app/a\tb", "app/a\u0001b"}) {
            try (FakeVault v = FakeVault.http()) {
                SecretRegistry.put("keep", "x");
                VaultFixtureException e = assertThrows(VaultFixtureException.class,
                        () -> fixture(v).readSecretKeyInto(bad, "k", "var"));
                assertEquals("Invalid secret path '" + bad + "': '#', '?', whitespace and control characters are not allowed",
                        e.getMessage());
                VaultFixtureException e2 = assertThrows(VaultFixtureException.class,
                        () -> fixture(v).readAllSecretsFromWithPrefix(bad, "p."));
                assertEquals(e.getMessage(), e2.getMessage());
                assertTrue(v.requests().isEmpty());
                assertFalse(SecretRegistry.contains("var"));
                assertEquals("x", SecretRegistry.get("keep"));
            }
        }
    }

    @Test
    void logsStoredSecrets() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", PATH, 200, kv("{\"client_secret\":\"" + SECRET + "\"}"));
            v.enqueue("GET", "/v1/secret/data/app/mtls", 200, kv("{\"cert\":\"c\",\"key\":\"k\",\"ca\":\"a\"}"));
            HVault f = fixture(v);
            f.readSecretKeyInto("app/oauth", "client_secret", "clientSecret");
            f.readAllSecretsFromWithPrefix("app/mtls", "mtls.");
            List<String> infos = logs.records().stream()
                    .filter(r -> r.getLevel() == Level.INFO && r.getLoggerName().equals(HVault.class.getName()))
                    .map(LogRecord::getMessage).toList();
            assertEquals(List.of(
                    "Stored key 'client_secret' of secret/app/oauth into 'clientSecret'",
                    "Stored 3 keys of secret/app/mtls with prefix 'mtls.'"), infos);
            assertNoLeak(logs.allText());
        }
    }

    @Test
    void dotSegmentsAndEmptyPathRejectedBeforeAnyCall() {
        String dots = "'.', '..' and empty segments are not allowed";
        String[][] cases = {{"app/../sys", dots}, {"../x", dots}, {"app/./x", dots}, {"app//x", dots},
            {"/", "empty path"}, {"  ", "empty path"}, {"", "empty path"}};
        for (String[] c : cases) {
            try (FakeVault v = FakeVault.http()) {
                VaultFixtureException e = assertThrows(VaultFixtureException.class,
                        () -> fixture(v).readSecretKeyInto(c[0], "k", "var"));
                assertEquals("Invalid secret path '" + c[0] + "': " + c[1], e.getMessage());
                assertThrows(VaultFixtureException.class, () -> fixture(v).readAllSecretsFromWithPrefix(c[0], "p."));
                assertTrue(v.requests().isEmpty(), c[0]);
            }
        }
    }
}
