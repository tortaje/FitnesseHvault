package io.github.tortaje.hvault.config;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.tortaje.hvault.VaultFixtureException;
import io.github.tortaje.hvault.testsupport.LogCapture;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class VaultConfigTest {

    private static EnvSource env(String... kv) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m::get;
    }

    private static Properties props(String... kv) {
        Properties p = new Properties();
        for (int i = 0; i < kv.length; i += 2) p.setProperty(kv[i], kv[i + 1]);
        return p;
    }

    @Test
    void envWinsOverSystemWinsOverFile() {
        Properties sys = props("hvault.addr", "http://v", "hvault.kv.mount", "sys");
        Properties file = props("hvault.kv.mount", "file");
        assertEquals("env", VaultConfig.load(env("VAULT_ADDR", "http://v", "VAULT_KV_MOUNT", "env"), sys, file).kvMount());
        assertEquals("sys", VaultConfig.load(env(), sys, file).kvMount());
        assertEquals("file", VaultConfig.load(env("VAULT_ADDR", "http://v"), props(), file).kvMount());
    }

    @Test
    void defaults() {
        VaultConfig c = VaultConfig.load(env("VAULT_ADDR", "http://v"), props(), props());
        assertEquals("secret", c.kvMount());
        assertEquals("kubernetes", c.k8sAuthPath());
        assertEquals(Path.of("/var/run/secrets/kubernetes.io/serviceaccount/token"), c.k8sTokenPath());
        assertEquals(3, c.retryMaxAttempts());
        assertEquals(Duration.ofMillis(1000), c.retryInitialDelay());
        assertEquals(Duration.ofMillis(5000), c.connectTimeout());
        assertEquals(Duration.ofMillis(10000), c.requestTimeout());
        assertTrue(c.token().isEmpty());
        assertTrue(c.role().isEmpty());
        assertTrue(c.namespace().isEmpty());
        assertTrue(c.caCert().isEmpty());
    }

    @Test
    void missingAddr() {
        VaultFixtureException e = assertThrows(VaultFixtureException.class,
                () -> VaultConfig.load(env(), props(), props()));
        assertEquals("Vault not configured: VAULT_ADDR missing (env, -D or hvault.properties)", e.getMessage());
    }

    @Test
    void trailingSlashStripped() {
        assertEquals("https://vault:8200",
                VaultConfig.load(env("VAULT_ADDR", "https://vault:8200/"), props(), props()).addr());
        assertEquals("https://vault:8200", VaultConfig.builder("https://vault:8200/").build().addr());
    }

    @Test
    void tokenFromSystemProperty() {
        VaultConfig c = VaultConfig.load(env("VAULT_ADDR", "http://v"), props("hvault.token", "-D"), props());
        assertEquals("-D", c.token().orElseThrow());
    }

    @Test
    void tokenInFileIgnoredWithWarning() {
        try (LogCapture log = LogCapture.on("io.github.tortaje.hvault.config.VaultConfig")) {
            VaultConfig c = VaultConfig.load(env("VAULT_ADDR", "http://v"), props(), props("hvault.token", "hvs.FILE-TOKEN"));
            assertTrue(c.token().isEmpty());
            assertEquals(1, log.records().size());
            assertEquals(Level.WARNING, log.records().get(0).getLevel());
            assertTrue(log.allText().contains("hvault.token in hvault.properties is ignored: use VAULT_TOKEN"));
            assertFalse(log.allText().contains("hvs.FILE-TOKEN"));
        }
    }

    @Test
    void blankValuesAreAbsent() {
        VaultConfig c = VaultConfig.load(
                env("VAULT_ADDR", "http://v", "VAULT_TOKEN", "", "VAULT_ROLE", "  ", "VAULT_KV_MOUNT", ""),
                props(), props());
        assertTrue(c.token().isEmpty());
        assertTrue(c.role().isEmpty());
        assertEquals("secret", c.kvMount());
    }

    @Test
    void allKeysMapped() {
        String[][] table = {
            {"VAULT_ADDR", "hvault.addr"}, {"VAULT_TOKEN", "hvault.token"}, {"VAULT_ROLE", "hvault.role"},
            {"VAULT_NAMESPACE", "hvault.namespace"}, {"VAULT_CACERT", "hvault.cacert"},
            {"VAULT_KV_MOUNT", "hvault.kv.mount"}, {"VAULT_K8S_AUTH_PATH", "hvault.k8s.auth.path"},
            {"VAULT_K8S_TOKEN_PATH", "hvault.k8s.token.path"}, {"VAULT_RETRY_MAX_ATTEMPTS", "hvault.retry.max.attempts"},
            {"VAULT_RETRY_INITIAL_DELAY_MS", "hvault.retry.initial.delay.ms"},
            {"VAULT_CONNECT_TIMEOUT_MS", "hvault.connect.timeout.ms"},
            {"VAULT_REQUEST_TIMEOUT_MS", "hvault.request.timeout.ms"}};
        String[] values = {"http://a", "tok", "rl", "ns", "/ca.pem", "kv", "k8s", "/jwt", "7", "11", "13", "17"};
        Map<String, String> e = new HashMap<>();
        Properties p = new Properties();
        for (int i = 0; i < table.length; i++) {
            e.put(table[i][0], values[i]);
            p.setProperty(table[i][1], values[i]);
        }
        for (VaultConfig c : new VaultConfig[] {
                VaultConfig.load(e::get, props(), props()),
                VaultConfig.load(env(), p, props("hvault.token", "ignored"))}) {
            assertEquals("http://a", c.addr());
            assertEquals("tok", c.token().orElseThrow());
            assertEquals("rl", c.role().orElseThrow());
            assertEquals("ns", c.namespace().orElseThrow());
            assertEquals(Path.of("/ca.pem"), c.caCert().orElseThrow());
            assertEquals("kv", c.kvMount());
            assertEquals("k8s", c.k8sAuthPath());
            assertEquals(Path.of("/jwt"), c.k8sTokenPath());
            assertEquals(7, c.retryMaxAttempts());
            assertEquals(Duration.ofMillis(11), c.retryInitialDelay());
            assertEquals(Duration.ofMillis(13), c.connectTimeout());
            assertEquals(Duration.ofMillis(17), c.requestTimeout());
        }
        // file layer for every non-token key
        Properties f = new Properties();
        for (int i = 0; i < table.length; i++) if (i != 1) f.setProperty(table[i][1], values[i]);
        VaultConfig c = VaultConfig.load(env(), props(), f);
        assertEquals("http://a", c.addr());
        assertEquals("kv", c.kvMount());
        assertEquals(Duration.ofMillis(17), c.requestTimeout());
        assertEquals("ns", c.namespace().orElseThrow());
    }

    @Test
    void invalidNumber() {
        VaultFixtureException e = assertThrows(VaultFixtureException.class, () -> VaultConfig.load(
                env("VAULT_ADDR", "http://v", "VAULT_RETRY_MAX_ATTEMPTS", "abc"), props(), props()));
        assertEquals("Invalid value for VAULT_RETRY_MAX_ATTEMPTS: abc", e.getMessage());
    }

    @Test
    void builderAppliesDefaultsAndSetters() {
        VaultConfig c = VaultConfig.builder("http://v").kvMount("kv-app").token("t")
                .caCert(Path.of("/x.pem")).retryInitialDelay(Duration.ofMillis(1)).build();
        assertEquals("kv-app", c.kvMount());
        assertEquals("t", c.token().orElseThrow());
        assertEquals(Path.of("/x.pem"), c.caCert().orElseThrow());
        assertEquals(Duration.ofMillis(1), c.retryInitialDelay());
        assertEquals(3, c.retryMaxAttempts());
        assertEquals("kubernetes", c.k8sAuthPath());
    }

    @Test
    void invalidAddrRejected() {
        for (String bad : new String[] {"not a uri", "vault:8200", "ftp://v", "http://", "/relative"}) {
            VaultFixtureException e = assertThrows(VaultFixtureException.class,
                    () -> VaultConfig.load(env("VAULT_ADDR", bad), props(), props()));
            assertEquals("Invalid value for VAULT_ADDR: " + bad, e.getMessage());
            e = assertThrows(VaultFixtureException.class, () -> VaultConfig.builder(bad).build());
            assertEquals("Invalid value for VAULT_ADDR: " + bad, e.getMessage());
        }
        assertEquals("https://v:8200", VaultConfig.load(env("VAULT_ADDR", "https://v:8200"), props(), props()).addr());
    }

    @Test
    void invalidMountRejected() {
        VaultFixtureException e = assertThrows(VaultFixtureException.class, () -> VaultConfig.load(
                env("VAULT_ADDR", "http://v", "VAULT_KV_MOUNT", "a#b"), props(), props()));
        assertEquals("Invalid value for VAULT_KV_MOUNT: a#b", e.getMessage());
        assertThrows(VaultFixtureException.class, () -> VaultConfig.builder("http://v").kvMount("a?b").build());
        assertThrows(VaultFixtureException.class, () -> VaultConfig.builder("http://v").kvMount("a b").build());
    }

    @Test
    void numericBounds() {
        String[][] cases = {
            {"VAULT_RETRY_MAX_ATTEMPTS", "0"}, {"VAULT_RETRY_INITIAL_DELAY_MS", "-1"},
            {"VAULT_CONNECT_TIMEOUT_MS", "0"}, {"VAULT_REQUEST_TIMEOUT_MS", "0"}};
        for (String[] c : cases) {
            VaultFixtureException e = assertThrows(VaultFixtureException.class,
                    () -> VaultConfig.load(env("VAULT_ADDR", "http://v", c[0], c[1]), props(), props()));
            assertEquals("Invalid value for " + c[0] + ": " + c[1], e.getMessage());
        }
        assertEquals(0, VaultConfig.load(env("VAULT_ADDR", "http://v", "VAULT_RETRY_INITIAL_DELAY_MS", "0"),
                props(), props()).retryInitialDelay().toMillis());
    }

    @Test
    void unreadablePropertiesFileWrapped() {
        java.io.InputStream bad = new java.io.ByteArrayInputStream("a=\\u12G4".getBytes());
        VaultFixtureException e = assertThrows(VaultFixtureException.class, () -> VaultConfig.readProps(bad));
        assertEquals("Cannot read hvault.properties", e.getMessage());
        java.io.InputStream io = new java.io.InputStream() {
            public int read() throws java.io.IOException { throw new java.io.IOException("boom"); }
        };
        e = assertThrows(VaultFixtureException.class, () -> VaultConfig.readProps(io));
        assertEquals("Cannot read hvault.properties", e.getMessage());
    }

    @Test
    void invalidAuthPathRejected() {
        for (String bad : new String[] {"k8s roks", "a?b", "../x", "a//b"}) {
            VaultFixtureException e = assertThrows(VaultFixtureException.class, () -> VaultConfig.load(
                    env("VAULT_ADDR", "http://v", "VAULT_K8S_AUTH_PATH", bad), props(), props()));
            assertEquals("Invalid value for VAULT_K8S_AUTH_PATH: " + bad, e.getMessage());
        }
    }

    @Test
    void mountWithDotSegmentsRejected() {
        VaultFixtureException e = assertThrows(VaultFixtureException.class,
                () -> VaultConfig.builder("http://v").kvMount("../sys").build());
        assertEquals("Invalid value for VAULT_KV_MOUNT: ../sys", e.getMessage());
    }

    @Test
    void namespaceWithControlCharactersRejected() {
        VaultFixtureException e = assertThrows(VaultFixtureException.class,
                () -> VaultConfig.builder("http://v").namespace("team-a\r\nX-Evil: 1").build());
        assertTrue(e.getMessage().startsWith("Invalid value for VAULT_NAMESPACE"), e.getMessage());
        assertEquals("team-a/sub", VaultConfig.builder("http://v").namespace("team-a/sub").build()
                .namespace().orElseThrow());
    }

    @Test
    void invalidAddrMessageHidesUserInfo() {
        VaultFixtureException e = assertThrows(VaultFixtureException.class,
                () -> VaultConfig.builder("ftp://user:pass@v").build());
        assertEquals("Invalid value for VAULT_ADDR: ftp://REDACTED:REDACTED@v", e.getMessage());
    }

    /** Runs fromEnvironment() with a context class loader whose classpath root is {@code dir}. */
    private static VaultConfig fromEnvironmentWith(Path dir) throws Exception {
        Thread t = Thread.currentThread();
        ClassLoader previous = t.getContextClassLoader();
        try (URLClassLoader cl = new URLClassLoader(new URL[] {dir.toUri().toURL()}, null)) {
            t.setContextClassLoader(cl);
            return VaultConfig.fromEnvironment();
        } finally {
            t.setContextClassLoader(previous);
        }
    }

    @Test
    void fromEnvironmentReadsHvaultPropertiesOnTheClasspath(@TempDir Path dir) throws Exception {
        assumeTrue(System.getenv("VAULT_ADDR") == null && System.getenv("VAULT_KV_MOUNT") == null
                && System.getProperty("hvault.addr") == null, "real Vault settings present in this environment");
        Files.writeString(dir.resolve("hvault.properties"),
                "hvault.addr=https://vault.example.com:8200\nhvault.kv.mount=from-file\n");
        VaultConfig c = fromEnvironmentWith(dir);
        assertEquals("https://vault.example.com:8200", c.addr());
        assertEquals("from-file", c.kvMount());
    }

    @Test
    void fromEnvironmentWithoutFileNeedsVaultAddr(@TempDir Path dir) {
        assumeTrue(System.getenv("VAULT_ADDR") == null && System.getProperty("hvault.addr") == null,
                "real Vault settings present in this environment");
        VaultFixtureException e = assertThrows(VaultFixtureException.class, () -> fromEnvironmentWith(dir));
        assertEquals("Vault not configured: VAULT_ADDR missing (env, -D or hvault.properties)", e.getMessage());
    }

    @Test
    void readPropsOfMissingResourceIsEmpty() {
        assertTrue(VaultConfig.readProps(null).isEmpty());
    }
}
