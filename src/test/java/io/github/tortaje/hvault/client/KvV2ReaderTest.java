package io.github.tortaje.hvault.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.tortaje.hvault.VaultFixtureException;
import io.github.tortaje.hvault.auth.TokenProvider;
import io.github.tortaje.hvault.config.VaultConfig;
import io.github.tortaje.hvault.testsupport.FakeVault;
import io.github.tortaje.hvault.testsupport.Pems;
import io.opentelemetry.api.common.Attributes;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;
import io.github.tortaje.hvault.testsupport.LogCapture;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KvV2ReaderTest {

    private static final String PATH = "/v1/secret/data/app/oauth";
    private static final String LOGIN = "/v1/auth/kubernetes/login";

    @TempDir
    Path tmp;

    private KvV2Reader reader(VaultConfig cfg) {
        RetryPolicy retry = new RetryPolicy(3, Duration.ofMillis(1), d -> { }, () -> 0);
        VaultHttpClient http = new VaultHttpClient(cfg, retry);
        return new KvV2Reader(cfg, http, new TokenProvider(cfg, http, Clock.systemUTC()));
    }

    private KvV2Reader staticReader(FakeVault v) {
        return reader(VaultConfig.builder(v.url()).token("t").build());
    }

    private KvV2Reader k8sReader(FakeVault v) throws IOException {
        Path jwt = tmp.resolve("jwt");
        Files.writeString(jwt, "j");
        return reader(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt).build());
    }

    private static String kv(String dataJson) {
        return "{\"data\":{\"data\":" + dataJson + ",\"metadata\":{\"version\":1}}}";
    }

    private Map<String, String> read(KvV2Reader r) {
        return r.read("app/oauth", Attributes.empty(), false);
    }

    @Test
    void readsAllKeys() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", PATH, 200, kv("{\"zeta\":\"1\",\"alpha\":\"2\",\"mid\":\"3\",\"b\":\"4\"}"));
            Map<String, String> m = read(staticReader(v));
            assertEquals(List.of("zeta", "alpha", "mid", "b"), List.copyOf(m.keySet()));
            assertEquals("2", m.get("alpha"));
            assertEquals("t", v.requests().get(0).headers().get("x-vault-token"));
        }
    }

    @Test
    void nonTextValuesAsJson() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", PATH, 200, kv("{\"n\":42,\"t\":true,\"o\":{\"x\":1},\"z\":null,\"l\":[1,2]}"));
            Map<String, String> m = read(staticReader(v));
            assertEquals("42", m.get("n"));
            assertEquals("true", m.get("t"));
            assertEquals("{\"x\":1}", m.get("o"));
            assertEquals("null", m.get("z"));
            assertEquals("[1,2]", m.get("l"));
        }
    }

    @Test
    void multilineAndUnicodePreserved() {
        try (FakeVault v = FakeVault.http()) {
            String value = Pems.read("client-rsa.pem") + "é€";
            v.enqueue("GET", PATH, 200, kv(new JSONObject().put("pem", value).toString()));
            assertEquals(value, read(staticReader(v)).get("pem"));
        }
    }

    @Test
    void customMount() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", "/v1/kv-app/data/app/oauth", 200, kv("{\"a\":\"1\"}"));
            Map<String, String> m = reader(VaultConfig.builder(v.url()).token("t").kvMount("kv-app").build())
                    .read("app/oauth", Attributes.empty(), false);
            assertEquals("1", m.get("a"));
        }
    }

    @Test
    void recordCountWorksWithoutSdk() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", PATH, 200, kv("{\"a\":\"1\",\"b\":\"2\"}"));
            assertEquals(2, staticReader(v).read("app/oauth", Attributes.empty(), true).size());
        }
    }

    @Test
    void notFound() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", PATH, 404, "{\"errors\":[]}");
            assertEquals("Secret not found: secret/app/oauth",
                    assertThrows(VaultFixtureException.class, () -> read(staticReader(v))).getMessage());
        }
    }

    @Test
    void forbiddenStaticToken() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", PATH, 403, "{\"errors\":[\"permission denied\"]}");
            assertEquals("Access denied to secret/app/oauth (HTTP 403): check policy for the provided token",
                    assertThrows(VaultFixtureException.class, () -> read(staticReader(v))).getMessage());
            assertEquals(1, v.requests().size());
        }
    }

    @Test
    void forbiddenThenReloginSucceeds() throws IOException {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", LOGIN, 200, "{\"auth\":{\"client_token\":\"t1\",\"lease_duration\":3600}}");
            v.enqueue("POST", LOGIN, 200, "{\"auth\":{\"client_token\":\"t2\",\"lease_duration\":3600}}");
            v.enqueue("GET", PATH, 403, "{\"errors\":[\"permission denied\"]}");
            v.enqueue("GET", PATH, 200, kv("{\"a\":\"1\"}"));
            assertEquals("1", read(k8sReader(v)).get("a"));
            long logins = v.requests().stream().filter(r -> r.method().equals("POST")).count();
            assertEquals(2, logins);
            assertEquals("t2", v.requests().get(v.requests().size() - 1).headers().get("x-vault-token"));
        }
    }

    @Test
    void forbiddenTwice() throws IOException {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", LOGIN, 200, "{\"auth\":{\"client_token\":\"t1\",\"lease_duration\":3600}}");
            v.enqueue("POST", LOGIN, 200, "{\"auth\":{\"client_token\":\"t2\",\"lease_duration\":3600}}");
            v.enqueue("GET", PATH, 403, "{}");
            v.enqueue("GET", PATH, 403, "{}");
            KvV2Reader r = k8sReader(v);
            assertEquals("Access denied to secret/app/oauth (HTTP 403): check policy for role 'r'",
                    assertThrows(VaultFixtureException.class, () -> read(r)).getMessage());
        }
    }

    @Test
    void otherStatus() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", PATH, 400, "{\"errors\":[\"bad path\"]}");
            assertEquals("Vault error on secret/app/oauth (HTTP 400): bad path",
                    assertThrows(VaultFixtureException.class, () -> read(staticReader(v))).getMessage());
        }
    }

    @Test
    void otherStatusWithoutErrors() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", PATH, 400, "{}");
            assertEquals("Vault error on secret/app/oauth (HTTP 400)",
                    assertThrows(VaultFixtureException.class, () -> read(staticReader(v))).getMessage());
        }
    }

    @Test
    void bodyNeverInMessage() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", PATH, 400, "{\"errors\":[\"bad\"],\"data\":{\"x\":\"s3cr3t-VALUE-42\"}}");
            String msg = assertThrows(VaultFixtureException.class, () -> read(staticReader(v))).getMessage();
            assertFalse(msg.contains("s3cr3t-VALUE-42"));
        }
    }

    @Test
    void logsReloginOnForbidden() throws IOException {
        try (FakeVault v = FakeVault.http(); LogCapture logs = LogCapture.on(KvV2Reader.class.getName())) {
            v.enqueue("POST", LOGIN, 200, "{\"auth\":{\"client_token\":\"t1\",\"lease_duration\":3600}}");
            v.enqueue("POST", LOGIN, 200, "{\"auth\":{\"client_token\":\"t2\",\"lease_duration\":3600}}");
            v.enqueue("GET", PATH, 403, "{}");
            v.enqueue("GET", PATH, 200, kv("{\"a\":\"1\"}"));
            read(k8sReader(v));
            assertEquals(List.of("Access denied to secret/app/oauth (HTTP 403) for role 'r', logging in again"),
                    messages(logs, Level.INFO));
        }
    }

    private static List<String> messages(LogCapture logs, Level level) {
        return logs.records().stream().filter(r -> r.getLevel() == level).map(LogRecord::getMessage).toList();
    }
}
