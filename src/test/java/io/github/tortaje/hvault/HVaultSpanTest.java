package io.github.tortaje.hvault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.tortaje.hvault.client.Sleeper;
import io.github.tortaje.hvault.config.VaultConfig;
import io.github.tortaje.hvault.registry.SecretRegistry;
import io.github.tortaje.hvault.testsupport.FakeVault;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.EventData;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HVaultSpanTest {

    private static final String SECRET = "s3cr3t-VALUE-42";
    private static final String TOKEN = "hvs.TEST-TOKEN";
    private static final String JWT = "eyJhbGciOi.jwt-PAYLOAD.sig";
    private static final String READ_NAME = "GET /v1/{mount}/data/{path}";
    private static final String LOGIN_NAME = "POST /v1/auth/{mount}/login";

    private static InMemorySpanExporter spans;

    @TempDir
    Path tmp;

    @BeforeAll
    static void registerSdk() {
        spans = InMemorySpanExporter.create();
        GlobalOpenTelemetry.set(OpenTelemetrySdk.builder()
                .setTracerProvider(SdkTracerProvider.builder()
                        .addSpanProcessor(SimpleSpanProcessor.create(spans)).build())
                .setPropagators(ContextPropagators.create(W3CTraceContextPropagator.getInstance()))
                .build());
    }

    @BeforeEach
    void reset() {
        spans.reset();
        SecretRegistry.clear();
    }

    private static HVault fixture(VaultConfig cfg) {
        Sleeper noSleep = d -> { };
        return new HVault(() -> VaultRuntime.create(cfg, noSleep, Clock.systemUTC()));
    }

    private static HVault staticToken(FakeVault v, int attempts) {
        return fixture(VaultConfig.builder(v.url()).token(TOKEN).retryMaxAttempts(attempts).build());
    }

    private static String kv(String dataJson) {
        return "{\"data\":{\"data\":" + dataJson + ",\"metadata\":{}}}";
    }

    private static <T> T attr(SpanData s, String key, Class<T> type) {
        Object v = type == Long.class
                ? s.getAttributes().get(AttributeKey.longKey(key))
                : s.getAttributes().get(AttributeKey.stringKey(key));
        return type.cast(v);
    }

    @Test
    void readSpan() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", "/v1/secret/data/app/oauth", 200, kv("{\"client_secret\":\"" + SECRET + "\"}"));
            staticToken(v, 1).readSecretKeyInto("app/oauth", "client_secret", "clientSecret");

            List<SpanData> items = spans.getFinishedSpanItems();
            assertEquals(1, items.size());
            SpanData s = items.get(0);
            assertEquals(READ_NAME, s.getName());
            assertEquals(SpanKind.CLIENT, s.getKind());
            assertEquals("GET", attr(s, "http.request.method", String.class));
            assertEquals(v.url() + "/v1/secret/data/app/oauth", attr(s, "url.full", String.class));
            assertNotNull(attr(s, "server.address", String.class));
            assertEquals((long) java.net.URI.create(v.url()).getPort(), attr(s, "server.port", Long.class));
            assertEquals(200L, attr(s, "http.response.status_code", Long.class));
            assertEquals("secret", attr(s, "vault.kv.mount", String.class));
            assertEquals("app/oauth", attr(s, "vault.secret.path", String.class));
            assertEquals("clientSecret", attr(s, "hvault.target.variable", String.class));
            assertNull(attr(s, "http.request.resend_count", Long.class));
            assertEquals(StatusCode.UNSET, s.getStatus().getStatusCode());
        }
    }

    @Test
    void readAllSpanHasCount() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", "/v1/secret/data/app/mtls", 200,
                    kv("{\"cert\":\"c\",\"key\":\"" + SECRET + "\",\"ca\":\"a\"}"));
            staticToken(v, 1).readAllSecretsFromWithPrefix("app/mtls", "mtls.");

            List<SpanData> items = spans.getFinishedSpanItems();
            assertEquals(1, items.size());
            SpanData s = items.get(0);
            assertEquals("mtls.", attr(s, "hvault.target.prefix", String.class));
            assertEquals(3L, attr(s, "hvault.secret.count", Long.class));
            assertNull(attr(s, "hvault.target.variable", String.class));
        }
    }

    @Test
    void retryProducesOneSpanPerAttempt() {
        try (FakeVault v = FakeVault.http()) {
            String path = "/v1/secret/data/app/oauth";
            v.enqueue("GET", path, 503, "{}");
            v.enqueue("GET", path, 503, "{}");
            v.enqueue("GET", path, 200, kv("{\"client_secret\":\"" + SECRET + "\"}"));
            staticToken(v, 3).readSecretKeyInto("app/oauth", "client_secret", "clientSecret");

            List<SpanData> items = spans.getFinishedSpanItems();
            assertEquals(3, items.size());
            assertNull(attr(items.get(0), "http.request.resend_count", Long.class));
            assertEquals(1L, attr(items.get(1), "http.request.resend_count", Long.class));
            assertEquals(2L, attr(items.get(2), "http.request.resend_count", Long.class));
            for (int i = 0; i < 2; i++) {
                assertEquals(StatusCode.ERROR, items.get(i).getStatus().getStatusCode());
                assertEquals("503", attr(items.get(i), "error.type", String.class));
                assertEquals(503L, attr(items.get(i), "http.response.status_code", Long.class));
            }
            assertEquals(StatusCode.UNSET, items.get(2).getStatus().getStatusCode());
            assertEquals(200L, attr(items.get(2), "http.response.status_code", Long.class));
        }
    }

    @Test
    void notFoundSpanIsError() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", "/v1/secret/data/app/oauth", 404, "{\"errors\":[]}");
            assertThrows(VaultFixtureException.class,
                    () -> staticToken(v, 1).readSecretKeyInto("app/oauth", "client_secret", "clientSecret"));

            List<SpanData> items = spans.getFinishedSpanItems();
            assertEquals(1, items.size());
            SpanData s = items.get(0);
            assertEquals(StatusCode.ERROR, s.getStatus().getStatusCode());
            assertEquals(404L, attr(s, "http.response.status_code", Long.class));
            // Traced overwrites the "404" status string with the exception class name
            assertEquals("io.github.tortaje.hvault.VaultFixtureException", attr(s, "error.type", String.class));
            assertTrue(s.getEvents().stream().anyMatch(e -> e.getName().equals("exception")));
        }
    }

    @Test
    void loginSpan() throws Exception {
        Path jwt = tmp.resolve("jwt");
        Files.writeString(jwt, JWT);
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", "/v1/auth/kubernetes/login", 200,
                    "{\"auth\":{\"client_token\":\"" + TOKEN + "\",\"lease_duration\":3600}}");
            v.enqueue("GET", "/v1/secret/data/app/oauth", 200, kv("{\"client_secret\":\"" + SECRET + "\"}"));
            fixture(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt).retryMaxAttempts(1).build())
                    .readSecretKeyInto("app/oauth", "client_secret", "clientSecret");

            List<SpanData> items = spans.getFinishedSpanItems();
            assertEquals(2, items.size());
            SpanData login = items.get(0);
            assertEquals(LOGIN_NAME, login.getName());
            assertEquals(SpanKind.CLIENT, login.getKind());
            assertEquals("POST", attr(login, "http.request.method", String.class));
            assertEquals("kubernetes", attr(login, "vault.auth.method", String.class));
            assertEquals("r", attr(login, "vault.auth.role", String.class));
            assertEquals(READ_NAME, items.get(1).getName());
        }
    }

    @Test
    void noSecretInSpans() throws Exception {
        Path jwt = tmp.resolve("jwt");
        Files.writeString(jwt, JWT);
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("POST", "/v1/auth/kubernetes/login", 200,
                    "{\"auth\":{\"client_token\":\"" + TOKEN + "\",\"lease_duration\":3600}}");
            v.enqueue("GET", "/v1/secret/data/app/oauth", 200, kv("{\"client_secret\":\"" + SECRET + "\"}"));
            v.enqueue("GET", "/v1/secret/data/app/missing", 404, "{\"errors\":[\"" + SECRET + "\"]}");
            HVault h = fixture(VaultConfig.builder(v.url()).role("r").k8sTokenPath(jwt).retryMaxAttempts(1).build());
            h.readSecretKeyInto("app/oauth", "client_secret", "clientSecret");
            assertThrows(VaultFixtureException.class, () -> h.readSecretKeyInto("app/missing", "k", "x"));

            List<SpanData> items = spans.getFinishedSpanItems();
            assertFalse(items.isEmpty());
            for (SpanData s : items) {
                assertClean(s.getName());
                s.getAttributes().forEach((k, val) -> assertClean(String.valueOf(val)));
                for (EventData e : s.getEvents()) {
                    assertClean(e.getName());
                    e.getAttributes().forEach((k, val) -> assertClean(String.valueOf(val)));
                }
                assertClean(String.valueOf(s.getStatus().getDescription()));
            }
        }
    }

    private static void assertClean(String text) {
        for (String bad : new String[] {SECRET, TOKEN, JWT}) {
            assertFalse(text.contains(bad), "leak in span data: " + text);
        }
    }

    @Test
    void urlFullHidesUserInfo() {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", "/v1/secret/data/app/oauth", 200, kv("{\"client_secret\":\"x\"}"));
            String withUser = v.url().replace("http://", "http://user:pass@");
            fixture(VaultConfig.builder(withUser).token(TOKEN).retryMaxAttempts(1).build())
                    .readSecretKeyInto("app/oauth", "client_secret", "clientSecret");
            String url = attr(spans.getFinishedSpanItems().get(0), "url.full", String.class);
            assertEquals(v.url().replace("http://", "http://REDACTED:REDACTED@") + "/v1/secret/data/app/oauth", url);
        }
    }
}
