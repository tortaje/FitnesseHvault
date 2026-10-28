package io.github.tortaje.hvault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.tortaje.hvault.client.Sleeper;
import io.github.tortaje.hvault.config.VaultConfig;
import io.github.tortaje.hvault.registry.MtlsContexts;
import io.github.tortaje.hvault.registry.SecretRegistry;
import io.github.tortaje.hvault.testsupport.Pems;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.vault.VaultContainer;

@Testcontainers
@TestMethodOrder(OrderAnnotation.class)
class HVaultVaultIT {

    private static final String ROOT = "root-token";
    private static final String SECRET = "s3cr3t-VALUE-42";

    @Container
    static final VaultContainer<?> VAULT = new VaultContainer<>("hashicorp/vault:1.18.3").withVaultToken(ROOT);

    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static String limitedToken;

    @BeforeAll
    static void provision() throws Exception {
        api("POST", "/v1/sys/mounts/kv-app", ROOT,
                new JSONObject().put("type", "kv").put("options", new JSONObject().put("version", "2")));
        write("secret", "app/oauth", new JSONObject().put("client_id", "my-client").put("client_secret", SECRET));
        write("secret", "app/mtls", new JSONObject()
                .put("cert", Pems.read("client-rsa.pem"))
                .put("key", Pems.read("client-rsa-pkcs1.key"))
                .put("ca", Pems.read("ca.pem")));
        write("kv-app", "app/x", new JSONObject().put("k", "v"));
        api("PUT", "/v1/sys/policies/acl/only-oauth", ROOT, new JSONObject()
                .put("policy", "path \"secret/data/app/oauth\" { capabilities = [\"read\"] }"));
        JSONObject token = new JSONObject(api("POST", "/v1/auth/token/create", ROOT,
                new JSONObject().put("policies", new org.json.JSONArray().put("only-oauth"))));
        limitedToken = token.getJSONObject("auth").getString("client_token");
    }

    @AfterEach
    void clear() {
        SecretRegistry.clear();
    }

    private static void write(String mount, String path, JSONObject data) throws Exception {
        api("POST", "/v1/" + mount + "/data/" + path, ROOT, new JSONObject().put("data", data));
    }

    private static String api(String method, String path, String token, JSONObject body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(VAULT.getHttpHostAddress() + path))
                .header("X-Vault-Token", token)
                .header("Content-Type", "application/json")
                .method(method, HttpRequest.BodyPublishers.ofString(body == null ? "" : body.toString()))
                .build();
        HttpResponse<String> res = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() / 100 != 2) {
            throw new IllegalStateException(method + " " + path + " -> HTTP " + res.statusCode());
        }
        return res.body();
    }

    private static HVault fixture(String token, String mount, Sleeper sleeper) {
        VaultConfig.Builder b = VaultConfig.builder(VAULT.getHttpHostAddress())
                .token(token)
                .retryMaxAttempts(3)
                .retryInitialDelay(Duration.ofMillis(100));
        if (mount != null) {
            b.kvMount(mount);
        }
        VaultConfig cfg = b.build();
        return new HVault(() -> VaultRuntime.create(cfg, sleeper, Clock.systemUTC()));
    }

    private static HVault fixture(String token, String mount) {
        return fixture(token, mount, Sleeper.real());
    }

    private static String message(Runnable r) {
        return assertThrows(VaultFixtureException.class, r::run).getMessage();
    }

    @Test
    @Order(1)
    void readSecret() {
        String out = fixture(ROOT, null).readSecretKeyInto("app/oauth", "client_secret", "secret");
        assertEquals("******** [STORED SAFELY IN secret]", out);
        assertEquals(SECRET, SecretRegistry.get("secret"));
    }

    @Test
    @Order(2)
    void readAllThenMtls() {
        HVault f = fixture(ROOT, null);
        f.readAllSecretsFromWithPrefix("app/mtls", "mtls.");
        assertNotNull(MtlsContexts.fromRegistry("mtls.cert", "mtls.key", "mtls.ca"));
    }

    @Test
    @Order(3)
    void customMount() {
        fixture(ROOT, "kv-app").readSecretKeyInto("app/x", "k", "x");
        assertEquals("v", SecretRegistry.get("x"));
    }

    @Test
    @Order(4)
    void notFound() {
        HVault f = fixture(ROOT, null);
        assertEquals("Secret not found: secret/app/none",
                message(() -> f.readSecretKeyInto("app/none", "k", "v")));
    }

    @Test
    @Order(5)
    void missingKey() {
        HVault f = fixture(ROOT, null);
        assertEquals("Key 'nope' not found in secret/app/oauth (available keys: client_id, client_secret)",
                message(() -> f.readSecretKeyInto("app/oauth", "nope", "v")));
    }

    @Test
    @Order(6)
    void forbiddenWithLimitedToken() {
        HVault f = fixture(limitedToken, null);
        assertEquals("Access denied to secret/app/mtls (HTTP 403): check policy for the provided token",
                message(() -> f.readSecretKeyInto("app/mtls", "cert", "v")));
    }

    @Test
    @Order(7)
    void sealedVaultExhaustsRetries() throws Exception {
        api("PUT", "/v1/sys/seal", ROOT, null);
        AtomicInteger pauses = new AtomicInteger();
        Sleeper counting = d -> {
            pauses.incrementAndGet();
            Sleeper.real().sleep(d);
        };
        HVault f = fixture(ROOT, null, counting);
        String msg = message(() -> f.readSecretKeyInto("app/oauth", "client_id", "v"));
        assertTrue(msg.startsWith("Vault unreachable after 3 attempts: HTTP 503"), msg);
        assertEquals(2, pauses.get());
    }
}
