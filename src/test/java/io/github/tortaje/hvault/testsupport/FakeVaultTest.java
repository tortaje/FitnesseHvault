package io.github.tortaje.hvault.testsupport;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.tortaje.hvault.registry.MtlsContexts;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;

class FakeVaultTest {

    private static HttpResponse<String> get(HttpClient c, String url, String token) throws Exception {
        return c.send(HttpRequest.newBuilder(URI.create(url)).header("X-Vault-Token", token).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void servesQueuedResponsesInOrderAndRecords() throws Exception {
        try (FakeVault v = FakeVault.http()) {
            v.enqueue("GET", "/v1/secret/data/a", 503, "{}");
            v.enqueue("GET", "/v1/secret/data/a", 200, "{\"ok\":1}");
            HttpClient c = HttpClient.newHttpClient();
            assertEquals(503, get(c, v.url() + "/v1/secret/data/a?x=1", "t1").statusCode());
            HttpResponse<String> r2 = get(c, v.url() + "/v1/secret/data/a", "t2");
            assertEquals(200, r2.statusCode());
            assertEquals("{\"ok\":1}", r2.body());
            assertEquals(500, get(c, v.url() + "/v1/secret/data/a", "t3").statusCode());
            assertEquals(3, v.requests().size());
            assertEquals("/v1/secret/data/a", v.requests().get(0).path());
            assertEquals("t1", v.requests().get(0).headers().get("x-vault-token"));
            assertEquals("GET", v.requests().get(1).method());
        }
    }

    @Test
    void httpsWithTestCa() throws Exception {
        try (FakeVault v = FakeVault.https(Pems.read("server.pem"), Pems.read("server.key"))) {
            v.enqueue("GET", "/v1/x", 200, "{}");
            HttpClient c = HttpClient.newBuilder()
                    .sslContext(MtlsContexts.trustingOnly(Pems.read("ca.pem"))).build();
            assertEquals(200, get(c, v.url() + "/v1/x", "t").statusCode());
        }
    }
}
