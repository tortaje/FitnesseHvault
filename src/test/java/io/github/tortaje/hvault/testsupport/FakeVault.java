package io.github.tortaje.hvault.testsupport;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.github.tortaje.hvault.registry.MtlsContexts;
import io.github.tortaje.hvault.registry.SecretRegistry;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/** Scriptable fake Vault server for tests. */
public final class FakeVault implements AutoCloseable {

    public record Recorded(String method, String path, Map<String, String> headers, String body) {
    }

    private record Reply(int status, String body, Duration delay, String location) {
    }

    private static final AtomicLong SEQ = new AtomicLong();

    private final HttpServer server;
    private final String scheme;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final Map<String, ConcurrentLinkedQueue<Reply>> queues = new ConcurrentHashMap<>();
    private final List<Recorded> recorded = new CopyOnWriteArrayList<>();

    private FakeVault(HttpServer server, String scheme) {
        this.server = server;
        this.scheme = scheme;
        server.createContext("/", this::handle);
        server.setExecutor(executor);
        server.start();
    }

    public static FakeVault http() {
        try {
            return new FakeVault(HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0),
                    "http");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static FakeVault https(String certPem, String keyPem) {
        // MtlsContexts only reads from SecretRegistry (no remove API): use unique private names;
        // SecretRegistry.clear() in other tests removes them.
        long n = SEQ.incrementAndGet();
        String certVar = "__fakevault.cert." + n;
        String keyVar = "__fakevault.key." + n;
        SecretRegistry.put(certVar, certPem);
        SecretRegistry.put(keyVar, keyPem);
        try {
            HttpsServer s = HttpsServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0);
            s.setHttpsConfigurator(new HttpsConfigurator(MtlsContexts.fromRegistry(certVar, keyVar, null)));
            return new FakeVault(s, "https");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String url() {
        return scheme + "://127.0.0.1:" + server.getAddress().getPort();
    }

    public void enqueue(String method, String path, int status, String jsonBody) {
        queue(method, path).add(new Reply(status, jsonBody, Duration.ZERO, null));
    }

    public void enqueueDelay(String method, String path, Duration delay) {
        queue(method, path).add(new Reply(200, "{}", delay, null));
    }

    /** Answers 307 with the given Location (absolute URL). */
    public void enqueueRedirect(String method, String path, String location) {
        queue(method, path).add(new Reply(307, "", Duration.ZERO, location));
    }

    public List<Recorded> requests() {
        return new ArrayList<>(recorded);
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private ConcurrentLinkedQueue<Reply> queue(String method, String path) {
        return queues.computeIfAbsent(method.toUpperCase() + " " + path, k -> new ConcurrentLinkedQueue<>());
    }

    private void handle(HttpExchange ex) throws IOException {
        String method = ex.getRequestMethod();
        String path = ex.getRequestURI().getPath();
        Map<String, String> headers = new TreeMap<>();
        ex.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(), String.join(",", v)));
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        recorded.add(new Recorded(method, path, headers, body));

        Reply reply = queue(method, path).poll();
        if (reply == null) {
            reply = new Reply(500, "{\"errors\":[\"unexpected request\"]}", Duration.ZERO, null);
        }
        if (!reply.delay().isZero()) {
            try {
                Thread.sleep(reply.delay().toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                ex.close();
                return;
            }
        }
        byte[] out = reply.body().getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        if (reply.location() != null) {
            ex.getResponseHeaders().set("Location", reply.location());
        }
        try {
            ex.sendResponseHeaders(reply.status(), out.length == 0 ? -1 : out.length);
            if (out.length > 0) {
                ex.getResponseBody().write(out);
            }
        } catch (IOException ignored) {
            // client gave up (timeout test)
        } finally {
            ex.close();
        }
    }
}
