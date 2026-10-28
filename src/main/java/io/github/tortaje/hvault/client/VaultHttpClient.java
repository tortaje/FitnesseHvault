package io.github.tortaje.hvault.client;

import io.github.tortaje.hvault.VaultFixtureException;
import io.github.tortaje.hvault.config.VaultConfig;
import io.github.tortaje.hvault.config.VaultUris;
import io.github.tortaje.hvault.otel.Traced;
import io.github.tortaje.hvault.registry.MtlsContexts;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.time.Duration;
import java.util.function.Function;
import java.util.logging.Logger;
import javax.net.ssl.SSLException;

/** Sends every request to Vault: retry loop, one CLIENT span per attempt, TLS with optional CA. */
public final class VaultHttpClient {

    private static final Logger LOG = Logger.getLogger(VaultHttpClient.class.getName());

    /** Returned by an attempt that got a retryable status and has attempts left. */
    private record Retry(int status) { }

    private final VaultConfig config;
    private final RetryPolicy retry;
    private final HttpClient http;

    public VaultHttpClient(VaultConfig config, RetryPolicy retry) {
        this.config = config;
        this.retry = retry;
        // NORMAL follows redirects (e.g. an HA standby pointing to the active node) but never HTTPS -> HTTP
        HttpClient.Builder b = HttpClient.newBuilder().connectTimeout(config.connectTimeout())
                .followRedirects(HttpClient.Redirect.NORMAL);
        URI addr = URI.create(config.addr());
        if ("http".equalsIgnoreCase(addr.getScheme()) && !VaultUris.isLoopback(addr.getHost())) {
            LOG.warning(() -> "VAULT_ADDR uses plain HTTP to " + addr.getHost()
                    + ": the Vault token and secrets are sent unencrypted");
        }
        if (config.caCert().isPresent()) {
            java.nio.file.Path ca = config.caCert().get();
            try {
                b.sslContext(MtlsContexts.trustingOnly(Files.readString(ca)));
            } catch (IOException | RuntimeException e) {
                throw new VaultFixtureException("Invalid VAULT_CACERT file " + ca, e);
            }
        }
        this.http = b.build();
    }

    public <T> T get(String apiPath, String spanName, Attributes attributes, String token,
                     Function<HttpResult, T> handler) {
        return execute("GET", apiPath, spanName, attributes, token, null, handler);
    }

    /** {@code token} may be null (login): no X-Vault-Token header is sent. */
    public <T> T post(String apiPath, String spanName, Attributes attributes, String token, String jsonBody,
                      Function<HttpResult, T> handler) {
        return execute("POST", apiPath, spanName, attributes, token, jsonBody, handler);
    }

    @SuppressWarnings("unchecked")
    private <T> T execute(String method, String apiPath, String spanName, Attributes attributes, String token,
                          String jsonBody, Function<HttpResult, T> handler) {
        String url = config.addr() + apiPath;
        URI uri = URI.create(url);
        String call = "Vault " + method + " " + apiPath;
        int max = retry.maxAttempts();
        for (int n = 1; ; n++) {
            final int attempt = n;
            Attributes attrs = spanAttributes(attributes, method, VaultUris.redactUserInfo(url), uri, attempt);
            String failure;
            try {
                Object result = Traced.call(spanName, attrs,
                        () -> attemptOnce(method, uri, token, jsonBody, handler, call, attempt, max));
                if (!(result instanceof Retry r)) return (T) result;
                failure = "HTTP " + r.status();
            } catch (VaultFixtureException e) {
                throw e;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new VaultFixtureException("Interrupted while calling Vault", e);
            } catch (Exception e) {
                if (isTls(e)) {
                    throw new VaultFixtureException("TLS error to Vault: check VAULT_CACERT", e);
                }
                if (!retry.isRetryable(e)) {
                    throw e instanceof RuntimeException re ? re : new VaultFixtureException(e.toString(), e);
                }
                if (attempt >= max) {
                    logGivingUp(call, attempt, max, e.toString());
                    throw new VaultFixtureException("Vault unreachable after " + attempt + " attempts: " + e, e);
                }
                failure = e.toString();
            }
            Duration delay = retry.delayBefore(attempt + 1);
            String cause = failure;
            LOG.warning(() -> call + ": attempt " + attempt + "/" + max + " failed (" + cause + "), retrying in "
                    + delay.toMillis() + " ms");
            retry.pause(delay);
        }
    }

    private static void logGivingUp(String call, int attempt, int max, String cause) {
        LOG.warning(() -> call + ": attempt " + attempt + "/" + max + " failed (" + cause + "), giving up");
    }

    private <T> Object attemptOnce(String method, URI uri, String token, String jsonBody,
                                   Function<HttpResult, T> handler, String call, int attempt, int max)
            throws Exception {
        HttpRequest.Builder rb = HttpRequest.newBuilder(uri).timeout(config.requestTimeout());
        if (token != null) rb.header("X-Vault-Token", token);
        config.namespace().ifPresent(ns -> rb.header("X-Vault-Namespace", ns));
        if (jsonBody != null) {
            rb.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(jsonBody));
        } else {
            rb.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<String> resp = http.send(rb.build(), HttpResponse.BodyHandlers.ofString());
        int status = resp.statusCode();
        Span span = Span.current();
        span.setAttribute("http.response.status_code", (long) status);
        if (status >= 400) {
            span.setStatus(StatusCode.ERROR);
            span.setAttribute("error.type", String.valueOf(status));
        }
        if (retry.isRetryableStatus(status)) {
            if (attempt < max) return new Retry(status);
            logGivingUp(call, attempt, max, "HTTP " + status);
            String summary = VaultErrors.summary(resp.body());
            throw new VaultFixtureException("Vault unreachable after " + attempt + " attempts: HTTP " + status
                    + (summary.isEmpty() ? "" : " " + summary));
        }
        return handler.apply(new HttpResult(status, resp.body()));
    }

    private static Attributes spanAttributes(Attributes extra, String method, String url, URI uri, int attempt) {
        AttributesBuilder b = Attributes.builder().putAll(extra)
                .put("http.request.method", method)
                .put("url.full", url)
                .put("server.address", uri.getHost())
                .put("server.port", (long) (uri.getPort() > 0 ? uri.getPort()
                        : "https".equals(uri.getScheme()) ? 443 : 80));
        if (attempt >= 2) b.put("http.request.resend_count", (long) (attempt - 1));
        return b.build();
    }

    private static boolean isTls(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof SSLException) return true;
        }
        return false;
    }
}
