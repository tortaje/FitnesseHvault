package io.github.tortaje.hvault.client;

import io.github.tortaje.hvault.VaultFixtureException;
import io.github.tortaje.hvault.auth.TokenProvider;
import io.github.tortaje.hvault.config.VaultConfig;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiPredicate;
import java.util.logging.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/** Reads a KV v2 secret and maps Vault errors to the documented messages. */
public final class KvV2Reader {

    private static final Logger LOG = Logger.getLogger(KvV2Reader.class.getName());

    private final VaultConfig config;
    private final VaultHttpClient http;
    private final TokenProvider tokens;

    public KvV2Reader(VaultConfig config, VaultHttpClient http, TokenProvider tokens) {
        this.config = config;
        this.http = http;
        this.tokens = tokens;
    }

    /**
     * Reads the secret at {@code path} (already normalized). Values are returned as text, in response order.
     * In Kubernetes mode a 403 triggers exactly one re-login and retry.
     */
    public Map<String, String> read(String path, Attributes targetAttributes, boolean recordCount) {
        String mount = config.kvMount();
        String where = mount + "/" + path;
        Attributes attrs = targetAttributes.toBuilder()
                .put(AttributeKey.stringKey("vault.kv.mount"), mount)
                .put(AttributeKey.stringKey("vault.secret.path"), path)
                .build();
        boolean relogged = false;
        while (true) {
            Optional<Map<String, String>> result = http.get("/v1/" + mount + "/data/" + path,
                    "GET /v1/{mount}/data/{path}", attrs, tokens.token(), r -> handle(r, where, recordCount));
            if (result.isPresent()) return result.get();
            if (relogged || !tokens.canRelogin()) {
                throw new VaultFixtureException("Access denied to " + where + " (HTTP 403): check policy for "
                        + tokens.authDescription());
            }
            LOG.info(() -> "Access denied to " + where + " (HTTP 403) for " + tokens.authDescription()
                    + ", logging in again");
            tokens.invalidate();
            relogged = true;
        }
    }

    /** Empty when Vault answered 403, so that the caller can log in again. */
    private Optional<Map<String, String>> handle(HttpResult r, String where, boolean recordCount) {
        int status = r.status();
        if (status == 200) {
            Map<String, String> map = parse(r.body(), where);
            if (recordCount) Span.current().setAttribute("hvault.secret.count", (long) map.size());
            return Optional.of(map);
        }
        if (status == 404) throw new VaultFixtureException("Secret not found: " + where);
        if (status == 403) return Optional.empty();
        String summary = VaultErrors.summary(r.body());
        throw new VaultFixtureException("Vault error on " + where + " (HTTP " + status + ")"
                + (summary.isEmpty() ? "" : ": " + summary));
    }

    private static Map<String, String> parse(String body, String where) {
        Map<String, String> out = new LinkedHashMap<>();
        try {
            JSONTokener t = new JSONTokener(body);
            walk(t, (k, tk) -> {
                if (!k.equals("data")) return false;
                walk(tk, (k2, tk2) -> {
                    if (!k2.equals("data")) return false;
                    walk(tk2, (key, tk3) -> {
                        out.put(key, text(tk3.nextValue()));
                        return true;
                    });
                    return true;
                });
                return true;
            });
        } catch (JSONException e) {
            throw new VaultFixtureException("Vault error on " + where + " (HTTP 200): unexpected response");
        }
        return out;
    }

    /** Walks the members of the JSON object at the tokener position; the handler returns true if it consumed the value. */
    private static void walk(JSONTokener t, BiPredicate<String, JSONTokener> handler) {
        if (t.nextClean() != '{') throw new JSONException("object expected");
        char c = t.nextClean();
        if (c == '}') return;
        t.back();
        do {
            String key = String.valueOf(t.nextValue());
            if (t.nextClean() != ':') throw new JSONException("colon expected");
            if (!handler.test(key, t)) t.nextValue();
            c = t.nextClean();
        } while (c == ',');
        if (c != '}') throw new JSONException("object end expected");
    }

    private static String text(Object value) {
        if (value == JSONObject.NULL) return "null";
        if (value instanceof String s) return s;
        return String.valueOf(value);
    }
}
