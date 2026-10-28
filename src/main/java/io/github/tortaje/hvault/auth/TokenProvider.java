package io.github.tortaje.hvault.auth;

import io.github.tortaje.hvault.VaultFixtureException;
import io.github.tortaje.hvault.client.HttpResult;
import io.github.tortaje.hvault.client.VaultErrors;
import io.github.tortaje.hvault.client.VaultHttpClient;
import io.github.tortaje.hvault.config.VaultConfig;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.logging.Logger;
import org.json.JSONException;
import org.json.JSONObject;

/** Supplies the Vault token: static, or obtained by Kubernetes login and renewed before expiry. */
public final class TokenProvider {

    private static final Logger LOG = Logger.getLogger(TokenProvider.class.getName());
    private static final long EXPIRY_MARGIN_SECONDS = 30;
    private static final String NO_AUTH = "No Vault auth available: set VAULT_TOKEN, "
            + "or VAULT_ROLE with a mounted service account token";

    private enum Mode { STATIC, KUBERNETES }

    private final VaultConfig config;
    private final VaultHttpClient http;
    private final Clock clock;

    private Mode mode;
    private String token;
    private Instant expiry; // null = never expires

    public TokenProvider(VaultConfig config, VaultHttpClient http, Clock clock) {
        this.config = config;
        this.http = http;
        this.clock = clock;
    }

    /** Returns a valid token, logging in (Kubernetes mode) when none is cached or it is about to expire. */
    public synchronized String token() {
        if (mode == null) {
            mode = resolveMode();
            LOG.info(() -> mode == Mode.STATIC ? "Vault auth: static token"
                    : "Vault auth: Kubernetes login with role '" + config.role().get() + "' (auth path "
                    + config.k8sAuthPath() + ")");
        }
        if (mode == Mode.STATIC) {
            return config.token().get();
        }
        if (token == null) {
            login();
        } else if (expiry != null && !clock.instant().isBefore(expiry)) {
            LOG.info(() -> "Vault token for role '" + config.role().get() + "' expires soon, logging in again");
            login();
        }
        return token;
    }

    /** Drops the cached login token so the next {@link #token()} logs in again. */
    public synchronized void invalidate() {
        if (mode == Mode.KUBERNETES) {
            token = null;
            expiry = null;
        }
    }

    /** True when a new login can produce a fresh token (Kubernetes mode). */
    public synchronized boolean canRelogin() {
        return (mode != null ? mode : resolveModeQuietly()) == Mode.KUBERNETES;
    }

    /** Human-readable auth source for error messages. */
    public String authDescription() {
        return canRelogin() ? "role '" + config.role().orElse("") + "'" : "the provided token";
    }

    private Mode resolveMode() {
        if (config.token().isPresent()) return Mode.STATIC;
        if (config.role().isPresent() && Files.isReadable(config.k8sTokenPath())) return Mode.KUBERNETES;
        throw new VaultFixtureException(NO_AUTH);
    }

    private Mode resolveModeQuietly() {
        try {
            return resolveMode();
        } catch (VaultFixtureException e) {
            return Mode.STATIC;
        }
    }

    private void login() {
        String role = config.role().get();
        String jwt;
        try {
            jwt = Files.readString(config.k8sTokenPath()).trim();
        } catch (IOException e) {
            throw new VaultFixtureException(NO_AUTH, e);
        }
        String body = new JSONObject().put("role", role).put("jwt", jwt).toString();
        Attributes attrs = Attributes.of(
                AttributeKey.stringKey("vault.auth.method"), "kubernetes",
                AttributeKey.stringKey("vault.auth.role"), role);
        String mount = config.k8sAuthPath();
        http.post("/v1/auth/" + mount + "/login", "POST /v1/auth/{mount}/login", attrs, null, body,
                r -> handleLogin(r, role, mount));
    }

    private Void handleLogin(HttpResult r, String role, String mount) {
        int status = r.status();
        if (status == 400 || status == 403) {
            throw new VaultFixtureException("Kubernetes login rejected for role '" + role + "' (HTTP " + status + ")");
        }
        if (status < 200 || status >= 300) {
            String summary = VaultErrors.summary(r.body());
            throw new VaultFixtureException("Vault error on auth/" + mount + "/login (HTTP " + status + ")"
                    + (summary.isEmpty() ? "" : ": " + summary));
        }
        try {
            JSONObject auth = new JSONObject(r.body()).getJSONObject("auth");
            String clientToken = auth.getString("client_token");
            long lease = auth.optLong("lease_duration", 0);
            this.token = clientToken;
            // renew 30 s before expiry, or at half-life for leases shorter than a minute
            this.expiry = lease > 0
                    ? clock.instant().plusSeconds(lease - Math.min(EXPIRY_MARGIN_SECONDS, lease / 2)) : null;
            LOG.info(() -> "Kubernetes login succeeded for role '" + role + "', Vault token "
                    + (lease > 0 ? "valid for " + lease + " s" : "does not expire"));
        } catch (JSONException e) {
            throw new VaultFixtureException("Vault error on auth/" + mount + "/login (HTTP " + status
                    + "): unexpected response");
        }
        return null;
    }
}
