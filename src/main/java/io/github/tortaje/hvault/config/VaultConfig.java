package io.github.tortaje.hvault.config;

import io.github.tortaje.hvault.VaultFixtureException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;
import java.util.Properties;
import java.util.logging.Logger;

/** Immutable Vault settings resolved from env > system properties > hvault.properties. */
public final class VaultConfig {
    private static final Logger LOG = Logger.getLogger(VaultConfig.class.getName());
    private static final String DEFAULT_K8S_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    private final String addr;
    private final String token;
    private final String role;
    private final String namespace;
    private final Path caCert;
    private final String kvMount;
    private final String k8sAuthPath;
    private final Path k8sTokenPath;
    private final int retryMaxAttempts;
    private final Duration retryInitialDelay;
    private final Duration connectTimeout;
    private final Duration requestTimeout;

    private VaultConfig(Builder b) {
        this.addr = b.addr;
        this.token = b.token;
        this.role = b.role;
        this.namespace = b.namespace;
        this.caCert = b.caCert;
        this.kvMount = b.kvMount;
        this.k8sAuthPath = b.k8sAuthPath;
        this.k8sTokenPath = b.k8sTokenPath;
        this.retryMaxAttempts = b.retryMaxAttempts;
        this.retryInitialDelay = b.retryInitialDelay;
        this.connectTimeout = b.connectTimeout;
        this.requestTimeout = b.requestTimeout;
    }

    /** Resolves the configuration from the real environment, system properties and hvault.properties. */
    public static VaultConfig fromEnvironment() {
        return load(EnvSource.system(), System.getProperties(), loadFileProps());
    }

    public static VaultConfig load(EnvSource env, Properties systemProps, Properties fileProps) {
        if (fileProps.getProperty("hvault.token") != null) {
            LOG.warning("hvault.token in hvault.properties is ignored: use VAULT_TOKEN");
        }
        String addr = resolve(env, systemProps, fileProps, "VAULT_ADDR", "hvault.addr");
        if (addr == null) {
            throw new VaultFixtureException("Vault not configured: VAULT_ADDR missing (env, -D or hvault.properties)");
        }
        Builder b = builder(addr);
        // hvault.token is never read from the file
        b.token = resolve(env, systemProps, null, "VAULT_TOKEN", "hvault.token");
        b.role = resolve(env, systemProps, fileProps, "VAULT_ROLE", "hvault.role");
        b.namespace = resolve(env, systemProps, fileProps, "VAULT_NAMESPACE", "hvault.namespace");
        String ca = resolve(env, systemProps, fileProps, "VAULT_CACERT", "hvault.cacert");
        b.caCert = ca == null ? null : Path.of(ca);
        b.kvMount = orDefault(resolve(env, systemProps, fileProps, "VAULT_KV_MOUNT", "hvault.kv.mount"), b.kvMount);
        b.k8sAuthPath = orDefault(
                resolve(env, systemProps, fileProps, "VAULT_K8S_AUTH_PATH", "hvault.k8s.auth.path"), b.k8sAuthPath);
        String jwt = resolve(env, systemProps, fileProps, "VAULT_K8S_TOKEN_PATH", "hvault.k8s.token.path");
        if (jwt != null) b.k8sTokenPath = Path.of(jwt);
        b.retryMaxAttempts = number(env, systemProps, fileProps,
                "VAULT_RETRY_MAX_ATTEMPTS", "hvault.retry.max.attempts", b.retryMaxAttempts, 1);
        b.retryInitialDelay = Duration.ofMillis(number(env, systemProps, fileProps,
                "VAULT_RETRY_INITIAL_DELAY_MS", "hvault.retry.initial.delay.ms", (int) b.retryInitialDelay.toMillis(), 0));
        b.connectTimeout = Duration.ofMillis(number(env, systemProps, fileProps,
                "VAULT_CONNECT_TIMEOUT_MS", "hvault.connect.timeout.ms", (int) b.connectTimeout.toMillis(), 1));
        b.requestTimeout = Duration.ofMillis(number(env, systemProps, fileProps,
                "VAULT_REQUEST_TIMEOUT_MS", "hvault.request.timeout.ms", (int) b.requestTimeout.toMillis(), 1));
        return b.build();
    }

    public static Builder builder(String addr) {
        return new Builder(addr);
    }

    private static Properties loadFileProps() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) cl = VaultConfig.class.getClassLoader();
        try (InputStream in = cl.getResourceAsStream("hvault.properties")) {
            return readProps(in);
        } catch (IOException e) {
            throw new VaultFixtureException("Cannot read hvault.properties", e);
        }
    }

    static Properties readProps(InputStream in) {
        Properties p = new Properties();
        if (in == null) return p;
        try {
            p.load(in);
        } catch (IOException | IllegalArgumentException e) {
            throw new VaultFixtureException("Cannot read hvault.properties", e);
        }
        return p;
    }

    private static boolean validAddr(String a) {
        try {
            java.net.URI u = new java.net.URI(a);
            return u.isAbsolute() && ("http".equalsIgnoreCase(u.getScheme()) || "https".equalsIgnoreCase(u.getScheme()))
                    && u.getHost() != null;
        } catch (java.net.URISyntaxException e) {
            return false;
        }
    }

    private static String clean(String v) {
        if (v == null) return null;
        String t = v.trim();
        return t.isEmpty() ? null : t;
    }

    private static String resolve(EnvSource env, Properties sys, Properties file, String envName, String prop) {
        String v = clean(env.get(envName));
        if (v == null) v = clean(sys.getProperty(prop));
        if (v == null && file != null) v = clean(file.getProperty(prop));
        return v;
    }

    private static String orDefault(String v, String def) {
        return v != null ? v : def;
    }

    private static int number(EnvSource env, Properties sys, Properties file, String envName, String prop, int def,
                              int min) {
        String v = resolve(env, sys, file, envName, prop);
        if (v == null) return def;
        try {
            int n = Integer.parseInt(v);
            if (n >= min) return n;
        } catch (NumberFormatException e) {
            // reported below
        }
        throw new VaultFixtureException("Invalid value for " + envName + ": " + v);
    }

    public String addr() { return addr; }
    public Optional<String> token() { return Optional.ofNullable(token); }
    public Optional<String> role() { return Optional.ofNullable(role); }
    public Optional<String> namespace() { return Optional.ofNullable(namespace); }
    public Optional<Path> caCert() { return Optional.ofNullable(caCert); }
    public String kvMount() { return kvMount; }
    public String k8sAuthPath() { return k8sAuthPath; }
    public Path k8sTokenPath() { return k8sTokenPath; }
    public int retryMaxAttempts() { return retryMaxAttempts; }
    public Duration retryInitialDelay() { return retryInitialDelay; }
    public Duration connectTimeout() { return connectTimeout; }
    public Duration requestTimeout() { return requestTimeout; }

    /** Builder applying the same defaults as {@link #load}. */
    public static final class Builder {
        private String addr;
        private String rawAddr;
        private String token;
        private String role;
        private String namespace;
        private Path caCert;
        private String kvMount = "secret";
        private String k8sAuthPath = "kubernetes";
        private Path k8sTokenPath = Path.of(DEFAULT_K8S_TOKEN);
        private int retryMaxAttempts = 3;
        private Duration retryInitialDelay = Duration.ofMillis(1000);
        private Duration connectTimeout = Duration.ofMillis(5000);
        private Duration requestTimeout = Duration.ofMillis(10000);

        private Builder(String addr) {
            addr(addr);
        }

        private static String stripSlash(String a) {
            return a != null && a.endsWith("/") ? a.substring(0, a.length() - 1) : a;
        }

        public Builder addr(String v) { this.rawAddr = v; this.addr = stripSlash(v); return this; }
        public Builder token(String v) { this.token = v; return this; }
        public Builder role(String v) { this.role = v; return this; }
        public Builder namespace(String v) { this.namespace = v; return this; }
        public Builder caCert(Path v) { this.caCert = v; return this; }
        public Builder kvMount(String v) { this.kvMount = v; return this; }
        public Builder k8sAuthPath(String v) { this.k8sAuthPath = v; return this; }
        public Builder k8sTokenPath(Path v) { this.k8sTokenPath = v; return this; }
        public Builder retryMaxAttempts(int v) { this.retryMaxAttempts = v; return this; }
        public Builder retryInitialDelay(Duration v) { this.retryInitialDelay = v; return this; }
        public Builder connectTimeout(Duration v) { this.connectTimeout = v; return this; }
        public Builder requestTimeout(Duration v) { this.requestTimeout = v; return this; }

        public VaultConfig build() {
            if (addr == null || !validAddr(addr)) {
                throw new VaultFixtureException("Invalid value for VAULT_ADDR: " + VaultUris.redactUserInfo(rawAddr));
            }
            if (kvMount == null || VaultUris.pathProblem(kvMount) != null) {
                throw new VaultFixtureException("Invalid value for VAULT_KV_MOUNT: " + kvMount);
            }
            if (k8sAuthPath == null || VaultUris.pathProblem(k8sAuthPath) != null) {
                throw new VaultFixtureException("Invalid value for VAULT_K8S_AUTH_PATH: " + k8sAuthPath);
            }
            if (namespace != null && namespace.chars().anyMatch(Character::isISOControl)) {
                throw new VaultFixtureException("Invalid value for VAULT_NAMESPACE: control characters are not allowed");
            }
            return new VaultConfig(this);
        }
    }
}
