package io.github.tortaje.hvault;

import io.github.tortaje.hvault.config.VaultUris;
import io.github.tortaje.hvault.registry.SecretRegistry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.util.Map;
import java.util.function.Supplier;
import java.util.logging.Logger;

/** FitNesse script-table fixture reading HashiCorp Vault KV v2 secrets into the secret registry. */
public class HVault {

    private static final Logger LOG = Logger.getLogger(HVault.class.getName());

    private final Supplier<VaultRuntime> supplier;
    private VaultRuntime runtime;

    public HVault() {
        this(VaultRuntime::shared);
    }

    HVault(Supplier<VaultRuntime> runtime) {
        this.supplier = runtime;
    }

    /** Stores {@code key} of the secret at {@code path} under {@code variable}; returns a masked string. */
    public String readSecretKeyInto(String path, String key, String variable) {
        VaultRuntime rt = runtime();
        String p = normalize(path);
        Map<String, String> data = rt.reader().read(p, Attributes.of(
                AttributeKey.stringKey("hvault.target.variable"), variable), false);
        String value = data.get(key);
        if (value == null) {
            throw new VaultFixtureException("Key '" + key + "' not found in " + rt.config().kvMount() + "/" + p
                    + " (available keys: " + String.join(", ", data.keySet()) + ")");
        }
        SecretRegistry.put(variable, value);
        LOG.info(() -> "Stored key '" + key + "' of " + rt.config().kvMount() + "/" + p + " into '" + variable + "'");
        return "******** [STORED SAFELY IN " + variable + "]";
    }

    /** Stores every key of the secret at {@code path} under {@code prefix + key}; all or nothing. */
    public String readAllSecretsFromWithPrefix(String path, String prefix) {
        String p = normalize(path);
        VaultRuntime rt = runtime();
        Map<String, String> data = rt.reader().read(p, Attributes.of(
                AttributeKey.stringKey("hvault.target.prefix"), prefix), true);
        data.forEach((k, v) -> SecretRegistry.put(prefix + k, v));
        LOG.info(() -> "Stored " + data.size() + " keys of " + rt.config().kvMount() + "/" + p
                + " with prefix '" + prefix + "'");
        return "******** [" + data.size() + " SECRETS STORED WITH PREFIX " + prefix + "]";
    }

    /** Empties the secret registry. */
    public boolean clearSecrets() {
        SecretRegistry.clear();
        return true;
    }

    private synchronized VaultRuntime runtime() {
        if (runtime == null) {
            runtime = supplier.get();
        }
        return runtime;
    }

    private static String normalize(String path) {
        String p = path.trim();
        int start = 0;
        int end = p.length();
        while (start < end && p.charAt(start) == '/') start++;
        while (end > start && p.charAt(end - 1) == '/') end--;
        p = p.substring(start, end);
        String problem = VaultUris.pathProblem(p);
        if (problem != null) {
            throw new VaultFixtureException("Invalid secret path '" + path + "': " + problem);
        }
        return p;
    }
}
