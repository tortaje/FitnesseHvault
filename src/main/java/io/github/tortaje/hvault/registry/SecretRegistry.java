package io.github.tortaje.hvault.registry;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/** Process-wide store of secret values keyed by wiki variable name. */
public final class SecretRegistry {

    private static final Map<String, String> VALUES = new ConcurrentHashMap<>();

    private SecretRegistry() {
    }

    public static void put(String variable, String value) {
        Objects.requireNonNull(variable, "variable must not be null");
        Objects.requireNonNull(value, "value must not be null");
        VALUES.put(variable, value);
    }

    public static String get(String variable) {
        Objects.requireNonNull(variable, "variable must not be null");
        String value = VALUES.get(variable);
        if (value == null) {
            throw new IllegalStateException("Registry variable '" + variable + "' missing");
        }
        return value;
    }

    public static boolean contains(String variable) {
        Objects.requireNonNull(variable, "variable must not be null");
        return VALUES.containsKey(variable);
    }

    public static void clear() {
        VALUES.clear();
    }
}
