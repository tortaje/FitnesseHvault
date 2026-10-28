package io.github.tortaje.hvault;

import io.github.tortaje.hvault.auth.TokenProvider;
import io.github.tortaje.hvault.client.KvV2Reader;
import io.github.tortaje.hvault.client.RetryPolicy;
import io.github.tortaje.hvault.client.Sleeper;
import io.github.tortaje.hvault.client.VaultHttpClient;
import io.github.tortaje.hvault.config.VaultConfig;
import java.time.Clock;

/** Wired Vault client stack, shared per JVM in production. */
final class VaultRuntime {

    private static VaultRuntime shared;

    private final VaultConfig config;
    private final KvV2Reader reader;

    private VaultRuntime(VaultConfig config, KvV2Reader reader) {
        this.config = config;
        this.reader = reader;
    }

    static VaultRuntime create(VaultConfig config, Sleeper sleeper, Clock clock) {
        VaultHttpClient http = new VaultHttpClient(config, RetryPolicy.from(config, sleeper));
        TokenProvider tokens = new TokenProvider(config, http, clock);
        return new VaultRuntime(config, new KvV2Reader(config, http, tokens));
    }

    /** Created on first successful call; a configuration failure is not cached. */
    static synchronized VaultRuntime shared() {
        if (shared == null) {
            shared = create(VaultConfig.fromEnvironment(), Sleeper.real(), Clock.systemUTC());
        }
        return shared;
    }

    KvV2Reader reader() {
        return reader;
    }

    VaultConfig config() {
        return config;
    }
}
