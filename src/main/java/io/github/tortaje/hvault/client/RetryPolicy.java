package io.github.tortaje.hvault.client;

import io.github.tortaje.hvault.VaultFixtureException;
import io.github.tortaje.hvault.config.VaultConfig;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.DoubleSupplier;
import javax.net.ssl.SSLException;

/** Decides which Vault call failures are retried and how long to wait before each retry. */
public final class RetryPolicy {

    private static final double JITTER_FACTOR = 0.2;

    private final int maxAttempts;
    private final Duration initialDelay;
    private final Sleeper sleeper;
    private final DoubleSupplier random;

    public RetryPolicy(int maxAttempts, Duration initialDelay, Sleeper sleeper, DoubleSupplier random) {
        this.maxAttempts = maxAttempts;
        this.initialDelay = initialDelay;
        this.sleeper = sleeper;
        this.random = random;
    }

    public static RetryPolicy from(VaultConfig c, Sleeper s) {
        return new RetryPolicy(c.retryMaxAttempts(), c.retryInitialDelay(), s,
                () -> ThreadLocalRandom.current().nextDouble());
    }

    public int maxAttempts() {
        return maxAttempts;
    }

    public boolean isRetryableStatus(int status) {
        return status == 429 || status == 500 || status == 502 || status == 503 || status == 504;
    }

    public boolean isRetryable(Throwable t) {
        if (t instanceof SSLException) return false;
        return t instanceof IOException;
    }

    /** Delay before the given attempt (attempt >= 2): initialDelay * 2^(attempt-2) * (1 + 0.2 * random). */
    public Duration delayBefore(int attempt) {
        if (attempt < 2) {
            throw new IllegalArgumentException("delay only applies to attempts >= 2, got " + attempt);
        }
        double base = initialDelay.toMillis() * Math.pow(2, attempt - 2);
        double jittered = base * (1 + JITTER_FACTOR * random.getAsDouble());
        return Duration.ofMillis(Math.round(jittered));
    }

    public void pauseBefore(int attempt) {
        pause(delayBefore(attempt));
    }

    /** Sleeps for a delay obtained from {@link #delayBefore(int)}. */
    public void pause(Duration delay) {
        try {
            sleeper.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VaultFixtureException("Interrupted while waiting to retry Vault call", e);
        }
    }
}
