package io.github.tortaje.hvault.client;

import static org.junit.jupiter.api.Assertions.*;

import io.github.tortaje.hvault.VaultFixtureException;
import io.github.tortaje.hvault.config.VaultConfig;
import java.io.IOException;
import java.net.ConnectException;
import java.net.UnknownHostException;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.Test;

class RetryPolicyTest {

    private static RetryPolicy policy(Sleeper sleeper, double jitter) {
        return new RetryPolicy(3, Duration.ofMillis(1000), sleeper, () -> jitter);
    }

    @Test
    void retryableStatuses() {
        RetryPolicy p = policy(d -> {}, 0);
        for (int s : new int[] {429, 500, 502, 503, 504}) {
            assertTrue(p.isRetryableStatus(s), "status " + s);
        }
        for (int s : new int[] {400, 401, 403, 404, 501}) {
            assertFalse(p.isRetryableStatus(s), "status " + s);
        }
    }

    @Test
    void retryableExceptions() {
        RetryPolicy p = policy(d -> {}, 0);
        assertTrue(p.isRetryable(new ConnectException()));
        assertTrue(p.isRetryable(new HttpTimeoutException("timeout")));
        assertTrue(p.isRetryable(new UnknownHostException("host")));
        assertTrue(p.isRetryable(new IOException("x")));
        assertFalse(p.isRetryable(new SSLHandshakeException("handshake")));
        assertFalse(p.isRetryable(new SSLException("ssl")));
        assertFalse(p.isRetryable(new IllegalStateException()));
    }

    @Test
    void exponentialDelaysWithoutJitter() {
        RetryPolicy p = policy(d -> {}, 0);
        assertEquals(Duration.ofMillis(1000), p.delayBefore(2));
        assertEquals(Duration.ofMillis(2000), p.delayBefore(3));
        assertEquals(Duration.ofMillis(4000), p.delayBefore(4));
    }

    @Test
    void jitterUpTo20Percent() {
        RetryPolicy p = policy(d -> {}, 1.0);
        assertEquals(Duration.ofMillis(1200), p.delayBefore(2));
    }

    @Test
    void delayBeforeFirstAttemptIsRejected() {
        RetryPolicy p = policy(d -> {}, 0);
        assertThrows(IllegalArgumentException.class, () -> p.delayBefore(1));
    }

    @Test
    void pauseUsesSleeper() {
        List<Duration> slept = new ArrayList<>();
        RetryPolicy p = policy(slept::add, 0);
        p.pauseBefore(3);
        assertEquals(List.of(Duration.ofMillis(2000)), slept);
    }

    @Test
    void interruptRestoresFlag() {
        RetryPolicy p = policy(d -> {
            throw new InterruptedException("stop");
        }, 0);
        try {
            VaultFixtureException e = assertThrows(VaultFixtureException.class, () -> p.pauseBefore(2));
            assertEquals("Interrupted while waiting to retry Vault call", e.getMessage());
            assertTrue(Thread.interrupted());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void fromConfigUsesConfiguredValues() {
        VaultConfig cfg = VaultConfig.builder("http://vault.local:8200")
                .retryMaxAttempts(5)
                .retryInitialDelay(Duration.ofMillis(10))
                .build();
        RetryPolicy p = RetryPolicy.from(cfg, d -> {});
        assertEquals(5, p.maxAttempts());
        long ms = p.delayBefore(2).toMillis();
        assertTrue(ms >= 10 && ms <= 12, "delay was " + ms);
    }
}
