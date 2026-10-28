package io.github.tortaje.hvault.client;

import java.time.Duration;

/** Abstraction over thread sleep so retry delays can be controlled in tests. */
@FunctionalInterface
public interface Sleeper {

    void sleep(Duration d) throws InterruptedException;

    static Sleeper real() {
        return d -> Thread.sleep(d.toMillis());
    }
}
