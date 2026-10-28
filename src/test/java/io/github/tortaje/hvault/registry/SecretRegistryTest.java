package io.github.tortaje.hvault.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SecretRegistryTest {

    @AfterEach
    void reset() {
        SecretRegistry.clear();
    }

    @Test
    void putThenGet() {
        SecretRegistry.put("a", "x");
        assertEquals("x", SecretRegistry.get("a"));
    }

    @Test
    void putReplaces() {
        SecretRegistry.put("a", "x");
        SecretRegistry.put("a", "y");
        assertEquals("y", SecretRegistry.get("a"));
    }

    @Test
    void getMissingThrows() {
        var e = assertThrows(IllegalStateException.class, () -> SecretRegistry.get("nope"));
        assertEquals("Registry variable 'nope' missing", e.getMessage());
    }

    @Test
    void containsAndClear() {
        SecretRegistry.put("a", "x");
        assertTrue(SecretRegistry.contains("a"));
        SecretRegistry.clear();
        assertFalse(SecretRegistry.contains("a"));
    }

    @Test
    void concurrentPuts() throws Exception {
        int threads = 8;
        int perThread = 1000;
        List<Thread> workers = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int id = t;
            Thread th = new Thread(() -> {
                for (int i = 0; i < perThread; i++) {
                    SecretRegistry.put("k" + id + "-" + i, "v" + i);
                }
            });
            workers.add(th);
            th.start();
        }
        for (Thread th : workers) {
            th.join();
        }
        for (int t = 0; t < threads; t++) {
            for (int i = 0; i < perThread; i++) {
                assertTrue(SecretRegistry.contains("k" + t + "-" + i));
            }
        }
    }

    @Test
    void nullsRejected() {
        assertEquals("variable must not be null",
                assertThrows(NullPointerException.class, () -> SecretRegistry.put(null, "x")).getMessage());
        assertEquals("value must not be null",
                assertThrows(NullPointerException.class, () -> SecretRegistry.put("a", null)).getMessage());
        assertEquals("variable must not be null",
                assertThrows(NullPointerException.class, () -> SecretRegistry.get(null)).getMessage());
        assertEquals("variable must not be null",
                assertThrows(NullPointerException.class, () -> SecretRegistry.contains(null)).getMessage());
    }
}
