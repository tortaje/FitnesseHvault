package io.github.tortaje.hvault.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class VaultErrorsTest {

    @Test
    void joinsAndTruncates() {
        assertEquals("a; b", VaultErrors.summary("{\"errors\":[\"a\",\"b\"]}"));
        assertEquals(200, VaultErrors.summary("{\"errors\":[\"" + "x".repeat(300) + "\"]}").length());
        assertEquals("", VaultErrors.summary("<html>"));
        assertEquals("", VaultErrors.summary("{\"data\":{}}"));
        assertEquals("", VaultErrors.summary(null));
    }
}
