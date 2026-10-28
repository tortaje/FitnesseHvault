package io.github.tortaje.hvault.otel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.opentelemetry.api.common.Attributes;
import java.io.IOException;
import org.junit.jupiter.api.Test;

class TracedTest {

    @Test
    void returnsValue() throws Exception {
        assertEquals(42, Traced.call("x", Attributes.empty(), () -> 42));
    }

    @Test
    void rethrowsSameException() {
        var ex = new IOException("boom");
        assertSame(ex, assertThrows(IOException.class, () -> Traced.call("x", Attributes.empty(), () -> {
            throw ex;
        })));
    }
}
