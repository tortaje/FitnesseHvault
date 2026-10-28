package io.github.tortaje.hvault.otel;

import io.github.tortaje.otel.OtelFixtures;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.context.Scope;
import java.util.concurrent.Callable;

/** Wraps one outgoing call in a CLIENT span, made current, ended and marked in error on failure. */
public final class Traced {

    private Traced() {
    }

    public static <T> T call(String spanName, Attributes attributes, Callable<T> call) throws Exception {
        Span span = OtelFixtures.tracer().spanBuilder(spanName)
                .setSpanKind(SpanKind.CLIENT)
                .setAllAttributes(attributes)
                .startSpan();
        try (Scope ignored = span.makeCurrent()) {
            return call.call();
        } catch (Exception e) {
            span.recordException(e);
            span.setStatus(StatusCode.ERROR);
            span.setAttribute("error.type", e.getClass().getName());
            throw e;
        } finally {
            span.end();
        }
    }
}
