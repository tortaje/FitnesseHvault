package io.github.tortaje.hvault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class PackagedJarIT {

    private static Path shadedJar() throws IOException {
        try (Stream<Path> files = Files.list(Paths.get("target"))) {
            List<Path> jars = files
                    .filter(p -> p.getFileName().toString().matches("fitnesse-hvault-.*\\.jar"))
                    .filter(p -> !p.getFileName().toString().endsWith("-sources.jar"))
                    .filter(p -> !p.getFileName().toString().endsWith("-javadoc.jar"))
                    .collect(Collectors.toList());
            assertEquals(1, jars.size(), "expected exactly one packaged jar but found " + jars);
            return jars.get(0);
        }
    }

    @Test
    void shadedJarContents() throws IOException {
        List<String> names = new ArrayList<>();
        try (JarFile jar = new JarFile(shadedJar().toFile())) {
            jar.stream().filter(e -> !e.isDirectory()).forEach(e -> names.add(e.getName()));
        }
        assertTrue(names.stream().noneMatch(n -> n.startsWith("org/json/")), "org/json must be relocated");
        assertTrue(names.stream().noneMatch(n -> n.startsWith("io/opentelemetry/")), "OpenTelemetry must not be bundled");
        assertTrue(names.contains("io/github/tortaje/hvault/shaded/json/JSONObject.class"), "relocated JSONObject missing");
        assertTrue(names.stream().noneMatch(n -> n.endsWith("module-info.class")), "module-info.class must not be bundled");
        List<String> foreign = names.stream()
                .filter(n -> n.startsWith("io/github/tortaje/"))
                .filter(n -> !n.startsWith("io/github/tortaje/hvault/"))
                .collect(Collectors.toList());
        assertTrue(foreign.isEmpty(), "unexpected io/github/tortaje entries: " + foreign);
    }

    @Test
    void productionCodeDoesNotUseGlobalOpenTelemetry() throws IOException {
        try (Stream<Path> files = Files.walk(Paths.get("src/main/java"))) {
            List<Path> offenders = files.filter(p -> p.toString().endsWith(".java")).filter(p -> {
                try {
                    return Files.readString(p, StandardCharsets.UTF_8).contains("GlobalOpenTelemetry");
                } catch (IOException e) {
                    throw new java.io.UncheckedIOException(e);
                }
            }).collect(Collectors.toList());
            assertTrue(offenders.isEmpty(), "GlobalOpenTelemetry used in " + offenders);
        }
    }
}
