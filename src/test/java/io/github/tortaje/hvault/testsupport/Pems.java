package io.github.tortaje.hvault.testsupport;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Reads generated test PEM files from src/test/resources/pem. */
public final class Pems {

    private Pems() {
    }

    public static String read(String name) {
        try {
            return Files.readString(Path.of("src/test/resources/pem", name), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
