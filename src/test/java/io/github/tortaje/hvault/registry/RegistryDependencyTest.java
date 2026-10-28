package io.github.tortaje.hvault.registry;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class RegistryDependencyTest {

    @Test
    void registryImportsOnlyJdk() throws IOException {
        Path dir = Path.of("src/main/java/io/github/tortaje/hvault/registry");
        List<Path> files;
        try (Stream<Path> s = Files.list(dir)) {
            files = s.filter(p -> p.toString().endsWith(".java")).toList();
        }
        assertFalse(files.isEmpty());
        for (Path f : files) {
            for (String line : Files.readAllLines(f)) {
                if (line.startsWith("import ")) {
                    String target = line.substring("import ".length()).replaceFirst("^static\\s+", "");
                    assertTrue(target.startsWith("java.") || target.startsWith("javax."),
                            f.getFileName() + " has non-JDK import: " + line);
                }
            }
        }
    }
}
