package io.github.tortaje.hvault.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class VaultUrisTest {

    private static final String CHARS = "'#', '?', whitespace and control characters are not allowed";
    private static final String DOTS = "'.', '..' and empty segments are not allowed";

    @Test
    void validPathsHaveNoProblem() {
        assertNull(VaultUris.pathProblem("app/oauth"));
        assertNull(VaultUris.pathProblem("a.b/c..d/e."));
        assertNull(VaultUris.pathProblem("secret"));
    }

    @Test
    void forbiddenCharacters() {
        for (String p : new String[] {"a#b", "a?b", "a b", "a\tb", "a\u0001b"}) {
            assertEquals(CHARS, VaultUris.pathProblem(p), p);
        }
    }

    @Test
    void dotSegments() {
        for (String p : new String[] {"..", ".", "a/../b", "../a", "a/..", "a/./b", "a//b"}) {
            assertEquals(DOTS, VaultUris.pathProblem(p), p);
        }
    }

    @Test
    void emptyPath() {
        assertEquals("empty path", VaultUris.pathProblem(""));
    }

    @Test
    void redactsUserInfo() {
        assertEquals("https://REDACTED:REDACTED@vault.example.com:8200/x",
                VaultUris.redactUserInfo("https://user:pass@vault.example.com:8200/x"));
        assertEquals("https://vault.example.com:8200", VaultUris.redactUserInfo("https://vault.example.com:8200"));
        assertEquals("not a uri", VaultUris.redactUserInfo("not a uri"));
        assertNull(VaultUris.redactUserInfo(null));
    }

    @Test
    void loopbackHosts() {
        for (String h : new String[] {"localhost", "LOCALHOST", "127.0.0.1", "127.1.2.3", "::1", "[::1]"}) {
            assertTrue(VaultUris.isLoopback(h), h);
        }
        for (String h : new String[] {"vault.example.com", "10.0.0.1", "128.0.0.1", "localhost.example.com"}) {
            assertFalse(VaultUris.isLoopback(h), h);
        }
    }
}
