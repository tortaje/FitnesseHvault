package io.github.tortaje.hvault.config;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/** Validation and redaction rules for the URLs and paths sent to Vault. */
public final class VaultUris {

    private VaultUris() {
    }

    /**
     * Returns why {@code path} (a secret path or a mount, without leading or trailing '/') cannot be used in a
     * Vault URL, or null if it can.
     */
    public static String pathProblem(String path) {
        if (path.isEmpty()) return "empty path";
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c == '#' || c == '?' || Character.isWhitespace(c) || Character.isISOControl(c)) {
                return "'#', '?', whitespace and control characters are not allowed";
            }
        }
        for (String segment : path.split("/", -1)) {
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) {
                return "'.', '..' and empty segments are not allowed";
            }
        }
        return null;
    }

    /** Replaces the user info of a URL with REDACTED:REDACTED; returns other values unchanged. */
    public static String redactUserInfo(String url) {
        if (url == null) return null;
        try {
            URI u = new URI(url);
            if (u.getRawUserInfo() == null) return url;
            return url.replace(u.getRawUserInfo() + "@", "REDACTED:REDACTED@");
        } catch (URISyntaxException e) {
            return url;
        }
    }

    /** True for localhost, 127.0.0.0/8 and ::1. */
    public static boolean isLoopback(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) h = h.substring(1, h.length() - 1);
        return h.equals("localhost") || h.equals("::1") || h.matches("127(\\.\\d{1,3}){3}");
    }
}
