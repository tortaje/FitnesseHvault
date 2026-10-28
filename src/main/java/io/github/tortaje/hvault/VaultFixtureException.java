package io.github.tortaje.hvault;

/** Unchecked error raised by the Vault fixture; messages never contain secret values. */
public class VaultFixtureException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public VaultFixtureException(String message) {
        super(message);
    }

    public VaultFixtureException(String message, Throwable cause) {
        super(message, cause);
    }
}
