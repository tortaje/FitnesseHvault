package io.github.tortaje.hvault.client;

/** Status and raw body of a Vault HTTP response. */
public record HttpResult(int status, String body) {
}
