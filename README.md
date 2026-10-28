# fitnesse-hvault

[![Maven Central](https://img.shields.io/maven-central/v/io.github.tortaje/fitnesse-hvault.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.tortaje/fitnesse-hvault)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A FitNesse fixture that reads secrets from HashiCorp Vault (KV v2) into an in-memory registry.
Secret values are never returned to the wiki page: a script table only shows a masked confirmation.
Other fixtures (for example a REST fixture) pick the values up from the registry.

- Maven coordinates: `io.github.tortaje:fitnesse-hvault`, Java 17.
- `org.json` is embedded and relocated to `io.github.tortaje.hvault.shaded.json`, so it cannot clash with
  other copies on FitNesse's flat classpath.
- `fitnesse-otel` and `opentelemetry-api` are `provided`: they come from the FitNesse classpath.
- Vault prerequisites (token and Kubernetes auth, example secrets and certificates, screenshots, local
  demo): see the [Vault setup guide](docs/guide-vault.md).

## How it works

The fixture reads secrets from Vault and stores them in an in-memory registry inside FitNesse's Slim JVM;
the wiki page only gets a masked confirmation, and other fixtures read the values from the registry.

```mermaid
flowchart LR
    subgraph slim["FitNesse Slim JVM"]
        page["Wiki page"]
        fixture["HVault fixture"]
        registry[("SecretRegistry<br/>in memory")]
        rest["REST fixture"]
    end
    vault[("HashiCorp Vault<br/>KV v2")]
    k8s["Kubernetes API"]

    page -->|"read secret"| fixture
    fixture -.->|"******** [STORED SAFELY IN x]"| page
    fixture -->|"token or Kubernetes login,<br/>then GET /v1/secret/data/..."| vault
    vault -.->|"TokenReview<br/>(Kubernetes mode)"| k8s
    fixture -->|"put(variable, value)"| registry
    rest -->|"get(variable)"| registry
```

Sequence diagrams for each scenario (static token, Kubernetes login, token renewal, re-login on 403,
retries, outcome of a wiki row) are in [How it works](docs/how-it-works.md).

## Installation

Put the JARs in your FitNesse `lib` directory and add them to the page `!path`:

```
!path lib/fitnesse-otel-*-standalone.jar
!path lib/fitnesse-hvault-*.jar
!path conf
```

`conf` holds the optional `hvault.properties` (see Configuration).

## Example page

```
|import|
|io.github.tortaje.hvault|

|script|HVault|
|read secret|app/oauth|key|client_secret|into|clientSecret|
|read all secrets from|app/mtls|with prefix|mtls.|
|clear secrets|
```

| Method | Displayed result | Effect |
|---|---|---|
| `readSecretKeyInto(path, key, variable)` | `******** [STORED SAFELY IN clientSecret]` | Reads `key` from the secret at `path` and stores it as `variable` |
| `readAllSecretsFromWithPrefix(path, prefix)` | `******** [3 SECRETS STORED WITH PREFIX mtls.]` | Stores each key `k` as `prefix + k` |
| `clearSecrets()` | `true` | Empties the registry (meant for a `SuiteTearDown`) |

- `path` is relative to the KV mount: `app/oauth` reads `GET /v1/{mount}/data/app/oauth`.
- A non-text value (number, boolean, object) is stored in its JSON form.
- On failure nothing is written to the registry; `read all secrets` is all-or-nothing.

### In the FitNesse UI

A run against the example secrets of the [Vault setup guide](docs/guide-vault.md). Wrapping a row in `check`
turns the masked confirmation into an assertion:

```
|script|HVault|
|check|read secret|fitnesse/oauth|key|client_id|into|clientId|******** [STORED SAFELY IN clientId]|
|check|read secret|fitnesse/oauth|key|client_secret|into|clientSecret|******** [STORED SAFELY IN clientSecret]|
|check|read all secrets from|fitnesse/mtls|with prefix|mtls.|******** [3 SECRETS STORED WITH PREFIX mtls.]|
```

![FitNesse run: three secrets stored, values never shown](docs/images/fitnesse-read-secrets.png)

A failing row shows the reason as an exception on that row; the message names the available keys, never
their values (exception details unfolded in this screenshot):

![FitNesse run: missing key and missing secret reported on their rows](docs/images/fitnesse-error-messages.png)

## Configuration

Priority: environment variable, then system property, then `hvault.properties` (loaded from the classpath,
hence `!path conf`). A missing file is not an error.

| Environment variable | System property / file | Default | Purpose |
|---|---|---|---|
| `VAULT_ADDR` | `hvault.addr` | none (required) | Vault URL |
| `VAULT_TOKEN` | `hvault.token` (**system property only**) | none | Static token |
| `VAULT_ROLE` | `hvault.role` | none | Kubernetes auth role |
| `VAULT_NAMESPACE` | `hvault.namespace` | none | `X-Vault-Namespace` header (Vault Enterprise) |
| `VAULT_CACERT` | `hvault.cacert` | JVM truststore | Path to a CA PEM for TLS to Vault |
| `VAULT_KV_MOUNT` | `hvault.kv.mount` | `secret` | KV v2 mount |
| `VAULT_K8S_AUTH_PATH` | `hvault.k8s.auth.path` | `kubernetes` | Kubernetes auth mount |
| `VAULT_K8S_TOKEN_PATH` | `hvault.k8s.token.path` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Service account JWT |
| `VAULT_RETRY_MAX_ATTEMPTS` | `hvault.retry.max.attempts` | `3` | Total attempts |
| `VAULT_RETRY_INITIAL_DELAY_MS` | `hvault.retry.initial.delay.ms` | `1000` | First delay, doubled afterwards |
| `VAULT_CONNECT_TIMEOUT_MS` | `hvault.connect.timeout.ms` | `5000` | Connect timeout |
| `VAULT_REQUEST_TIMEOUT_MS` | `hvault.request.timeout.ms` | `10000` | Request timeout |

- `hvault.token` found in `hvault.properties` is ignored with a WARN log (no value): use `VAULT_TOKEN`.
- The configuration is resolved once, on the first fixture call, and kept for the JVM lifetime.

## Security rules

- The fixture never returns a secret value, whatever happens.
- No secret value, token, JWT or response body ever appears in a wiki result, exception message, log or span.
- The registry has no `toString()` and no way to enumerate its values.
- A static token is only accepted from `VAULT_TOKEN` or the `hvault.token` system property, never from a file.
- Secret paths and mounts with `#`, `?`, whitespace, control characters, `.`, `..` or empty segments are rejected
  before any call, so a wiki row cannot reach another Vault API.
- A plain `http://` `VAULT_ADDR` to a non-loopback host logs a WARNING: the token and secrets travel unencrypted.
- Redirects are followed (for example from an HA standby to the active node), never from HTTPS to HTTP.
- Credentials in `VAULT_ADDR` (`https://user:pass@...`) are shown as `REDACTED:REDACTED` in spans and messages.

## Observability

Telemetry goes through `fitnesse-otel` (OTLP to a Collector); the fixture only uses the OpenTelemetry API.

- **Traces**: one `CLIENT` span per HTTP attempt, `GET /v1/{mount}/data/{path}` or
  `POST /v1/auth/{mount}/login`, with HTTP, `vault.*` and `hvault.*` attributes.
- **Logs** (`java.util.logging`, correlated with the current span by `fitnesse-otel`):

| Level | Logger | Example |
|---|---|---|
| WARNING | `client.VaultHttpClient` | `Vault GET /v1/secret/data/app/oauth: attempt 1/3 failed (HTTP 503), retrying in 1000 ms` |
| WARNING | `client.VaultHttpClient` | `Vault GET /v1/secret/data/app/oauth: attempt 3/3 failed (HTTP 503), giving up` |
| INFO | `auth.TokenProvider` | `Vault auth: Kubernetes login with role 'fitnesse' (auth path kubernetes)` |
| INFO | `auth.TokenProvider` | `Kubernetes login succeeded for role 'fitnesse', Vault token valid for 3600 s` |
| INFO | `auth.TokenProvider` | `Vault token for role 'fitnesse' expires soon, logging in again` |
| INFO | `client.KvV2Reader` | `Access denied to secret/app/oauth (HTTP 403) for role 'fitnesse', logging in again` |
| INFO | `HVault` | `Stored key 'client_secret' of secret/app/oauth into 'clientSecret'` |
| WARNING | `config.VaultConfig` | `hvault.token in hvault.properties is ignored: use VAULT_TOKEN` |

  Logger names are relative to `io.github.tortaje.hvault`. Messages carry paths, key and variable names,
  never values.
- **Metrics**: none emitted by the fixture; derive call counts, errors and latencies from the spans (for
  example with the Collector `spanmetrics` connector).

## Tests

```
mvn verify              # unit tests and the packaged-JAR check (no Docker needed)
mvn verify -Pit         # also runs the *VaultIT tests against a real Vault (needs Docker)
```

`mvn verify` also writes a JaCoCo coverage report to `target/site/jacoco/index.html` (every test the build
ran, integration tests included with `-Pit`) and fails if line coverage drops below 90 % or branch coverage
below 85 %.
