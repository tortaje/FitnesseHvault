# How the `HVault` fixture works

Diagrams of the fixture's internals, its exchanges with Vault and Kubernetes, and what happens in each
scenario. Setup steps are in the [Vault setup guide](guide-vault.md); settings are in the
[README](../README.md#configuration).

## Contents

1. [Components](#1-components)
2. [Choosing the authentication mode](#2-choosing-the-authentication-mode)
3. [Reading a secret with a static token](#3-reading-a-secret-with-a-static-token)
4. [Kubernetes login](#4-kubernetes-login)
5. [Token renewal and re-login on 403](#5-token-renewal-and-re-login-on-403)
6. [Retries](#6-retries)
7. [Outcome of a wiki row](#7-outcome-of-a-wiki-row)

## 1. Components

The fixture runs in FitNesse's Slim JVM. Secret values only travel from Vault to the in-memory
registry; the wiki page only gets a masked confirmation.

```mermaid
flowchart LR
    subgraph slim["FitNesse Slim JVM"]
        page["Wiki page<br/>script table HVault"]
        fixture["HVault<br/>(fixture)"]
        reader["KvV2Reader<br/>KV v2 read, error mapping"]
        tokens["TokenProvider<br/>static or Kubernetes token"]
        http["VaultHttpClient<br/>retries, TLS, one span per attempt"]
        registry[("SecretRegistry<br/>in memory")]
        rest["REST fixture<br/>(other project)"]
    end
    vault[("HashiCorp Vault<br/>KV v2")]
    k8s["Kubernetes API"]
    otel["OpenTelemetry Collector"]

    page -->|"read secret / read all secrets"| fixture
    fixture -.->|"******** [STORED SAFELY IN x]"| page
    fixture --> reader
    reader --> tokens
    reader --> http
    tokens --> http
    http -->|"HTTP(S) + X-Vault-Token"| vault
    vault -.->|"TokenReview (Kubernetes mode)"| k8s
    fixture -->|"put(variable, value)"| registry
    rest -->|"get(variable), MtlsContexts"| registry
    http -.->|"spans and logs via fitnesse-otel"| otel
```

## 2. Choosing the authentication mode

The mode is decided once, on the first call that needs a token, and kept for the JVM lifetime.

```mermaid
flowchart TD
    start(["First read in the JVM"]) --> addr{"VAULT_ADDR set?"}
    addr -->|no| noaddr["Fail: Vault not configured:<br/>VAULT_ADDR missing"]
    addr -->|yes| tok{"VAULT_TOKEN set?<br/>(env or -Dhvault.token)"}
    tok -->|yes| static["Token mode<br/>the token is sent as is"]
    tok -->|no| role{"VAULT_ROLE set and<br/>JWT file readable?"}
    role -->|yes| kube["Kubernetes mode<br/>login, cache, renew"]
    role -->|no| noauth["Fail: No Vault auth available"]
```

## 3. Reading a secret with a static token

`|read secret|fitnesse/oauth|key|client_secret|into|clientSecret|`

```mermaid
sequenceDiagram
    autonumber
    participant W as Wiki page
    participant F as HVault
    participant R as KvV2Reader
    participant T as TokenProvider
    participant V as Vault
    participant S as SecretRegistry

    W->>F: read secret fitnesse/oauth, key client_secret, into clientSecret
    F->>F: normalize the path, reject '#', '?', spaces
    F->>R: read("fitnesse/oauth")
    R->>T: token()
    T-->>R: VAULT_TOKEN
    R->>V: GET /v1/secret/data/fitnesse/oauth (X-Vault-Token)
    V-->>R: 200 data.data = {client_id, client_secret}
    R-->>F: keys and values, in response order
    F->>F: key client_secret present?
    F->>S: put("clientSecret", value)
    F-->>W: ******** [STORED SAFELY IN clientSecret]
```

`|read all secrets from|fitnesse/mtls|with prefix|mtls.|` follows the same path, then stores every key
(`mtls.cert`, `mtls.key`, `mtls.ca`) only once the whole response has been read: all or nothing.

## 4. Kubernetes login

The pod's service account JWT is exchanged for a Vault token; Vault checks it with the Kubernetes API.

```mermaid
sequenceDiagram
    autonumber
    participant R as KvV2Reader
    participant T as TokenProvider
    participant P as Pod filesystem
    participant V as Vault
    participant K as Kubernetes API

    R->>T: token()
    T->>P: read the JWT (VAULT_K8S_TOKEN_PATH)
    T->>V: POST /v1/auth/kubernetes/login {role, jwt}
    V->>K: TokenReview(jwt)
    K-->>V: valid, service account fitnesse/fitnesse
    V->>V: service account bound to the role? attach its policies
    V-->>T: 200 auth.client_token, lease_duration
    T->>T: cache the token, expiry = now + lease - 30 s
    T-->>R: Vault token
    Note over R,V: Later reads reuse the cached token until it is about to expire
```

A rejected login (HTTP 400 or 403) fails the row with `Kubernetes login rejected for role '...'`.

## 5. Token renewal and re-login on 403

In Kubernetes mode the fixture keeps its token valid on its own. In token mode there is no way to get a
new token, so a 403 fails the row straight away.

```mermaid
sequenceDiagram
    autonumber
    participant R as KvV2Reader
    participant T as TokenProvider
    participant V as Vault

    Note over R,V: Scenario A: the cached token is about to expire
    R->>T: token()
    T->>T: now >= expiry
    T->>V: POST login (JWT read again)
    V-->>T: new token
    T-->>R: new token
    R->>V: GET secret
    V-->>R: 200

    Note over R,V: Scenario B: token revoked or policy changed
    R->>V: GET secret (cached token)
    V-->>R: 403
    R->>T: invalidate(), then token()
    T->>V: POST login
    V-->>T: new token
    R->>V: GET secret (new token)
    alt access granted
        V-->>R: 200
    else still denied
        V-->>R: 403
        R-->>R: fail: Access denied ... check policy for role 'fitnesse'
    end
```

At most one re-login per read: a second 403 means the policy really does not allow the path.

## 6. Retries

Every HTTP call (reads and logins) goes through the same loop. Each attempt is its own span; each failed
attempt is logged at WARNING.

```mermaid
flowchart TD
    send["Send attempt n of max<br/>(default max = 3)"] --> out{"Outcome"}
    out -->|"2xx, 400, 403, 404..."| handle["Map the response<br/>(see section 7)"]
    out -->|"429, 500, 502, 503, 504"| left{"n < max?"}
    out -->|"connection refused, timeout,<br/>unknown host"| left
    out -->|"TLS error"| tls["Fail: TLS error to Vault:<br/>check VAULT_CACERT (no retry)"]
    left -->|yes| wait["WARNING log, then wait<br/>initial delay x 2^(n-1), +0 to 20% jitter<br/>(default 1 s, then 2 s)"]
    wait --> send
    left -->|no| give["WARNING log 'giving up'<br/>Fail: Vault unreachable after n attempts"]
```

## 7. Outcome of a wiki row

What a `read secret` row shows, depending on what Vault answers. A failed row never changes the
registry.

```mermaid
flowchart TD
    row["read secret path, key, into variable"] --> path{"Path valid?"}
    path -->|"contains '#', '?', space"| bad["Fail: Invalid secret path"]
    path -->|yes| vault{"Vault response<br/>(after retries)"}
    vault -->|200| key{"Key present?"}
    key -->|yes| ok["Value stored in the registry<br/>Row shows ******** [STORED SAFELY IN variable]"]
    key -->|no| nokey["Fail: Key 'k' not found in mount/path<br/>(available keys: ...)"]
    vault -->|404| nf["Fail: Secret not found: mount/path"]
    vault -->|"403 (after one re-login in Kubernetes mode)"| denied["Fail: Access denied to mount/path (HTTP 403)"]
    vault -->|"other 4xx"| other["Fail: Vault error on mount/path (HTTP code): Vault's message"]
    vault -->|"5xx or network, retries exhausted"| down["Fail: Vault unreachable after n attempts"]
```

Failures appear as an exception on the row in FitNesse; messages name paths and keys, never values.
