# Read-only access to the secrets used by the FitNesse tests (KV v2 mounted at "secret/").
# With KV v2, data lives under secret/data/...: that is the path the fixture reads.
path "secret/data/fitnesse/*" {
  capabilities = ["read"]
}
