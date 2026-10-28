#!/usr/bin/env bash
# Throwaway local demo: a dev-mode Vault + a k3s cluster, set up for both authentication modes
# of the fixture (token and Kubernetes), with example secrets.
#
#   ./demo-local.sh up     # starts and configures everything, prints the variables to export
#   ./demo-local.sh down   # removes the containers, the network and the generated files
#
# Requirements: Docker and openssl. Nothing else (vault and kubectl run inside the containers).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${HVAULT_DEMO_DIR:-/tmp/hvault-demo}"
NET=hvault-demo
VAULT_IMAGE=hashicorp/vault:1.18.3
K3S_IMAGE=rancher/k3s:v1.30.6-k3s1

vault_cli() { docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root hvault-vault vault "$@"; }
kube() { docker exec hvault-k3s kubectl "$@"; }

down() {
  docker rm -f hvault-vault hvault-k3s >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  echo "Demo removed."
}

up() {
  mkdir -p "$WORK"
  docker network create "$NET" >/dev/null
  docker run -d --name hvault-k3s --privileged --network "$NET" "$K3S_IMAGE" server --disable=traefik >/dev/null
  docker run -d --name hvault-vault --network "$NET" -p 8200:8200 --cap-add=IPC_LOCK \
    -e VAULT_DEV_ROOT_TOKEN_ID=root -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 "$VAULT_IMAGE" >/dev/null

  echo "Waiting for k3s..."
  until kube get --raw=/readyz >/dev/null 2>&1; do sleep 2; done
  until vault_cli status >/dev/null 2>&1; do sleep 1; done

  # --- Example certificates (CA + client certificate) for the mTLS scenario
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=Demo CA" \
    -keyout "$WORK/ca.key" -out "$WORK/ca.pem" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=fitnesse-client" \
    -keyout "$WORK/client.key" -out "$WORK/client.csr" 2>/dev/null
  openssl x509 -req -in "$WORK/client.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
    -days 365 -out "$WORK/client.pem" 2>/dev/null
  for f in ca.pem client.pem client.key; do docker cp "$WORK/$f" "hvault-vault:/tmp/$f"; done

  # --- Example secrets (KV v2 engine mounted at secret/ in dev mode)
  vault_cli kv put secret/fitnesse/oauth client_id=fitnesse-client client_secret=change-me-0123456789 >/dev/null
  vault_cli kv put secret/fitnesse/mtls cert=@/tmp/client.pem key=@/tmp/client.key ca=@/tmp/ca.pem >/dev/null

  # --- Read policy
  docker cp "$HERE/fitnesse-read.hcl" hvault-vault:/tmp/fitnesse-read.hcl
  vault_cli policy write fitnesse-read /tmp/fitnesse-read.hcl >/dev/null

  # --- Token mode: a periodic token bound to the policy
  vault_cli token create -policy=fitnesse-read -period=24h -display-name=fitnesse-ci -field=token > "$WORK/vault-token"

  # --- Kubernetes mode: service accounts, then Vault configuration
  for f in k8s-fitnesse.yaml k8s-vault-reviewer.yaml; do
    docker cp "$HERE/$f" "hvault-k3s:/tmp/$f"
    kube apply -f "/tmp/$f" >/dev/null
  done
  K3S_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" hvault-k3s)
  REVIEWER_JWT=$(kube create token vault-reviewer -n kube-system --duration=24h)
  docker exec hvault-k3s cat /var/lib/rancher/k3s/server/tls/server-ca.crt > "$WORK/k8s-ca.crt"
  docker cp "$WORK/k8s-ca.crt" hvault-vault:/tmp/k8s-ca.crt
  vault_cli auth enable kubernetes >/dev/null
  vault_cli write auth/kubernetes/config \
    kubernetes_host="https://$K3S_IP:6443" \
    kubernetes_ca_cert=@/tmp/k8s-ca.crt \
    token_reviewer_jwt="$REVIEWER_JWT" \
    disable_local_ca_jwt=true >/dev/null
  vault_cli write auth/kubernetes/role/fitnesse \
    bound_service_account_names=fitnesse \
    bound_service_account_namespaces=fitnesse \
    token_policies=fitnesse-read \
    token_ttl=1h >/dev/null
  # Token of the "fitnesse" service account: in a real pod it is mounted automatically.
  kube create token fitnesse -n fitnesse --duration=1h > "$WORK/sa-token"

  cat <<EOF

Demo ready. UI: http://127.0.0.1:8200/ui  (Token method, token "root")

Token mode:
  export VAULT_ADDR=http://127.0.0.1:8200
  export VAULT_TOKEN=\$(cat $WORK/vault-token)

Kubernetes mode (service account token valid for 1 hour):
  unset VAULT_TOKEN
  export VAULT_ADDR=http://127.0.0.1:8200
  export VAULT_ROLE=fitnesse
  export VAULT_K8S_TOKEN_PATH=$WORK/sa-token
EOF
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
