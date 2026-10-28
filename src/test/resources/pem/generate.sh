#!/usr/bin/env bash
# Regenerates all test PEM files in this directory (10-year validity). Requires OpenSSL.
set -euo pipefail
cd "$(dirname "$0")"
rm -f ./*.pem ./*.key ./*.srl ./*.csr ./*.cnf
D=3650

mkca() { # name
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$1.key.tmp" -out "$1.pem" -days $D -subj "/CN=$1" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}
sign() { # keyfile certfile cn [ext]
  openssl req -new -key "$1" -subj "/CN=$3" -out tmp.csr
  printf '%s\n' "basicConstraints=CA:FALSE" "${4:-subjectAltName=DNS:localhost}" > tmp.cnf
  openssl x509 -req -in tmp.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days $D -extfile tmp.cnf -out "$2" 2>/dev/null
}

mkca ca && mv ca.key.tmp ca.key
mkca other-ca && rm other-ca.key.tmp

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out server.key
sign server.key server.pem server "subjectAltName=DNS:localhost,IP:127.0.0.1"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client-rsa-pkcs8.key
sign client-rsa-pkcs8.key client-rsa.pem client-rsa
openssl rsa -in client-rsa-pkcs8.key -traditional -out client-rsa-pkcs1.key 2>/dev/null \
  || openssl pkey -in client-rsa-pkcs8.key -traditional -out client-rsa-pkcs1.key

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out client-ec-pkcs8.key
sign client-ec-pkcs8.key client-ec.pem client-ec
openssl ec -in client-ec-pkcs8.key -out client-ec-sec1.key 2>/dev/null

openssl genpkey -algorithm ED25519 -out client-ed25519.key
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out client-rsapss.key

openssl pkcs8 -topk8 -v2 aes-256-cbc -passout pass:test -in client-rsa-pkcs8.key -out client-encrypted.key

cat client-rsa.pem ca.pem > client-chain.pem
rm -f tmp.csr tmp.cnf ca.srl
for f in *.key; do printf '%s: ' "$f"; head -1 "$f"; done
