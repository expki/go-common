#!/usr/bin/env bash
# Regenerates the OpenSSL oracle fixtures used by openssl_test.go.
#
# These are an INDEPENDENT corpus: OpenSSL builds the DER from its own model, so
# parsing + re-encoding them byte-exact in Go is evidence this package agrees
# with a real-world implementation, not just with its own encoder. The generated
# .der files are committed; this script only needs to run when the fixtures are
# intentionally refreshed.
#
# Usage: cd x509/testdata && ./gen_openssl_fixtures.sh
set -euo pipefail
cd "$(dirname "$0")"

KEY=openssl_key.pem
CNF=openssl.cnf

# A single EC P-256 key backs both the cert and the CSR (kept out of the test;
# only the cert/CSR DER are asserted on).
openssl ecparam -name prime256v1 -genkey -noout -out "$KEY"

# Self-signed certificate carrying the full [v3_ca] extension set.
openssl req -new -x509 -key "$KEY" -days 3650 -config "$CNF" \
    -set_serial 0x0123456789abcdef -out openssl_cert.pem
openssl x509 -in openssl_cert.pem -outform DER -out openssl_cert.der

# PKCS#10 CSR carrying the [v3_req] requested extensions.
openssl req -new -key "$KEY" -config "$CNF" -out openssl_csr.pem
openssl req -in openssl_csr.pem -outform DER -out openssl_csr.der

# The key is not needed by the tests; drop it so it is not committed.
rm -f "$KEY"

echo "Generated:"
ls -l openssl_cert.der openssl_csr.der openssl_cert.pem openssl_csr.pem
