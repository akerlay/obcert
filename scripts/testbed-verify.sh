#!/usr/bin/env bash
# Verify the name-constraint testbed against every certificate verifier available on this
# Mac, without installing anything into a keychain or NSS profile.
#
# Apple trustd is what Safari and Chrome use, and iOS ships the same implementation family,
# so its verdict is the closest proxy for the phone that can be obtained on a Mac.
set -euo pipefail

BED="${1:?usage: testbed-verify.sh <testbed-dir>}"
MANIFEST="$BED/manifest.json"
[ -f "$MANIFEST" ] || { echo "no manifest at $MANIFEST — run obcert-testbed first" >&2; exit 2; }

read_json() { /usr/bin/python3 -c "import json,sys;print(json.load(open(sys.argv[1]))$2)" "$MANIFEST"; }

LAN_IP="$(read_json "$MANIFEST" "['lanIP']")"
LOCAL_ROOT="$(read_json "$MANIFEST" "['localRootPEM']")"
# Certificates the profile installs without trust; the client is supposed to find these.
STORE_CERTS="$(/usr/bin/python3 -c "import json,sys;print(' '.join(json.load(open(sys.argv[1]))['storeCertPEMs']))" "$MANIFEST")"
CASE_COUNT="$(read_json "$MANIFEST" "['cases'].__len__()")"

CURRENT_IP="$(/usr/sbin/ipconfig getifaddr en0 2>/dev/null || /usr/sbin/ipconfig getifaddr en1 2>/dev/null || true)"
if [ -n "$CURRENT_IP" ] && [ "$CURRENT_IP" != "$LAN_IP" ]; then
  echo "LAN address changed ($LAN_IP -> $CURRENT_IP): regenerate the testbed, otherwise" >&2
  echo "the name-based cases would fail for the wrong reason." >&2
  exit 2
fi

UNTRUSTED="$BED/untrusted-chain.pem"
cat $STORE_CERTS > "$UNTRUSTED"

FAILURES=0
printf '%-6s %-9s %-14s %-14s %-14s\n' case expect trustd openssl nss

for i in $(seq 0 $((CASE_COUNT - 1))); do
  NAME="$(read_json "$MANIFEST" "['cases'][$i]['name']")"
  SERVER_NAME="$(read_json "$MANIFEST" "['cases'][$i]['serverName']")"
  EXPECT="$(read_json "$MANIFEST" "['cases'][$i]['expectation']")"
  CHAIN="$(read_json "$MANIFEST" "['cases'][$i]['certificateChainPEM']")"
  # The bare-IP case has no SNI; trustd/openssl still need a name to match against.
  HOST="${SERVER_NAME:-$LAN_IP}"

  LEAF="$BED/leaf-$NAME-only.pem"
  /usr/bin/awk 'BEGIN{n=0} /BEGIN CERT/{n++} n==1{print} /END CERT/{if(n==1) exit}' "$CHAIN" > "$LEAF"

  # --- Apple trustd. -L: no network fetch (also bounds the wait). -N: ignore keychains. ---
  # -v prints per-certificate reasons, so a rejection for the wrong reason (expiry, EKU)
  # cannot be mistaken for the name constraint doing its job.
  TRUSTD_OUT="$(/usr/bin/security verify-cert -L -N -v -p ssl -n "$HOST" \
      -c "$LEAF" $(for c in $STORE_CERTS; do printf -- '-c %s ' "$c"; done) \
      -r "$LOCAL_ROOT" 2>&1 || true)"
  if printf '%s' "$TRUSTD_OUT" | /usr/bin/grep -q "certificate verification successful"; then
    TRUSTD=valid
  else
    TRUSTD=invalid
  fi

  # --- OpenSSL ---
  if OPENSSL_OUT="$(openssl verify -CAfile "$LOCAL_ROOT" -untrusted "$UNTRUSTED" \
        -verify_hostname "$HOST" "$LEAF" 2>&1)"; then
    OPENSSL=valid
  else
    OPENSSL=invalid
  fi

  # --- NSS (Firefox's verifier). Needs vfychain from `brew install nss`. ---
  if command -v vfychain >/dev/null 2>&1 && command -v certutil >/dev/null 2>&1; then
    NSSDB="$BED/nssdb-$NAME"
    rm -rf "$NSSDB"; mkdir -p "$NSSDB"
    certutil -N -d "sql:$NSSDB" --empty-password >/dev/null 2>&1
    certutil -A -d "sql:$NSSDB" -n "obcert root"  -t "C,," -i "$LOCAL_ROOT" >/dev/null 2>&1
    i=0
    for c in $STORE_CERTS; do
      certutil -A -d "sql:$NSSDB" -n "store cert $i" -t ",," -i "$c" >/dev/null 2>&1
      i=$((i + 1))
    done
    if NSS_OUT="$(vfychain -d "sql:$NSSDB" -u 1 -a "$LEAF" 2>&1)" \
       && printf '%s' "$NSS_OUT" | /usr/bin/grep -qi "chain is good"; then
      NSS=valid
    else
      NSS=invalid
    fi
  else
    NSS=SKIP
    NSS_OUT="vfychain not found — brew install nss"
  fi

  printf '%-6s %-9s %-14s %-14s %-14s\n' "$NAME" "$EXPECT" "$TRUSTD" "$OPENSSL" "$NSS"

  for pair in "trustd:$TRUSTD" "openssl:$OPENSSL" "nss:$NSS"; do
    VERIFIER="${pair%%:*}"; VERDICT="${pair##*:}"
    [ "$VERDICT" = "SKIP" ] && continue
    if [ "$VERDICT" != "$EXPECT" ]; then
      echo "  FAIL $VERIFIER/$NAME: expected $EXPECT, got $VERDICT" >&2
      FAILURES=$((FAILURES + 1))
    fi
  done

  # Show why an invalid case was rejected, so a wrong reason (expiry, unknown issuer)
  # cannot be mistaken for the constraint doing its job.
  if [ "$EXPECT" = "invalid" ]; then
    TRUSTD_REASON="$(printf '%s' "$TRUSTD_OUT" | /usr/bin/sed -n 's/.*\[\([A-Za-z]*\)\].*/\1/p' \
        | /usr/bin/sort -u | /usr/bin/tr '\n' ' ')"
    echo "  trustd:  ${TRUSTD_REASON:-$(printf '%s' "$TRUSTD_OUT" | /usr/bin/head -1)}"
    echo "  openssl: $(printf '%s' "${OPENSSL_OUT:-}" | /usr/bin/grep -i -m1 'subtree\|constraint\|error' || true)"
    [ "$NSS" != "SKIP" ] && echo "  nss:     $(printf '%s' "${NSS_OUT:-}" | /usr/bin/grep -i -m1 'error\|constraint' || true)"
  fi
done

echo ""
if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES verdict(s) disagree with the matrix" >&2
  exit 1
fi
echo "all verifiers agree with the matrix"
