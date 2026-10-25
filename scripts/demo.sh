#!/bin/sh
# Offline end-to-end demo against the bundled fixture topologies.
# Usage: scripts/demo.sh path/to/netreach
set -eu
BIN="${1:-bin/netreach}"
T=testdata/topologies

section() { printf '\n==== %s ====\n\n' "$1"; }

section "1. Validate and lint every fixture snapshot"
for f in "$T"/*/snapshot.json; do "$BIN" validate -s "$f"; done

section "2. Hand-derived ground truth: engine and reference simulator vs expected.json"
"$BIN" verify -dir "$T"

section "3. Internet exposure of the three-tier shop (Markdown report)"
"$BIN" analyze -s "$T/public-web/snapshot.json"

section "4. Why is SSH from 198.51.100.20 blocked on the VPN gateway?"
"$BIN" why -s "$T/nacl-ordering/snapshot.json" -from 198.51.100.20 -to eni-vpn -proto tcp -port 22 -sport 40000

section "5. Why can't the private worker reach HTTPS through the NAT gateway?"
"$BIN" why -s "$T/nat-egress/snapshot.json" -from eni-worker -to 8.8.8.8 -proto tcp -port 443 -sport 40000

section "6. Internal reachability from client-a across VPC peerings (JSON, summarised)"
"$BIN" analyze -s "$T/peering/snapshot.json" -from eni-a -format json | grep -E '"(eni|reachable|tcp)"'

section "7. CI gate: fail when anything high-severity faces the internet"
if "$BIN" analyze -s "$T/nacl-ordering/snapshot.json" -fail-on high > /dev/null; then
  echo "unexpected: no high finding"; exit 1
else
  echo "exit code $? (3 = findings at or above the threshold), as intended"
fi
