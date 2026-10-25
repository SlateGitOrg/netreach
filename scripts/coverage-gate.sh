#!/bin/sh
# Usage: coverage-gate.sh PROFILE MIN_PERCENT
# Prints total statement coverage of the profile and fails below MIN_PERCENT.
set -eu
profile="$1"
min="$2"
total="$(go tool cover -func="$profile" | awk '/^total:/ {gsub("%", "", $3); print $3}')"
awk -v t="$total" -v m="$min" 'BEGIN {
  if (t + 0 < m + 0) { printf "coverage %.1f%% of core statements is below the %s%% gate\n", t, m; exit 1 }
  printf "coverage %.1f%% of core statements (gate %s%%)\n", t, m
}'
