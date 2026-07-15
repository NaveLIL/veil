#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
helper="$repository_root/scripts/prepare-release-ssh.sh"
temporary_root="$(mktemp -d)"
trap 'rm -rf -- "$temporary_root"' EXIT

fail() {
  printf 'prepare-release-ssh test: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  local label="$1"
  shift
  if "$@" > /dev/null 2>&1; then
    fail "$label unexpectedly succeeded"
  fi
}

ssh-keygen -q -t ed25519 -N '' -f "$temporary_root/client"
ssh-keygen -q -t ed25519 -N '' -f "$temporary_root/server"
read -r server_key_type server_key_data _ < "$temporary_root/server.pub"
known_hosts="veil.erez.pro $server_key_type $server_key_data"
private_key="$(< "$temporary_root/client")"

valid_output="$temporary_root/valid"
VPS_HOST="veil.erez.pro" \
VPS_USER="veil-deploy" \
VPS_SSH_PRIVATE_KEY="$private_key" \
VPS_SSH_KNOWN_HOSTS="$known_hosts" \
VPS_SSH_PORT="22" \
  bash "$helper" "$valid_output" > /dev/null
ssh-keygen -y -P '' -f "$valid_output/id" > /dev/null
ssh -G -F "$valid_output/config" veil-release 2> /dev/null \
  | grep -Fx 'hostname veil.erez.pro' > /dev/null
ssh -G -F "$valid_output/config" veil-release 2> /dev/null \
  | grep -Fx 'stricthostkeychecking true' > /dev/null

bom=$'\xEF\xBB\xBF'
private_key_crlf="${bom}$(sed 's/$/\r/' "$temporary_root/client")"$'\n'
known_hosts_crlf="${bom}veil.erez.pro $server_key_type $server_key_data"$'\r\n'
normalized_output="$temporary_root/normalized"
VPS_HOST="${bom}veil.erez.pro"$'\r\n' \
VPS_USER="${bom}veil-deploy"$'\r\n' \
VPS_SSH_PRIVATE_KEY="$private_key_crlf" \
VPS_SSH_KNOWN_HOSTS="$known_hosts_crlf" \
VPS_SSH_PORT="${bom}22"$'\r\n' \
  bash "$helper" "$normalized_output" > /dev/null
if LC_ALL=C grep -q $'\r' "$normalized_output/id" "$normalized_output/known_hosts" "$normalized_output/config"; then
  fail "normalized files still contain a carriage return"
fi
if [[ "$(LC_ALL=C head -c 3 "$normalized_output/id")" == "$bom" ]] \
  || [[ "$(LC_ALL=C head -c 3 "$normalized_output/known_hosts")" == "$bom" ]]; then
  fail "normalized files still contain a UTF-8 BOM"
fi
ssh-keygen -y -P '' -f "$normalized_output/id" > /dev/null

custom_port_output="$temporary_root/custom-port"
VPS_HOST="veil.erez.pro" \
VPS_USER="veil-deploy" \
VPS_SSH_PRIVATE_KEY="$private_key" \
VPS_SSH_KNOWN_HOSTS="[veil.erez.pro]:2222 $server_key_type $server_key_data" \
VPS_SSH_PORT="2222" \
  bash "$helper" "$custom_port_output" > /dev/null
ssh -G -F "$custom_port_output/config" veil-release 2> /dev/null \
  | grep -Fx 'port 2222' > /dev/null

expect_failure "missing host" \
  env VPS_HOST= VPS_USER=veil-deploy VPS_SSH_PRIVATE_KEY="$private_key" \
    VPS_SSH_KNOWN_HOSTS="$known_hosts" VPS_SSH_PORT=22 \
    bash "$helper" "$temporary_root/missing-host"
expect_failure "embedded host newline" \
  env VPS_HOST=$'veil.erez.pro\nother.example' VPS_USER=veil-deploy \
    VPS_SSH_PRIVATE_KEY="$private_key" VPS_SSH_KNOWN_HOSTS="$known_hosts" VPS_SSH_PORT=22 \
    bash "$helper" "$temporary_root/host-newline"
expect_failure "bare key carriage return" \
  env VPS_HOST=veil.erez.pro VPS_USER=veil-deploy \
    VPS_SSH_PRIVATE_KEY="${private_key}"$'\r' VPS_SSH_KNOWN_HOSTS="$known_hosts" VPS_SSH_PORT=22 \
    bash "$helper" "$temporary_root/bare-cr"
expect_failure "malformed private key" \
  env VPS_HOST=veil.erez.pro VPS_USER=veil-deploy \
    VPS_SSH_PRIVATE_KEY='not a private key' VPS_SSH_KNOWN_HOSTS="$known_hosts" VPS_SSH_PORT=22 \
    bash "$helper" "$temporary_root/bad-key"
expect_failure "known host mismatch" \
  env VPS_HOST=other.example VPS_USER=veil-deploy \
    VPS_SSH_PRIVATE_KEY="$private_key" VPS_SSH_KNOWN_HOSTS="$known_hosts" VPS_SSH_PORT=22 \
    bash "$helper" "$temporary_root/host-mismatch"
expect_failure "malformed known_hosts line" \
  env VPS_HOST=veil.erez.pro VPS_USER=veil-deploy \
    VPS_SSH_PRIVATE_KEY="$private_key" VPS_SSH_KNOWN_HOSTS="${known_hosts}"$'\nmalformed' VPS_SSH_PORT=22 \
    bash "$helper" "$temporary_root/bad-known-hosts"
expect_failure "invalid port" \
  env VPS_HOST=veil.erez.pro VPS_USER=veil-deploy \
    VPS_SSH_PRIVATE_KEY="$private_key" VPS_SSH_KNOWN_HOSTS="$known_hosts" VPS_SSH_PORT=70000 \
    bash "$helper" "$temporary_root/bad-port"

printf 'prepare-release-ssh tests passed.\n'
