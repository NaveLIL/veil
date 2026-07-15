#!/usr/bin/env bash

set -euo pipefail

readonly SSH_ALIAS="veil-release"
readonly UTF8_BOM=$'\xEF\xBB\xBF'

fail() {
  printf 'prepare-release-ssh: %s\n' "$*" >&2
  exit 1
}

normalize_line_endings() {
  local label="$1"
  local normalized_value="$2"
  local destination_variable="$3"

  if [[ "$normalized_value" == "$UTF8_BOM"* ]]; then
    normalized_value="${normalized_value#"$UTF8_BOM"}"
  fi
  if [[ "$normalized_value" == *"$UTF8_BOM"* ]]; then
    fail "$label contains an unexpected UTF-8 BOM"
  fi

  normalized_value="${normalized_value//$'\r\n'/$'\n'}"
  if [[ "$normalized_value" == *$'\r'* ]]; then
    fail "$label contains a bare carriage return"
  fi

  printf -v "$destination_variable" '%s' "$normalized_value"
}

normalize_scalar() {
  local label="$1"
  local value="$2"
  local destination_variable="$3"

  normalize_line_endings "$label" "$value" value
  if [[ "$value" == *$'\n' ]]; then
    value="${value%$'\n'}"
  fi
  if [[ -z "$value" || "$value" == *$'\n'* ]]; then
    fail "$label must contain exactly one non-empty line"
  fi

  printf -v "$destination_variable" '%s' "$value"
}

validate_hostname() {
  local hostname="$1"
  local label
  local -a labels

  if (( ${#hostname} > 253 )); then
    fail "VPS_HOST is longer than 253 characters"
  fi
  if [[ "$hostname" == *..* || "$hostname" == .* || "$hostname" == *. ]]; then
    fail "VPS_HOST is not a valid DNS name or IPv4 address"
  fi

  local IFS='.'
  read -r -a labels <<< "$hostname"
  for label in "${labels[@]}"; do
    if (( ${#label} == 0 || ${#label} > 63 )) \
      || [[ ! "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]; then
      fail "VPS_HOST is not a valid DNS name or IPv4 address"
    fi
  done
}

validate_known_hosts() {
  local known_hosts_file="$1"
  local validation_key_file="$2"
  local line host_field key_type key_data remainder
  local line_number=0
  local entry_count=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    if [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]]; then
      continue
    fi

    host_field=""
    key_type=""
    key_data=""
    remainder=""
    read -r host_field key_type key_data remainder <<< "$line"
    if [[ -z "$host_field" || -z "$key_type" || -z "$key_data" || "$host_field" == @* ]]; then
      fail "VPS_SSH_KNOWN_HOSTS has an unsupported entry on line $line_number"
    fi

    printf '%s %s\n' "$key_type" "$key_data" > "$validation_key_file"
    if ! ssh-keygen -l -f "$validation_key_file" > /dev/null 2>&1; then
      fail "VPS_SSH_KNOWN_HOSTS has an invalid public key on line $line_number"
    fi
    entry_count=$((entry_count + 1))
  done < "$known_hosts_file"

  rm -f -- "$validation_key_file"
  if (( entry_count == 0 )); then
    fail "VPS_SSH_KNOWN_HOSTS contains no host keys"
  fi
}

if [[ $# -ne 1 || -z "$1" ]]; then
  fail "usage: $0 OUTPUT_DIRECTORY"
fi

for command_name in ssh ssh-keygen; do
  command -v "$command_name" > /dev/null 2>&1 \
    || fail "$command_name is required"
done

host_raw="${VPS_HOST-}"
user_raw="${VPS_USER-}"
private_key_raw="${VPS_SSH_PRIVATE_KEY-}"
known_hosts_raw="${VPS_SSH_KNOWN_HOSTS-}"
port_raw="${VPS_SSH_PORT:-22}"

normalize_scalar "VPS_HOST" "$host_raw" host
normalize_scalar "VPS_USER" "$user_raw" user
normalize_scalar "VPS_SSH_PORT" "$port_raw" port
normalize_line_endings "VPS_SSH_PRIVATE_KEY" "$private_key_raw" private_key
normalize_line_endings "VPS_SSH_KNOWN_HOSTS" "$known_hosts_raw" known_hosts

validate_hostname "$host"
if [[ ! "$user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]]; then
  fail "VPS_USER contains unsupported characters"
fi
if [[ ! "$port" =~ ^[0-9]+$ ]] || (( ${#port} > 5 )) \
  || (( 10#$port < 1 || 10#$port > 65535 )); then
  fail "VPS_SSH_PORT must be an integer from 1 to 65535"
fi
if [[ -z "$private_key" ]]; then
  fail "VPS_SSH_PRIVATE_KEY is empty"
fi
if [[ -z "$known_hosts" ]]; then
  fail "VPS_SSH_KNOWN_HOSTS is empty"
fi

output_directory="$1"
if [[ "$output_directory" == *$'\n'* || "$output_directory" == *$'\r'* ]]; then
  fail "OUTPUT_DIRECTORY contains a line break"
fi

umask 077
mkdir -p -- "$output_directory"
chmod 700 -- "$output_directory"

key_file="$output_directory/id"
known_hosts_file="$output_directory/known_hosts"
config_file="$output_directory/config"
validation_key_file="$output_directory/.known-host-key"
for output_file in "$key_file" "$known_hosts_file" "$config_file" "$validation_key_file"; do
  if [[ -e "$output_file" || -L "$output_file" ]]; then
    fail "refusing to overwrite $output_file"
  fi
done

printf '%s\n' "${private_key%$'\n'}" > "$key_file"
printf '%s\n' "${known_hosts%$'\n'}" > "$known_hosts_file"
chmod 600 -- "$key_file" "$known_hosts_file"

if ! ssh-keygen -y -P '' -f "$key_file" > /dev/null 2>&1; then
  fail "VPS_SSH_PRIVATE_KEY is not a valid unencrypted OpenSSH private key"
fi
validate_known_hosts "$known_hosts_file" "$validation_key_file"

known_host_lookup="$host"
if [[ "$port" != "22" ]]; then
  known_host_lookup="[$host]:$port"
fi
if ! ssh-keygen -F "$known_host_lookup" -f "$known_hosts_file" > /dev/null 2>&1; then
  fail "VPS_SSH_KNOWN_HOSTS has no key for $known_host_lookup"
fi

cat > "$config_file" <<EOF
Host $SSH_ALIAS
    HostName $host
    User $user
    Port $port
    IdentityFile "$key_file"
    IdentitiesOnly yes
    IdentityAgent none
    UserKnownHostsFile "$known_hosts_file"
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking yes
    UpdateHostKeys no
    VerifyHostKeyDNS no
    CheckHostIP no
    BatchMode yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PreferredAuthentications publickey
    ForwardAgent no
    ForwardX11 no
    ClearAllForwardings yes
    PermitLocalCommand no
    ProxyCommand none
    ProxyJump none
    RequestTTY no
    CanonicalizeHostname no
    ConnectTimeout 20
    ConnectionAttempts 2
    ServerAliveInterval 15
    ServerAliveCountMax 2
EOF
chmod 600 -- "$config_file"

if ! ssh -G -F "$config_file" "$SSH_ALIAS" > /dev/null 2>&1; then
  fail "generated OpenSSH configuration is invalid"
fi

printf 'Prepared pinned SSH configuration for %s on port %s.\n' "$host" "$port"
