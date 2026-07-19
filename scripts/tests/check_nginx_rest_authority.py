#!/usr/bin/env python3
"""Regression gate for the managed Node's REST-v1 authority bridge."""

from pathlib import Path
import shlex
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = REPO_ROOT / "deploy" / "nginx" / "veil.erez.pro.conf"

REQUIRED_ACTIVE_SNIPPETS = {
    "fail-closed TLS default vhost": """server {
    listen 127.0.0.1:4443 ssl http2 proxy_protocol default_server;
    server_name _;

    ssl_reject_handshake on;
    return 421;
}""",
    "canonical public Host guard": """if ($host != veil.erez.pro) {
        return 421;
    }""",
    "REST-v1 authority allowlist": """map $http_host $veil_rest_v1_authority {
    default             '';
    'veil.erez.pro'     'veil.erez.pro';
    'veil.erez.pro:443' 'veil.erez.pro:443';
}""",
    "rejected unknown REST-v1 authority": """if ($veil_rest_v1_authority = '') {
        return 421;
    }""",
}

EXPECTED_PROXY_HEADERS = {
    "host": "proxy_set_header Host $veil_rest_v1_authority",
    "x-forwarded-host": (
        "proxy_set_header X-Forwarded-Host $veil_rest_v1_authority"
    ),
}


def strip_nginx_comments(text: str) -> str:
    """Remove active Nginx comments without treating quoted # as a comment."""

    result: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0

    while index < len(text):
        char = text[index]

        if escaped:
            result.append(char)
            escaped = False
        elif char == "\\":
            result.append(char)
            escaped = True
        elif quote is not None:
            result.append(char)
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            result.append(char)
            quote = char
        elif char == "#":
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        else:
            result.append(char)

        index += 1

    return "".join(result)


def active_directives(text: str) -> list[str]:
    """Split active Nginx directives at unquoted semicolons."""

    directives: list[str] = []
    buffer: list[str] = []
    quote: str | None = None
    escaped = False
    variable_braces = 0

    for char in strip_nginx_comments(text):
        if escaped:
            buffer.append(char)
            escaped = False
            continue

        if char == "\\":
            buffer.append(char)
            escaped = True
            continue

        if quote is not None:
            buffer.append(char)
            if char == quote:
                quote = None
            continue

        if char in ("'", '"'):
            buffer.append(char)
            quote = char
            continue

        if char == "{" and buffer and buffer[-1] == "$":
            variable_braces += 1
            buffer.append(char)
            continue

        if char == "}" and variable_braces:
            variable_braces -= 1
            buffer.append(char)
            continue

        if variable_braces:
            buffer.append(char)
            continue

        if char == ";":
            directive = "".join(buffer).strip()
            if directive:
                directives.append(directive)
            buffer.clear()
            continue

        if char in "{}":
            buffer.clear()
            continue

        buffer.append(char)

    return directives


def normalize_directive(directive: str) -> str:
    return " ".join(directive.split())


def validate_config(text: str) -> list[str]:
    """Return every authority-bridge policy violation in ``text``."""

    errors: list[str] = []
    active_text = strip_nginx_comments(text)

    for name, snippet in REQUIRED_ACTIVE_SNIPPETS.items():
        if active_text.count(snippet) != 1:
            errors.append(f"expected exactly one active {name}")

    observed = {name: [] for name in EXPECTED_PROXY_HEADERS}
    for directive in active_directives(text):
        try:
            fields = shlex.split(directive, comments=False, posix=True)
        except ValueError as error:
            if "proxy_set_header" in directive.casefold():
                errors.append(f"could not parse proxy_set_header directive: {error}")
            continue

        if not fields or fields[0].casefold() != "proxy_set_header":
            continue
        if len(fields) < 2:
            errors.append("proxy_set_header directive is missing its header name")
            continue

        header_name = fields[1].casefold()
        if header_name in observed:
            observed[header_name].append(normalize_directive(directive))

    for header_name, expected in EXPECTED_PROXY_HEADERS.items():
        directives = observed[header_name]
        if directives != [expected]:
            rendered = ", ".join(repr(item) for item in directives) or "none"
            errors.append(
                f"expected exactly one active {expected!r}; found {rendered}"
            )

    return errors


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise AssertionError(f"mutation fixture is no longer unique: {old!r}")
    return text.replace(old, new, 1)


def run_mutation_self_tests(good_text: str) -> None:
    safe_host = "proxy_set_header Host $veil_rest_v1_authority;"
    safe_forwarded_host = (
        "proxy_set_header X-Forwarded-Host $veil_rest_v1_authority;"
    )
    allowed_explicit_port = "    'veil.erez.pro:443' 'veil.erez.pro:443';"
    authority_guard = """if ($veil_rest_v1_authority = '') {
        return 421;
    }"""

    mutations = {
        "dynamic Host override": replace_once(
            good_text,
            safe_host,
            f"{safe_host}\n        proxy_set_header Host $arg_host;",
        ),
        "multiline braced Host override": replace_once(
            good_text,
            safe_host,
            f"{safe_host}\n        proxy_set_header\n            Host ${{arg_host}};",
        ),
        "dynamic forwarded Host override": replace_once(
            good_text,
            safe_forwarded_host,
            (
                f"{safe_forwarded_host}\n"
                "        proxy_set_header X-Forwarded-Host $server_name;"
            ),
        ),
        "unsafe replacement": replace_once(
            good_text,
            safe_host,
            "proxy_set_header Host $http_host;",
        ),
        "duplicate mapped Host": replace_once(
            good_text,
            safe_host,
            f"{safe_host}\n        {safe_host}",
        ),
        "commented-out mapped Host": replace_once(
            good_text,
            safe_host,
            f"# {safe_host}",
        ),
        "broadened authority map": replace_once(
            good_text,
            allowed_explicit_port,
            (
                f"{allowed_explicit_port}\n"
                "    'attacker.example'   'attacker.example';"
            ),
        ),
        "removed unknown-authority guard": replace_once(
            good_text,
            authority_guard,
            "",
        ),
    }

    for name, mutated_text in mutations.items():
        if not validate_config(mutated_text):
            raise AssertionError(f"dangerous mutation passed the gate: {name}")

    comments_are_inert = (
        f"{good_text}\n# proxy_set_header Host $arg_host;\n"
        "# proxy_set_header X-Forwarded-Host $http_host;\n"
    )
    comment_errors = validate_config(comments_are_inert)
    if comment_errors:
        raise AssertionError(
            "comment-only directives changed the active policy: "
            + "; ".join(comment_errors)
        )


def fail(messages: list[str]) -> None:
    for message in messages:
        print(f"nginx REST authority check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    text = CONFIG.read_text(encoding="utf-8")
    errors = validate_config(text)
    if errors:
        fail(errors)

    try:
        run_mutation_self_tests(text)
    except AssertionError as error:
        fail([f"mutation self-test failed: {error}"])

    print(
        "managed nginx REST-v1 authority allowlist is fail-closed; "
        "mutation self-tests passed"
    )


if __name__ == "__main__":
    main()
