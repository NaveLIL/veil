#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const defaultRepositoryRoot = resolve(scriptDirectory, "..");
const defaultRegistryPath = "veil-proto/public-failure-code-v1.json";
const defaultHistoryPath = "veil-proto/history/public-failure-code-v1.initial.json";
const defaultConsumerPath = "veil-mobile/src/contracts/publicFailureCodesV1.ts";
const defaultAndroidConsumerPath =
  "veil-mobile/android/app/src/main/java/io/veil/mobile/runtime/PublicFailureCodeV1.kt";

const ROOT_FIELDS = ["version", "codes"];
const ENTRY_FIELDS = [
  "code",
  "semantic_key",
  "exposure_gate",
  "recovery_action_key",
  "state",
];
const IMMUTABLE_ENTRY_FIELDS = ENTRY_FIELDS.filter((field) => field !== "state");
const STATES = new Set(["active", "retired", "reserved"]);
const CODE_PATTERN = /^VEIL-[A-Z][A-Z0-9]*-[0-9]{3}$/;
const KEY_PATTERN = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/;
const INITIAL_CODES = [
  "VEIL-SETUP-001",
  "VEIL-SETUP-002",
  "VEIL-LOCAL-001",
  "VEIL-LOCAL-002",
  "VEIL-LOCAL-003",
  "VEIL-NODE-001",
  "VEIL-NODE-002",
  "VEIL-NODE-003",
  "VEIL-NODE-004",
  "VEIL-PASS-001",
  "VEIL-PASS-002",
  "VEIL-PASS-003",
  "VEIL-RUNTIME-001",
  "VEIL-RUNTIME-002",
  "VEIL-SYNC-001",
  "VEIL-RUNTIME-999",
];
const INITIAL_HISTORY_SHA256 =
  "e9b50d2c3a8c5387e9e3883847bdce57cbd9eaaf1213fe906c0818fefeb9a78a";

export class RegistryValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "RegistryValidationError";
  }
}

function fail(message) {
  throw new RegistryValidationError(message);
}

function assertPlainObject(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    fail(`${label} must be an object`);
  }
}

function assertExactFields(value, fields, label) {
  const actual = Object.keys(value);
  if (actual.length !== fields.length || actual.some((field, index) => field !== fields[index])) {
    fail(`${label} fields must be exactly: ${fields.join(", ")}`);
  }
}

function assertAscii(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a non-empty string`);
  }
  if (!/^[\x20-\x7e]+$/.test(value)) {
    fail(`${label} must contain printable ASCII only`);
  }
}

function normalizedText(raw, label) {
  if (raw.charCodeAt(0) === 0xfeff) {
    fail(`${label} must not contain a byte-order mark`);
  }
  if (/\r(?!\n)/.test(raw)) {
    fail(`${label} must not contain bare carriage returns`);
  }
  return raw.replace(/\r\n/g, "\n");
}

export function canonicalRegistryText(registry) {
  return `${JSON.stringify(registry, null, 2)}\n`;
}

export function parseAndValidateRegistry(raw, label = "registry") {
  const normalized = normalizedText(raw, label);
  let registry;
  try {
    registry = JSON.parse(normalized);
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }

  assertPlainObject(registry, label);
  assertExactFields(registry, ROOT_FIELDS, label);
  if (registry.version !== 1) {
    fail(`${label}.version must be the integer 1`);
  }
  if (!Array.isArray(registry.codes)) {
    fail(`${label}.codes must be an array`);
  }

  const codes = new Set();
  const semantics = new Set();
  registry.codes.forEach((entry, index) => {
    const entryLabel = `${label}.codes[${index}]`;
    assertPlainObject(entry, entryLabel);
    assertExactFields(entry, ENTRY_FIELDS, entryLabel);

    for (const field of ENTRY_FIELDS) {
      assertAscii(entry[field], `${entryLabel}.${field}`);
    }
    if (!CODE_PATTERN.test(entry.code)) {
      fail(`${entryLabel}.code must match ${CODE_PATTERN}`);
    }
    for (const field of ["semantic_key", "exposure_gate", "recovery_action_key"]) {
      if (!KEY_PATTERN.test(entry[field])) {
        fail(`${entryLabel}.${field} must be lower snake case`);
      }
    }
    if (!STATES.has(entry.state)) {
      fail(`${entryLabel}.state must be active, retired, or reserved`);
    }
    if (codes.has(entry.code)) {
      fail(`${entryLabel}.code duplicates ${entry.code}`);
    }
    if (semantics.has(entry.semantic_key)) {
      fail(`${entryLabel}.semantic_key duplicates ${entry.semantic_key}`);
    }
    codes.add(entry.code);
    semantics.add(entry.semantic_key);

    if (entry.state === "reserved") {
      if (!entry.semantic_key.startsWith("reserved_")) {
        fail(`${entryLabel}.semantic_key must start with reserved_ for a reserved code`);
      }
      if (entry.exposure_gate !== "never" || entry.recovery_action_key !== "none") {
        fail(`${entryLabel} reserved codes must use exposure_gate=never and recovery_action_key=none`);
      }
    } else if (
      entry.semantic_key.startsWith("reserved_") ||
      entry.exposure_gate === "never" ||
      entry.recovery_action_key === "none"
    ) {
      fail(`${entryLabel} active or retired codes must not use reserved-only identities`);
    }
  });

  if (canonicalRegistryText(registry) !== normalized) {
    fail(`${label} must use canonical two-space JSON formatting and end with one newline`);
  }
  return registry;
}

export function parsePublicFailureCodeConsumer(raw, label = "PublicFailureCodeV1 consumer") {
  const normalized = normalizedText(raw, label);
  const declarationAnchor = /\bexport[ \t]+const[ \t]+PUBLIC_FAILURE_CODES_V1\b/g;
  const anchors = [...normalized.matchAll(declarationAnchor)];
  if (anchors.length !== 1) {
    fail(`${label} must contain exactly one exported PUBLIC_FAILURE_CODES_V1 declaration`);
  }

  const declaration = normalized.slice(anchors[0].index).match(
    /^export[ \t]+const[ \t]+PUBLIC_FAILURE_CODES_V1[ \t]*=[ \t]*\[([\s\S]*?)\][ \t]*as[ \t]+const[ \t]*;/,
  );
  if (!declaration) {
    fail(`${label} PUBLIC_FAILURE_CODES_V1 must be a literal array followed by as const`);
  }

  const codes = [];
  for (const [index, line] of declaration[1].split("\n").entries()) {
    if (line.trim() === "") {
      continue;
    }
    const item = line.match(/^[ \t]*"(VEIL-[A-Z][A-Z0-9]*-[0-9]{3})",[ \t]*$/);
    if (!item) {
      fail(
        `${label} array line ${index + 1} must contain one double-quoted public code and a trailing comma`,
      );
    }
    codes.push(item[1]);
  }
  if (codes.length === 0) {
    fail(`${label} PUBLIC_FAILURE_CODES_V1 must not be empty`);
  }
  if (new Set(codes).size !== codes.length) {
    fail(`${label} PUBLIC_FAILURE_CODES_V1 contains a duplicate code`);
  }
  return codes;
}

export function parseAndroidPublicFailureCodeConsumer(
  raw,
  label = "Android PublicFailureCodeV1 consumer",
) {
  const normalized = normalizedText(raw, label);
  const declarationAnchor = /\binternal[ \t]+enum[ \t]+class[ \t]+PublicFailureCodeV1\b/g;
  const anchors = [...normalized.matchAll(declarationAnchor)];
  if (anchors.length !== 1) {
    fail(`${label} must contain exactly one internal PublicFailureCodeV1 enum`);
  }

  const declaration = normalized.slice(anchors[0].index).match(
    /^internal[ \t]+enum[ \t]+class[ \t]+PublicFailureCodeV1\(val[ \t]+wireValue:[ \t]+String\)[ \t]*\{\n([\s\S]*?)\n\}/,
  );
  if (!declaration) {
    fail(`${label} must be a closed literal enum with a String wireValue`);
  }

  const codes = [];
  for (const [index, line] of declaration[1].split("\n").entries()) {
    if (line.trim() === "") continue;
    const item = line.match(
      /^[ \t]*[A-Z][A-Z0-9_]*\("(VEIL-[A-Z][A-Z0-9]*-[0-9]{3})"\),[ \t]*$/,
    );
    if (!item) {
      fail(`${label} enum line ${index + 1} must contain one literal public code entry`);
    }
    codes.push(item[1]);
  }
  if (codes.length === 0) fail(`${label} PublicFailureCodeV1 enum must not be empty`);
  if (new Set(codes).size !== codes.length) {
    fail(`${label} PublicFailureCodeV1 enum contains a duplicate code`);
  }
  return codes;
}

export function validateConsumerSync(registry, consumerCodes, label = "PublicFailureCodeV1 consumer") {
  const activeCodes = registry.codes
    .filter((entry) => entry.state === "active")
    .map((entry) => entry.code);
  const missing = activeCodes.filter((code) => !consumerCodes.includes(code));
  const extra = consumerCodes.filter((code) => !activeCodes.includes(code));
  if (missing.length > 0) {
    fail(`${label} is missing active registry code(s): ${missing.join(", ")}`);
  }
  if (extra.length > 0) {
    fail(`${label} has extra or inactive code(s): ${extra.join(", ")}`);
  }
  if (
    consumerCodes.length !== activeCodes.length ||
    consumerCodes.some((code, index) => code !== activeCodes[index])
  ) {
    fail(`${label} code order must exactly match active registry order`);
  }
}

function permittedStateTransition(previous, current) {
  return previous === current || (previous === "active" && current === "retired");
}

export function validateAppendOnly(previous, current, label = "registry history") {
  if (previous.version !== current.version) {
    fail(`${label}: version changed from ${previous.version} to ${current.version}`);
  }
  if (current.codes.length < previous.codes.length) {
    fail(`${label}: entries were deleted`);
  }

  previous.codes.forEach((oldEntry, index) => {
    const newEntry = current.codes[index];
    if (newEntry.code !== oldEntry.code) {
      fail(`${label}: code order changed at index ${index}; expected ${oldEntry.code}`);
    }
    for (const field of IMMUTABLE_ENTRY_FIELDS) {
      if (newEntry[field] !== oldEntry[field]) {
        fail(`${label}: ${oldEntry.code}.${field} is immutable`);
      }
    }
    if (!permittedStateTransition(oldEntry.state, newEntry.state)) {
      fail(`${label}: ${oldEntry.code} state cannot change from ${oldEntry.state} to ${newEntry.state}`);
    }
  });

  current.codes.slice(previous.codes.length).forEach((entry) => {
    if (entry.state === "retired") {
      fail(`${label}: newly appended ${entry.code} cannot start retired`);
    }
  });
}

export function validateInitialHistory(history, canonicalText) {
  const digest = createHash("sha256").update(canonicalText, "utf8").digest("hex");
  if (digest !== INITIAL_HISTORY_SHA256) {
    fail("initial history snapshot is immutable and does not match its reviewed digest");
  }
  const actualCodes = history.codes.map((entry) => entry.code);
  if (
    actualCodes.length !== INITIAL_CODES.length ||
    actualCodes.some((code, index) => code !== INITIAL_CODES[index])
  ) {
    fail(`initial history must contain the reviewed ${INITIAL_CODES.length} codes in roadmap order`);
  }
  if (history.codes.some((entry) => entry.state !== "active")) {
    fail("all codes in the initial history snapshot must remain active in that snapshot");
  }
}

function repositoryRelativePath(repositoryRoot, absolutePath, label) {
  const path = relative(repositoryRoot, absolutePath);
  if (path === "" || path === ".." || path.startsWith(`..${sep}`)) {
    fail(`${label} must be inside the repository root for Git history validation`);
  }
  return path.split(sep).join("/");
}

function assertGitCommit(repositoryRoot, reference) {
  try {
    execFileSync("git", ["cat-file", "-e", `${reference}^{commit}`], {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    fail(`Git baseline reference is not a commit: ${reference}`);
  }
}

function assertGitAncestor(repositoryRoot, ancestor, descendant) {
  try {
    execFileSync("git", ["merge-base", "--is-ancestor", ancestor, descendant], {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    fail(`Git contract history is not linear: ${ancestor} is not an ancestor of ${descendant}`);
  }
}

function listGitContractRevisions(
  repositoryRoot,
  reference,
  registryRepositoryPath,
  historyRepositoryPath,
) {
  try {
    const output = execFileSync(
      "git",
      [
        "rev-list",
        "--reverse",
        "--topo-order",
        "--full-history",
        `${reference}..HEAD`,
        "--",
        registryRepositoryPath,
        historyRepositoryPath,
      ],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    ).trim();
    return output === "" ? [] : output.split(/\r?\n/);
  } catch {
    fail(`cannot enumerate PublicFailureCodeV1 revisions after Git baseline ${reference}`);
  }
}

function readFileAtGitRef(repositoryRoot, reference, repositoryPath) {
  try {
    return execFileSync("git", ["show", `${reference}:${repositoryPath}`], {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    const stderr = error?.stderr?.toString("utf8") ?? "";
    if (stderr.includes("does not exist in") || stderr.includes("exists on disk, but not in")) {
      return null;
    }
    fail(`cannot read ${repositoryPath} at Git baseline ${reference}`);
  }
}

export function validateGitHistory({
  repositoryRoot,
  reference,
  registryPath,
  historyPath,
  registry,
  history,
}) {
  if (!reference || /^0+$/.test(reference)) {
    return { compared: false, bootstrap: false };
  }
  if (reference.startsWith("-") || /\s/.test(reference)) {
    fail("Git baseline reference contains unsupported characters");
  }
  assertGitCommit(repositoryRoot, reference);

  const registryRepositoryPath = repositoryRelativePath(repositoryRoot, registryPath, "registry");
  const historyRepositoryPath = repositoryRelativePath(repositoryRoot, historyPath, "history");
  const previousRegistryRaw = readFileAtGitRef(
    repositoryRoot,
    reference,
    registryRepositoryPath,
  );
  const previousHistoryRaw = readFileAtGitRef(repositoryRoot, reference, historyRepositoryPath);

  if (previousHistoryRaw !== null) {
    const previousHistory = parseAndValidateRegistry(previousHistoryRaw, "Git baseline history");
    if (canonicalRegistryText(previousHistory) !== canonicalRegistryText(history)) {
      fail("initial history snapshot changed relative to the Git baseline");
    }
  }

  if (previousRegistryRaw !== null && previousHistoryRaw === null) {
    fail("Git baseline registry exists without its immutable initial history snapshot");
  }

  assertGitAncestor(repositoryRoot, reference, "HEAD");
  const revisions = listGitContractRevisions(
    repositoryRoot,
    reference,
    registryRepositoryPath,
    historyRepositoryPath,
  );
  const bootstrap = previousRegistryRaw === null;
  let previousRegistry = previousRegistryRaw === null
    ? null
    : parseAndValidateRegistry(previousRegistryRaw, "Git baseline registry");
  let previousRevision = reference;

  if (bootstrap && revisions.length === 0) {
    fail("cannot locate the first committed registry revision after the Git baseline");
  }

  for (const revision of revisions) {
    assertGitAncestor(repositoryRoot, previousRevision, revision);
    const revisionHistoryRaw = readFileAtGitRef(
      repositoryRoot,
      revision,
      historyRepositoryPath,
    );
    if (revisionHistoryRaw === null) {
      fail(`Git revision ${revision} is missing the immutable initial history snapshot`);
    }
    const revisionHistory = parseAndValidateRegistry(
      revisionHistoryRaw,
      `Git revision ${revision} history`,
    );
    if (canonicalRegistryText(revisionHistory) !== canonicalRegistryText(history)) {
      fail(`initial history snapshot changed at Git revision ${revision}`);
    }

    const revisionRegistryRaw = readFileAtGitRef(
      repositoryRoot,
      revision,
      registryRepositoryPath,
    );
    if (revisionRegistryRaw === null) {
      fail(`Git revision ${revision} deleted or omitted the registry`);
    }
    const revisionRegistry = parseAndValidateRegistry(
      revisionRegistryRaw,
      `Git revision ${revision} registry`,
    );

    if (previousRegistry === null) {
      if (canonicalRegistryText(revisionRegistry) !== canonicalRegistryText(history)) {
        fail("first registry revision must exactly match the immutable initial history snapshot");
      }
    } else {
      validateAppendOnly(
        previousRegistry,
        revisionRegistry,
        `Git revision ${previousRevision} -> ${revision}`,
      );
    }
    previousRegistry = revisionRegistry;
    previousRevision = revision;
  }

  if (previousRegistry === null) {
    fail("Git history did not produce a registry revision");
  }
  validateAppendOnly(previousRegistry, registry, `Git working tree after ${previousRevision}`);
  return { compared: true, bootstrap };
}

function usage(message) {
  if (message) {
    console.error(message);
  }
  console.error(
    "Usage: node scripts/validate-public-failure-code-v1.mjs " +
      "[--repo-root <path>] [--registry <path>] [--history <path>] " +
      "[--consumer <path>] [--android-consumer <path>] [--against-ref <git-ref>]",
  );
  process.exit(2);
}

function parseArguments(argv) {
  const options = {
    repositoryRoot: defaultRepositoryRoot,
    registry: defaultRegistryPath,
    history: defaultHistoryPath,
    consumer: defaultConsumerPath,
    androidConsumer: defaultAndroidConsumerPath,
    reference: process.env.PUBLIC_FAILURE_BASE_REF || "",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument === "--repo-root" && value) {
      options.repositoryRoot = resolve(value);
      index += 1;
    } else if (argument === "--registry" && value) {
      options.registry = value;
      index += 1;
    } else if (argument === "--history" && value) {
      options.history = value;
      index += 1;
    } else if (argument === "--consumer" && value) {
      options.consumer = value;
      index += 1;
    } else if (argument === "--android-consumer" && value) {
      options.androidConsumer = value;
      index += 1;
    } else if (argument === "--against-ref" && value) {
      options.reference = value;
      index += 1;
    } else {
      usage(`Unknown or incomplete argument: ${argument}`);
    }
  }
  options.registryPath = resolve(options.repositoryRoot, options.registry);
  options.historyPath = resolve(options.repositoryRoot, options.history);
  options.consumerPath = resolve(options.repositoryRoot, options.consumer);
  options.androidConsumerPath = resolve(options.repositoryRoot, options.androidConsumer);
  return options;
}

export function validateFiles(options) {
  const registryRaw = readFileSync(options.registryPath, "utf8");
  const historyRaw = readFileSync(options.historyPath, "utf8");
  const consumerRaw = readFileSync(options.consumerPath, "utf8");
  const androidConsumerRaw = readFileSync(options.androidConsumerPath, "utf8");
  const registry = parseAndValidateRegistry(registryRaw, "PublicFailureCodeV1 registry");
  const history = parseAndValidateRegistry(historyRaw, "PublicFailureCodeV1 initial history");
  const consumerCodes = parsePublicFailureCodeConsumer(
    consumerRaw,
    "mobile PublicFailureCodeV1 consumer",
  );
  const androidConsumerCodes = parseAndroidPublicFailureCodeConsumer(
    androidConsumerRaw,
    "Android PublicFailureCodeV1 consumer",
  );
  const historyCanonical = canonicalRegistryText(history);

  validateInitialHistory(history, historyCanonical);
  validateAppendOnly(history, registry, "immutable initial history");
  validateConsumerSync(registry, consumerCodes, "mobile PublicFailureCodeV1 consumer");
  validateConsumerSync(registry, androidConsumerCodes, "Android PublicFailureCodeV1 consumer");
  const git = validateGitHistory({
    repositoryRoot: options.repositoryRoot,
    reference: options.reference,
    registryPath: options.registryPath,
    historyPath: options.historyPath,
    registry,
    history,
  });
  return { registry, git, consumerCodes, androidConsumerCodes };
}

function main() {
  try {
    const options = parseArguments(process.argv.slice(2));
    const result = validateFiles(options);
    const historyResult = result.git.compared
      ? result.git.bootstrap
        ? "Git bootstrap checked"
        : "Git append-only history checked"
      : "Git history not requested";
    console.log(
      `PublicFailureCodeV1 OK: ${result.registry.codes.length} entries; ` +
        `${result.consumerCodes.length} TS / ${result.androidConsumerCodes.length} Android codes; ` +
        `${historyResult}.`,
    );
  } catch (error) {
    console.error(`PublicFailureCodeV1 validation failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main();
}
