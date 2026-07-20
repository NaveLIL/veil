import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  canonicalRegistryText,
  parseAndroidPublicFailureCodeConsumer,
  parseAndValidateRegistry,
  parsePublicFailureCodeConsumer,
  validateAppendOnly,
  validateConsumerSync,
  validateGitHistory,
  validateInitialHistory,
} from "../validate-public-failure-code-v1.mjs";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(testDirectory, "..", "..");
const registryRaw = readFileSync(
  resolve(repositoryRoot, "veil-proto", "public-failure-code-v1.json"),
  "utf8",
);
const historyRaw = readFileSync(
  resolve(repositoryRoot, "veil-proto", "history", "public-failure-code-v1.initial.json"),
  "utf8",
);
const consumerRaw = readFileSync(
  resolve(
    repositoryRoot,
    "veil-mobile",
    "src",
    "contracts",
    "publicFailureCodesV1.ts",
  ),
  "utf8",
);
const consumerSource = consumerRaw.replace(/\r\n/g, "\n");
const androidConsumerRaw = readFileSync(
  resolve(
    repositoryRoot,
    "veil-mobile",
    "android",
    "app",
    "src",
    "main",
    "java",
    "io",
    "veil",
    "mobile",
    "runtime",
    "PublicFailureCodeV1.kt",
  ),
  "utf8",
);
const androidConsumerSource = androidConsumerRaw.replace(/\r\n/g, "\n");

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function parseFixture(value, label = "fixture") {
  return parseAndValidateRegistry(canonicalRegistryText(value), label);
}

test("reviewed registry preserves the exact 16-code history and appends two Direct codes", () => {
  const registry = parseAndValidateRegistry(registryRaw, "registry");
  const history = parseAndValidateRegistry(historyRaw, "history");

  assert.equal(registry.version, 1);
  assert.equal(registry.codes.length, 18);
  assert.equal(history.codes.length, 16);
  assert.deepEqual(registry.codes.slice(0, history.codes.length), history.codes);
  assert.deepEqual(registry.codes.slice(history.codes.length), [
    {
      code: "VEIL-DIRECT-001",
      semantic_key: "direct_message_definitely_not_sent",
      exposure_gate: "bounded_local_or_typed_native_direct_definite_non_acceptance",
      recovery_action_key: "keep_or_edit_then_send_new_intent_only_when_ready",
      state: "active",
    },
    {
      code: "VEIL-DIRECT-002",
      semantic_key: "direct_delivery_unknown",
      exposure_gate: "typed_native_direct_delivery_unknown",
      recovery_action_key: "keep_original_and_wait_without_blind_resend",
      state: "active",
    },
  ]);
  assert.doesNotThrow(() => validateInitialHistory(history, canonicalRegistryText(history)));
  assert.doesNotThrow(() => validateAppendOnly(history, registry));
});

test("SETUP-002 keeps active or ambiguous ceremonies fail closed", () => {
  const registry = parseAndValidateRegistry(registryRaw, "registry");
  const setupUnconfirmed = registry.codes.find((entry) => entry.code === "VEIL-SETUP-002");

  assert.deepEqual(setupUnconfirmed, {
    code: "VEIL-SETUP-002",
    semantic_key: "protected_setup_state_unconfirmed",
    exposure_gate: "setup_state_not_authoritatively_confirmed",
    recovery_action_key: "preserve_phrase_until_native_settled_and_vault_verified",
    state: "active",
  });
});

test("mobile literal consumer exactly matches active registry values and order", () => {
  const registry = parseAndValidateRegistry(registryRaw);
  const consumerCodes = parsePublicFailureCodeConsumer(consumerRaw);

  assert.equal(consumerCodes.length, 18);
  assert.deepEqual(
    consumerCodes,
    registry.codes.filter((entry) => entry.state === "active").map((entry) => entry.code),
  );
  assert.doesNotThrow(() => validateConsumerSync(registry, consumerCodes));
});

test("mobile consumer parser rejects executable or malformed array members", () => {
  const executableMember = consumerRaw.replace(
    '  "VEIL-SETUP-001",',
    "  getPublicFailureCode(),",
  );
  assert.throws(
    () => parsePublicFailureCodeConsumer(executableMember),
    /must contain one double-quoted public code/,
  );

  const duplicateDeclaration = `${consumerSource}\nexport const PUBLIC_FAILURE_CODES_V1 = [];\n`;
  assert.throws(
    () => parsePublicFailureCodeConsumer(duplicateDeclaration),
    /exactly one exported PUBLIC_FAILURE_CODES_V1 declaration/,
  );
});

test("mobile consumer sync rejects missing, extra, and reordered codes", () => {
  const registry = parseAndValidateRegistry(registryRaw);

  const missingSource = consumerSource.replace('  "VEIL-LOCAL-003",\n', "");
  const missing = parsePublicFailureCodeConsumer(missingSource);
  assert.throws(
    () => validateConsumerSync(registry, missing),
    /missing active registry code\(s\): VEIL-LOCAL-003/,
  );

  const extraSource = consumerSource.replace(
    "] as const;",
    '  "VEIL-EXTRA-001",\n] as const;',
  );
  const extra = parsePublicFailureCodeConsumer(extraSource);
  assert.throws(
    () => validateConsumerSync(registry, extra),
    /extra or inactive code\(s\): VEIL-EXTRA-001/,
  );

  const reorderedSource = consumerSource
    .replace('  "VEIL-SETUP-001",\n', "")
    .replace(
      '  "VEIL-SETUP-002",\n',
      '  "VEIL-SETUP-002",\n  "VEIL-SETUP-001",\n',
    );
  const reordered = parsePublicFailureCodeConsumer(reorderedSource);
  assert.throws(
    () => validateConsumerSync(registry, reordered),
    /code order must exactly match active registry order/,
  );
});

test("mobile consumer contains active entries only", () => {
  const registry = parseAndValidateRegistry(registryRaw);
  const retiredRegistry = clone(registry);
  retiredRegistry.codes[0].state = "retired";
  const activeConsumer = parsePublicFailureCodeConsumer(
    consumerSource.replace('  "VEIL-SETUP-001",\n', ""),
  );

  assert.doesNotThrow(() => validateConsumerSync(retiredRegistry, activeConsumer));
  assert.throws(
    () => validateConsumerSync(retiredRegistry, parsePublicFailureCodeConsumer(consumerRaw)),
    /extra or inactive code\(s\): VEIL-SETUP-001/,
  );
});

test("Android literal consumer exactly matches active registry values and order", () => {
  const registry = parseAndValidateRegistry(registryRaw);
  const consumerCodes = parseAndroidPublicFailureCodeConsumer(androidConsumerRaw);

  assert.equal(consumerCodes.length, 18);
  assert.deepEqual(
    consumerCodes,
    registry.codes.filter((entry) => entry.state === "active").map((entry) => entry.code),
  );
  assert.doesNotThrow(() => validateConsumerSync(registry, consumerCodes));
});

test("Android consumer parser rejects executable entries and sync drift", () => {
  const registry = parseAndValidateRegistry(registryRaw);
  const executable = androidConsumerSource.replace(
    '  SETUP_001("VEIL-SETUP-001"),',
    '  SETUP_001(loadPublicCode()),',
  );
  assert.throws(
    () => parseAndroidPublicFailureCodeConsumer(executable),
    /must contain one literal public code entry/,
  );

  const missing = parseAndroidPublicFailureCodeConsumer(
    androidConsumerSource.replace('  LOCAL_003("VEIL-LOCAL-003"),\n', ""),
  );
  assert.throws(
    () => validateConsumerSync(registry, missing, "Android consumer"),
    /missing active registry code\(s\): VEIL-LOCAL-003/,
  );

  const reordered = parseAndroidPublicFailureCodeConsumer(
    androidConsumerSource
      .replace('  SETUP_001("VEIL-SETUP-001"),\n', "")
      .replace(
        '  SETUP_002("VEIL-SETUP-002"),\n',
        '  SETUP_002("VEIL-SETUP-002"),\n  SETUP_001("VEIL-SETUP-001"),\n',
      ),
  );
  assert.throws(
    () => validateConsumerSync(registry, reordered, "Android consumer"),
    /code order must exactly match active registry order/,
  );
});

test("schema rejects non-ASCII, duplicate, malformed, and non-canonical entries", () => {
  const registry = parseAndValidateRegistry(registryRaw);

  const futureCategoryWithDigit = clone(registry);
  futureCategoryWithDigit.codes.push({
    code: "VEIL-PHASE5-001",
    semantic_key: "future_phase5_failure",
    exposure_gate: "typed_future_phase5_failure",
    recovery_action_key: "remain_closed",
    state: "active",
  });
  assert.doesNotThrow(() => parseFixture(futureCategoryWithDigit));

  const nonAscii = clone(registry);
  nonAscii.codes[0].semantic_key = "setup_ошибка";
  assert.throws(
    () => parseFixture(nonAscii),
    /printable ASCII only/,
  );

  const duplicate = clone(registry);
  duplicate.codes[1].code = duplicate.codes[0].code;
  assert.throws(() => parseFixture(duplicate), /duplicates VEIL-SETUP-001/);

  const malformed = clone(registry);
  malformed.codes[0].code = "veil-setup-1";
  assert.throws(() => parseFixture(malformed), /must match/);

  assert.throws(
    () => parseAndValidateRegistry(JSON.stringify(registry), "compact fixture"),
    /canonical two-space JSON formatting/,
  );
});

test("reserved entries permanently use non-exposing identities", () => {
  const registry = parseAndValidateRegistry(registryRaw);
  const reserved = clone(registry);
  reserved.codes.push({
    code: "VEIL-FUTURE-001",
    semantic_key: "reserved_future_001",
    exposure_gate: "never",
    recovery_action_key: "none",
    state: "reserved",
  });
  assert.doesNotThrow(() => parseFixture(reserved));
  assert.doesNotThrow(() => validateAppendOnly(registry, reserved));

  const exposedReserved = clone(reserved);
  exposedReserved.codes.at(-1).exposure_gate = "fallback_only";
  assert.throws(() => parseFixture(exposedReserved), /reserved codes must use/);

  const activeReservedIdentity = clone(reserved);
  activeReservedIdentity.codes.at(-1).state = "active";
  assert.throws(() => parseFixture(activeReservedIdentity), /reserved-only identities/);
});

test("append-only comparison permits append and active-to-retired only", () => {
  const registry = parseAndValidateRegistry(registryRaw);
  const next = clone(registry);
  next.codes[0].state = "retired";
  next.codes.push({
    code: "VEIL-SYNC-002",
    semantic_key: "future_sync_failure",
    exposure_gate: "typed_future_sync_failure",
    recovery_action_key: "remain_closed",
    state: "active",
  });
  const parsedNext = parseFixture(next);
  assert.doesNotThrow(() => validateAppendOnly(registry, parsedNext));

  const resurrected = clone(parsedNext);
  resurrected.codes[0].state = "active";
  assert.throws(
    () => validateAppendOnly(parsedNext, parseFixture(resurrected)),
    /state cannot change/,
  );

  const newlyRetired = clone(registry);
  newlyRetired.codes.push({
    code: "VEIL-SYNC-002",
    semantic_key: "future_sync_failure",
    exposure_gate: "typed_future_sync_failure",
    recovery_action_key: "remain_closed",
    state: "retired",
  });
  assert.throws(
    () => validateAppendOnly(registry, parseFixture(newlyRetired)),
    /cannot start retired/,
  );
});

test("append-only comparison rejects deletion, reorder, and identity mutation", () => {
  const registry = parseAndValidateRegistry(registryRaw);

  const deleted = clone(registry);
  deleted.codes.pop();
  assert.throws(() => validateAppendOnly(registry, deleted), /entries were deleted/);

  const reordered = clone(registry);
  [reordered.codes[0], reordered.codes[1]] = [reordered.codes[1], reordered.codes[0]];
  assert.throws(() => validateAppendOnly(registry, reordered), /code order changed/);

  const mutated = clone(registry);
  mutated.codes[0].recovery_action_key = "different_action";
  assert.throws(
    () => validateAppendOnly(registry, mutated),
    /recovery_action_key is immutable/,
  );
});

test("initial history digest rejects edits even when JSON remains valid", () => {
  const history = parseAndValidateRegistry(historyRaw);
  const mutated = clone(history);
  mutated.codes[0].semantic_key = "different_but_well_formed_semantic";
  const parsedMutation = parseFixture(mutated);

  assert.throws(
    () => validateInitialHistory(parsedMutation, canonicalRegistryText(parsedMutation)),
    /initial history snapshot is immutable/,
  );
});

test("Git baseline comparison accepts append and rejects historical mutation", () => {
  const temporaryRepository = mkdtempSync(resolve(tmpdir(), "veil-public-failure-"));
  const registryPath = resolve(
    temporaryRepository,
    "veil-proto",
    "public-failure-code-v1.json",
  );
  const historyPath = resolve(
    temporaryRepository,
    "veil-proto",
    "history",
    "public-failure-code-v1.initial.json",
  );

  try {
    mkdirSync(resolve(temporaryRepository, "veil-proto", "history"), { recursive: true });
    writeFileSync(registryPath, registryRaw, "utf8");
    writeFileSync(historyPath, historyRaw, "utf8");
    execFileSync("git", ["init", "--quiet"], { cwd: temporaryRepository });
    execFileSync("git", ["config", "core.autocrlf", "false"], {
      cwd: temporaryRepository,
    });
    execFileSync("git", ["config", "user.name", "Veil Contract Test"], {
      cwd: temporaryRepository,
    });
    execFileSync("git", ["config", "user.email", "veil-contract-test@invalid"], {
      cwd: temporaryRepository,
    });
    execFileSync("git", ["add", "veil-proto"], { cwd: temporaryRepository });
    execFileSync("git", ["commit", "--quiet", "-m", "initial registry"], {
      cwd: temporaryRepository,
    });
    const reference = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: temporaryRepository,
      encoding: "utf8",
    }).trim();
    const registry = parseAndValidateRegistry(registryRaw);
    const history = parseAndValidateRegistry(historyRaw);
    const appended = clone(registry);
    appended.codes.push({
      code: "VEIL-SYNC-002",
      semantic_key: "future_sync_failure",
      exposure_gate: "typed_future_sync_failure",
      recovery_action_key: "remain_closed",
      state: "active",
    });

    assert.deepEqual(
      validateGitHistory({
        repositoryRoot: temporaryRepository,
        reference,
        registryPath,
        historyPath,
        registry: parseFixture(appended),
        history,
      }),
      { compared: true, bootstrap: false },
    );

    const mutated = clone(registry);
    mutated.codes[0].semantic_key = "mutated_semantic";
    assert.throws(
      () =>
        validateGitHistory({
          repositoryRoot: temporaryRepository,
          reference,
          registryPath,
          historyPath,
          registry: parseFixture(mutated),
          history,
        }),
      /semantic_key is immutable/,
    );

    const changedHistory = clone(history);
    changedHistory.codes[0].state = "retired";
    assert.throws(
      () =>
        validateGitHistory({
          repositoryRoot: temporaryRepository,
          reference,
          registryPath,
          historyPath,
          registry,
          history: parseFixture(changedHistory),
        }),
      /initial history snapshot changed/,
    );
  } finally {
    rmSync(temporaryRepository, { recursive: true, force: true });
  }
});
