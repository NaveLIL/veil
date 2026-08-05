import { NativeModules, Platform } from "react-native";

export type NativeIdentitySetupMode = "create" | "restore";
export type NativeIdentitySetupResult = "committed" | "user_cancelled" | "interrupted";
export type NativeIdentitySetupStartFailureKind = "unavailable" | "ambiguous";
export type NativeIdentitySetupDurableStatus =
  | "in_progress"
  | NativeIdentitySetupResult;
export type NativeIdentitySetupReconciliationStatus =
  | "none"
  | "unconfirmed"
  | NativeIdentitySetupDurableStatus;
export type NativeIdentitySetupReconciliationResult =
  | { readonly status: "none" }
  | { readonly status: "unconfirmed" }
  | {
      readonly status: NativeIdentitySetupDurableStatus;
      readonly attemptId: string;
      readonly processIncarnationId: string;
      readonly mode: NativeIdentitySetupMode;
    };

interface VeilIdentitySetupNative {
  beginNativeIdentitySetup(
    mode: NativeIdentitySetupMode,
  ): Promise<unknown>;
  reconcileNativeIdentitySetup?(): Promise<unknown>;
}

const PUBLIC_SETUP_ERROR =
  "Secure identity setup is unavailable. Close Veil and try again.";
const CANONICAL_LOWERCASE_UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const STATUS_RESULT_KEYS = ["status"] as const;
const ATTEMPT_RESULT_KEYS = [
  "status",
  "attemptId",
  "processIncarnationId",
  "mode",
] as const;

/**
 * Sanitized start failure. `unavailable` is reserved for native failures that
 * happen before a ceremony can be shown (or after a failed launch releases its
 * lease). Busy and unknown native failures are ambiguous because another
 * ceremony or lease may still exist.
 */
export class NativeIdentitySetupStartError extends Error {
  readonly kind: NativeIdentitySetupStartFailureKind;

  constructor(kind: NativeIdentitySetupStartFailureKind) {
    super(PUBLIC_SETUP_ERROR);
    this.name = "NativeIdentitySetupStartError";
    this.kind = kind;
  }
}

export function isNativeIdentitySetupStartError(
  error: unknown,
): error is NativeIdentitySetupStartError {
  return error instanceof NativeIdentitySetupStartError;
}

/**
 * Opens the protected platform-owned identity flow.
 *
 * No recovery material or identity key crosses this boundary. JavaScript
 * receives only whether native storage reported a commit, the user explicitly
 * cancelled, or the Activity result was interrupted/ambiguous. Callers must
 * strictly verify durable vault presence after both commit and interruption.
 */
export async function beginNativeIdentitySetup(
  mode: NativeIdentitySetupMode,
): Promise<NativeIdentitySetupResult> {
  if (Platform.OS === "web") throw new NativeIdentitySetupStartError("unavailable");

  let native: VeilIdentitySetupNative | undefined;
  let begin: VeilIdentitySetupNative["beginNativeIdentitySetup"] | undefined;
  try {
    native = NativeModules.VeilIdentitySetup as
      | VeilIdentitySetupNative
      | undefined;
    begin = native?.beginNativeIdentitySetup;
  } catch {
    // A hostile/malformed native module proxy cannot prove that setup never
    // started. Collapse lookup and method-access failures to the ambiguous
    // public class without allowing native diagnostic text to escape.
    throw new NativeIdentitySetupStartError("ambiguous");
  }
  if (!native || typeof begin !== "function") {
    throw new NativeIdentitySetupStartError("unavailable");
  }

  try {
    const result = await Reflect.apply(begin, native, [mode]);
    if (
      result === "committed" ||
      result === "user_cancelled" ||
      result === "interrupted"
    ) {
      return result;
    }
    // An unknown native payload must never be interpreted as either a commit or
    // a rollback. The interruption path requires a strict durable-vault check.
    return "interrupted";
  } catch (error) {
    // Native diagnostics can contain implementation details. The public UI
    // receives only a closed start classification. Busy and unknown failures
    // cannot prove that no ceremony/lease exists and therefore fail closed.
    throw new NativeIdentitySetupStartError(classifyStartFailure(error));
  }
}

/**
 * Reconciles the closed durable setup classification after startup or an
 * interrupted Activity result. Native payloads are copied only after an exact
 * shape check. An unavailable bridge, rejection, or malformed value is always
 * reduced to the same public `unconfirmed` result.
 */
export async function reconcileNativeIdentitySetup(): Promise<NativeIdentitySetupReconciliationResult> {
  if (Platform.OS === "web") return { status: "unconfirmed" };

  try {
    const native = NativeModules.VeilIdentitySetup as
      | VeilIdentitySetupNative
      | undefined;
    if (!native || typeof native.reconcileNativeIdentitySetup !== "function") {
      return { status: "unconfirmed" };
    }

    return parseNativeIdentitySetupReconciliation(
      await native.reconcileNativeIdentitySetup(),
    );
  } catch {
    return { status: "unconfirmed" };
  }
}

function parseNativeIdentitySetupReconciliation(
  value: unknown,
): NativeIdentitySetupReconciliationResult {
  if (!isPlainRecord(value)) return { status: "unconfirmed" };

  const statusFields = readExactOwnDataFields(value, STATUS_RESULT_KEYS);
  if (statusFields) {
    const status = statusFields.status;
    return status === "none" || status === "unconfirmed"
      ? { status }
      : { status: "unconfirmed" };
  }

  const attemptFields = readExactOwnDataFields(value, ATTEMPT_RESULT_KEYS);
  if (!attemptFields) return { status: "unconfirmed" };
  const { status, attemptId, processIncarnationId, mode } = attemptFields;
  if (
    !isDurableStatus(status) ||
    typeof attemptId !== "string" ||
    !CANONICAL_LOWERCASE_UUID_V4.test(attemptId) ||
    typeof processIncarnationId !== "string" ||
    !CANONICAL_LOWERCASE_UUID_V4.test(processIncarnationId) ||
    attemptId === processIncarnationId ||
    (mode !== "create" && mode !== "restore")
  ) {
    return { status: "unconfirmed" };
  }

  return {
    status,
    attemptId,
    processIncarnationId,
    mode,
  };
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function readExactOwnDataFields(
  value: Record<string, unknown>,
  expected: readonly string[],
): Record<string, unknown> | null {
  const actual = Reflect.ownKeys(value);
  if (
    actual.length !== expected.length ||
    !actual.every((key) => typeof key === "string" && expected.includes(key))
  ) return null;

  const fields: Record<string, unknown> = {};
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      return null;
    }
    fields[key] = descriptor.value;
  }
  return fields;
}

function isDurableStatus(value: unknown): value is NativeIdentitySetupDurableStatus {
  return (
    value === "in_progress" ||
    value === "committed" ||
    value === "user_cancelled" ||
    value === "interrupted"
  );
}

function classifyStartFailure(error: unknown): NativeIdentitySetupStartFailureKind {
  if (
    !error ||
    (typeof error !== "object" && typeof error !== "function")
  ) return "ambiguous";

  let code: unknown;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(error, "code");
    if (
      !descriptor ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    ) return "ambiguous";
    code = descriptor.value;
  } catch {
    return "ambiguous";
  }
  switch (code) {
    case "E_VEIL_SETUP_MODE":
    case "E_VEIL_SETUP_ACTIVITY":
    case "E_VEIL_SETUP_LAUNCH":
      return "unavailable";
    case "E_VEIL_SETUP_BUSY":
    default:
      return "ambiguous";
  }
}
