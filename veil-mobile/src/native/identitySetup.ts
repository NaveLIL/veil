import { NativeModules, Platform } from "react-native";

export type NativeIdentitySetupMode = "create" | "restore";
export type NativeIdentitySetupResult = "committed" | "user_cancelled" | "interrupted";
export type NativeIdentitySetupStartFailureKind = "unavailable" | "ambiguous";

interface VeilIdentitySetupNative {
  beginNativeIdentitySetup(
    mode: NativeIdentitySetupMode,
  ): Promise<unknown>;
}

const PUBLIC_SETUP_ERROR =
  "Secure identity setup is unavailable. Close Veil and try again.";

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

  const native = NativeModules.VeilIdentitySetup as VeilIdentitySetupNative | undefined;
  if (!native || typeof native.beginNativeIdentitySetup !== "function") {
    throw new NativeIdentitySetupStartError("unavailable");
  }

  try {
    const result = await native.beginNativeIdentitySetup(mode);
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

function classifyStartFailure(error: unknown): NativeIdentitySetupStartFailureKind {
  if (!error || typeof error !== "object") return "ambiguous";
  const code = (error as Record<string, unknown>).code;
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
