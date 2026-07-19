import { NativeModules, Platform } from "react-native";

export type NativeIdentitySetupMode = "create" | "restore";
export type NativeIdentitySetupResult = "committed" | "user_cancelled" | "interrupted";

interface VeilIdentitySetupNative {
  beginNativeIdentitySetup(
    mode: NativeIdentitySetupMode,
  ): Promise<unknown>;
}

const PUBLIC_SETUP_ERROR =
  "Secure identity setup is unavailable. Close Veil and try again.";

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
  if (Platform.OS === "web") throw new Error(PUBLIC_SETUP_ERROR);

  const native = NativeModules.VeilIdentitySetup as VeilIdentitySetupNative | undefined;
  if (!native || typeof native.beginNativeIdentitySetup !== "function") {
    throw new Error(PUBLIC_SETUP_ERROR);
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
  } catch {
    // Native diagnostics can contain implementation details. The public UI
    // deliberately exposes one stable, non-sensitive recovery instruction.
    throw new Error(PUBLIC_SETUP_ERROR);
  }
}
