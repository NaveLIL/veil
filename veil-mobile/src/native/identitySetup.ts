import { NativeModules, Platform } from "react-native";

export type NativeIdentitySetupMode = "create" | "restore";
export type NativeIdentitySetupResult = "committed" | "cancelled";

interface VeilIdentitySetupNative {
  beginNativeIdentitySetup(
    mode: NativeIdentitySetupMode,
  ): Promise<NativeIdentitySetupResult>;
}

const PUBLIC_SETUP_ERROR =
  "Secure identity setup is unavailable. Close Veil and try again.";

/**
 * Opens the protected platform-owned identity flow.
 *
 * No recovery material or identity key crosses this boundary. JavaScript
 * receives only whether native storage committed or the user cancelled.
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
    if (result !== "committed" && result !== "cancelled") {
      throw new Error(PUBLIC_SETUP_ERROR);
    }
    return result;
  } catch {
    // Native diagnostics can contain implementation details. The public UI
    // deliberately exposes one stable, non-sensitive recovery instruction.
    throw new Error(PUBLIC_SETUP_ERROR);
  }
}
