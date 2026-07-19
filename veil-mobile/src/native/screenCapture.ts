import { NativeModules, Platform } from "react-native";

interface VeilWindowSecurityNative {
  setSensitiveScreen(enabled: boolean): Promise<unknown>;
}

/**
 * Announces whether the fully authenticated, foreground Ready shell is shown.
 *
 * This is not an authority decision: Android release builds ignore downgrade
 * requests at compile time, and secret/background/Recents boundaries remain
 * native-owned. Missing or failed bridges leave the Activity secure.
 */
export async function setAuthenticatedContentReady(ready: boolean): Promise<void> {
  if (Platform.OS !== "android") return;
  const native = NativeModules.VeilCrypto as VeilWindowSecurityNative | undefined;
  if (!native || typeof native.setSensitiveScreen !== "function") return;
  try {
    await native.setSensitiveScreen(!ready);
  } catch {
    // MainActivity starts secure. A bridge failure must not affect rendering or
    // invite retries, and native diagnostics never become public UI text.
  }
}
