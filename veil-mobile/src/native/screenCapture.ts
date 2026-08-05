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
  let native: VeilWindowSecurityNative | undefined;
  let update: VeilWindowSecurityNative["setSensitiveScreen"] | undefined;
  try {
    native = NativeModules.VeilCrypto as VeilWindowSecurityNative | undefined;
    update = native?.setSensitiveScreen;
  } catch {
    // A lazy/hostile module proxy is equivalent to an unavailable bridge.
    // Android remains secure and no native diagnostic may become an unhandled
    // renderer rejection.
    return;
  }
  if (!native || typeof update !== "function") return;
  try {
    await Reflect.apply(update, native, [!ready]);
  } catch {
    // MainActivity starts secure. A bridge failure must not affect rendering or
    // invite retries, and native diagnostics never become public UI text.
  }
}
