/**
 * High-level Android account runtime.
 *
 * This boundary intentionally exposes only public account/origin metadata.
 * Recovery phrases, Node Access Pass bearers, private keys, REST signatures,
 * ratchet state, and SQLCipher keys never have a JavaScript representation.
 */
import {
  NativeEventEmitter,
  NativeModules,
  Platform,
  type EmitterSubscription,
} from "react-native";

export type NativeSessionState = "locked" | "opening" | "open" | "closing" | "error";
export type NativeConnectionState = "disconnected" | "connecting" | "connected" | "error";
export type NativeSecureSyncState =
  | "idle"
  | "publishing_keys"
  | "syncing_directory"
  | "directory_synchronized"
  | "error";

export interface AuthenticatedBinding {
  canonicalServerOrigin: string;
  userId: string;
}

export interface PendingNodeAccessPass {
  /** Random native flow reference. This is not the bearer token. */
  flowId: string;
  canonicalOrigin: string;
  /** First 48 bits of SHA-256(token), suitable only for human disambiguation. */
  tokenRef: string;
  expiresInSeconds: number;
}

export interface VeilMobileRuntimeSnapshot {
  identityExists: boolean;
  sessionState: NativeSessionState;
  connectionState: NativeConnectionState;
  directoryReady: boolean;
  /** Coarse native bootstrap progress. Contains no keys, request data, or capabilities. */
  secureSyncState: NativeSecureSyncState;
  binding: AuthenticatedBinding | null;
  pendingAccessPass: PendingNodeAccessPass | null;
}

interface VeilMobileRuntimeNative {
  getRuntimeSnapshot(): Promise<VeilMobileRuntimeSnapshot>;
  openSession(): Promise<VeilMobileRuntimeSnapshot>;
  connect(canonicalOrigin: string): Promise<AuthenticatedBinding>;
  connectPendingAccessPass(flowId: string): Promise<AuthenticatedBinding>;
  disconnect(): Promise<VeilMobileRuntimeSnapshot>;
  lockSession(): Promise<VeilMobileRuntimeSnapshot>;
  cancelPendingAccessPass(flowId: string): Promise<boolean>;
  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

const NativeRuntime = NativeModules.VeilMobileRuntime as VeilMobileRuntimeNative | undefined;

const unavailable = (): never => {
  throw new Error(
    `VeilMobileRuntime native module is unavailable on ${Platform.OS}. ` +
      "Use a native Veil build with the Rust account runtime linked.",
  );
};

const requireRuntime = (): VeilMobileRuntimeNative => NativeRuntime ?? unavailable();

const runtimeEmitter = NativeRuntime ? new NativeEventEmitter(NativeRuntime as never) : null;

const VeilRuntime = {
  getSnapshot: (): Promise<VeilMobileRuntimeSnapshot> => requireRuntime().getRuntimeSnapshot(),
  openSession: (): Promise<VeilMobileRuntimeSnapshot> => requireRuntime().openSession(),
  connect: (canonicalOrigin: string): Promise<AuthenticatedBinding> =>
    requireRuntime().connect(canonicalOrigin),
  connectPendingAccessPass: (flowId: string): Promise<AuthenticatedBinding> =>
    requireRuntime().connectPendingAccessPass(flowId),
  disconnect: (): Promise<VeilMobileRuntimeSnapshot> => requireRuntime().disconnect(),
  lock: (): Promise<VeilMobileRuntimeSnapshot> => requireRuntime().lockSession(),
  cancelPendingAccessPass: (flowId: string): Promise<boolean> =>
    requireRuntime().cancelPendingAccessPass(flowId),
  subscribe(listener: (snapshot: VeilMobileRuntimeSnapshot) => void): EmitterSubscription {
    const emitter = runtimeEmitter;
    if (!emitter) return unavailable();
    return emitter.addListener("VeilRuntimeStateChanged", listener);
  },
};

export default VeilRuntime;
