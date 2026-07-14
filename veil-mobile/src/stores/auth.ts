import { create } from "zustand";

interface AuthState {
  nativeIdentityState: "checking" | "locked" | "local_identity_ready" | "native_error";
  publicIdentityKey: string | null;
  nativeError: string | null;
  setLocalIdentityReady: (publicIdentityKey: string) => void;
  setLocked: () => void;
  setNativeError: (message: string) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  nativeIdentityState: "checking",
  publicIdentityKey: null,
  nativeError: null,
  setLocalIdentityReady: (publicIdentityKey) =>
    set({ nativeIdentityState: "local_identity_ready", publicIdentityKey, nativeError: null }),
  setLocked: () => set({ nativeIdentityState: "locked", publicIdentityKey: null, nativeError: null }),
  setNativeError: (nativeError) =>
    set({ nativeIdentityState: "native_error", publicIdentityKey: null, nativeError }),
}));
