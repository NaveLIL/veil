import { create } from "zustand";

interface AuthState {
  mnemonic: string | null;
  identityKey: string | null;
  isAuthenticated: boolean;
  setMnemonic: (m: string) => void;
  setIdentityKey: (key: string) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  mnemonic: null,
  identityKey: null,
  isAuthenticated: false,
  setMnemonic: (m) => set({ mnemonic: m }),
  setIdentityKey: (key) => set({ identityKey: key, isAuthenticated: true, mnemonic: null }),
  logout: () => set({ mnemonic: null, identityKey: null, isAuthenticated: false }),
}));
