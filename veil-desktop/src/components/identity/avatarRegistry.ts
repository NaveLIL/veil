import { createSignal } from "solid-js";
import {
  canonicalIdentityKey,
  canonicalIdentityOrigin,
  canonicalIdentityUserId,
} from "@/components/identity/identityProfile";
import type { PhaseprintIdentity } from "@/components/identity/Phaseprint";

interface AvatarEntry {
  source: string;
  bytes: number;
}

const MAX_ENTRIES = 128;
const MAX_TOTAL_BYTES = 16 * 1024 * 1024;
const entries = new Map<string, AvatarEntry>();
const [revision, setRevision] = createSignal(0);
let totalBytes = 0;

function locatorKey(identity: PhaseprintIdentity): string | null {
  const origin = canonicalIdentityOrigin(identity.canonicalServerOrigin);
  const userId = canonicalIdentityUserId(identity.userId);
  const identityKey = canonicalIdentityKey(identity.identityKey);
  return origin && userId && identityKey ? `${origin}\n${userId}\n${identityKey}` : null;
}

function revoke(key: string): void {
  const entry = entries.get(key);
  if (!entry) return;
  entries.delete(key);
  totalBytes -= entry.bytes;
  URL.revokeObjectURL(entry.source);
}

function publish(): void {
  setRevision((value) => value + 1);
}

export function avatarSourceForIdentity(identity: PhaseprintIdentity): string | null {
  revision();
  const key = locatorKey(identity);
  if (!key) return null;
  const entry = entries.get(key);
  if (!entry) return null;
  // Map iteration order is the eviction order. Refresh it on every successful
  // read so the documented budget is true LRU rather than insertion FIFO.
  entries.delete(key);
  entries.set(key, entry);
  return entry.source;
}

export function installNativeAvatar(
  identity: PhaseprintIdentity,
  assetId: string | null,
  jpegBase64: string | null,
): void {
  const key = locatorKey(identity);
  if (!key) return;
  revoke(key);
  if (!assetId || !jpegBase64) { publish(); return; }
  if (!/^[0-9a-f-]{36}$/.test(assetId) || jpegBase64.length > 360_000) { publish(); return; }
  let binary: string;
  try { binary = atob(jpegBase64); } catch { publish(); return; }
  if (
    binary.length < 4
    || binary.length > 256 * 1024
    || binary.charCodeAt(0) !== 0xff
    || binary.charCodeAt(1) !== 0xd8
    || binary.charCodeAt(binary.length - 2) !== 0xff
    || binary.charCodeAt(binary.length - 1) !== 0xd9
  ) { publish(); return; }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  const source = URL.createObjectURL(new Blob([bytes], { type: "image/jpeg" }));
  entries.set(key, { source, bytes: bytes.byteLength });
  totalBytes += bytes.byteLength;
  while (entries.size > MAX_ENTRIES || totalBytes > MAX_TOTAL_BYTES) {
    const oldest = entries.keys().next().value as string | undefined;
    if (!oldest) break;
    revoke(oldest);
  }
  publish();
}

export function rejectAvatarSource(source: string): void {
  for (const [key, entry] of entries) {
    if (entry.source === source) { revoke(key); publish(); return; }
  }
}

export function clearAvatarRegistry(): void {
  for (const key of [...entries.keys()]) revoke(key);
  publish();
}
