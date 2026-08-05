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

export interface NativeAvatarPayload extends PhaseprintIdentity {
  avatarAssetId: string | null;
  avatarJpegBase64: string | null;
  profileVersion: string;
}

export type NativeAvatarLoader = () => Promise<NativeAvatarPayload>;

interface HydrationRecord {
  profileVersion: string;
}

interface HydrationJob {
  key: string;
  identity: Required<Pick<
    PhaseprintIdentity,
    "canonicalServerOrigin" | "userId" | "identityKey"
  >>;
  loader: NativeAvatarLoader;
  minimumProfileVersion: string | null;
  registryEpoch: number;
  started: boolean;
  promise: Promise<boolean>;
  resolve: (installed: boolean) => void;
}

const MAX_ENTRIES = 128;
const MAX_TOTAL_BYTES = 16 * 1024 * 1024;
const MAX_HYDRATION_JOBS = 256;
const MAX_CONCURRENT_HYDRATIONS = 4;
const entries = new Map<string, AvatarEntry>();
const hydrationRecords = new Map<string, HydrationRecord>();
const hydrationJobs = new Map<string, HydrationJob>();
const hydrationQueue: HydrationJob[] = [];
const [revision, setRevision] = createSignal(0);
let totalBytes = 0;
let activeHydrations = 0;
let registryEpoch = 0;

function locatorKey(identity: PhaseprintIdentity): string | null {
  const origin = canonicalIdentityOrigin(identity.canonicalServerOrigin);
  const userId = canonicalIdentityUserId(identity.userId);
  const identityKey = canonicalIdentityKey(identity.identityKey);
  return origin && userId && identityKey ? `${origin}\n${userId}\n${identityKey}` : null;
}

function exactLocator(identity: PhaseprintIdentity): HydrationJob["identity"] | null {
  const canonicalServerOrigin = canonicalIdentityOrigin(identity.canonicalServerOrigin);
  const userId = canonicalIdentityUserId(identity.userId);
  const identityKey = canonicalIdentityKey(identity.identityKey);
  if (
    !canonicalServerOrigin
    || !userId
    || !identityKey
    || canonicalServerOrigin !== identity.canonicalServerOrigin
    || userId !== identity.userId
    || identityKey !== identity.identityKey
  ) return null;
  return { canonicalServerOrigin, userId, identityKey };
}

function canonicalProfileVersion(value: string | null | undefined): string | null {
  if (
    typeof value !== "string"
    || !/^(0|[1-9][0-9]*)$/.test(value)
    || value.length > 19
    || BigInt(value) > 9223372036854775807n
  ) return null;
  return value;
}

function newerProfileVersion(left: string | null, right: string | null): string | null {
  if (!left) return right;
  if (!right) return left;
  return BigInt(left) >= BigInt(right) ? left : right;
}

function versionSatisfies(actual: string, minimum: string | null): boolean {
  return !minimum || BigInt(actual) >= BigInt(minimum);
}

function touchHydrationRecord(key: string, record: HydrationRecord): void {
  hydrationRecords.delete(key);
  hydrationRecords.set(key, record);
  while (hydrationRecords.size > MAX_ENTRIES) {
    const oldest = hydrationRecords.keys().next().value as string | undefined;
    if (!oldest) break;
    hydrationRecords.delete(oldest);
  }
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

async function runHydration(job: HydrationJob): Promise<boolean> {
  // A profile update can join an already-running initial request. One retry
  // closes the narrow race where the first response predates that event.
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let payload: NativeAvatarPayload;
    try {
      payload = await job.loader();
    } catch {
      return false;
    }
    if (job.registryEpoch !== registryEpoch || hydrationJobs.get(job.key) !== job) return false;
    const payloadLocator = exactLocator(payload);
    const profileVersion = canonicalProfileVersion(payload.profileVersion);
    if (
      !payloadLocator
      || locatorKey(payloadLocator) !== job.key
      || !profileVersion
    ) return false;
    if (!versionSatisfies(profileVersion, job.minimumProfileVersion)) continue;

    if (payload.avatarAssetId === null && payload.avatarJpegBase64 === null) {
      installNativeAvatar(job.identity, null, null);
      touchHydrationRecord(job.key, { profileVersion });
      return true;
    }
    // Native may truthfully return profile metadata while an avatar download
    // failed. Retain the previous local image and allow a later visible retry.
    if (!payload.avatarAssetId || !payload.avatarJpegBase64) return false;
    installNativeAvatar(job.identity, payload.avatarAssetId, payload.avatarJpegBase64);
    if (!entries.has(job.key)) return false;
    touchHydrationRecord(job.key, { profileVersion });
    return true;
  }
  return false;
}

function pumpHydrationQueue(): void {
  while (activeHydrations < MAX_CONCURRENT_HYDRATIONS && hydrationQueue.length > 0) {
    const job = hydrationQueue.shift()!;
    if (job.registryEpoch !== registryEpoch || hydrationJobs.get(job.key) !== job) {
      job.resolve(false);
      continue;
    }
    job.started = true;
    activeHydrations += 1;
    void runHydration(job).then((installed) => {
      if (hydrationJobs.get(job.key) === job) hydrationJobs.delete(job.key);
      job.resolve(installed);
    }).finally(() => {
      activeHydrations -= 1;
      pumpHydrationQueue();
    });
  }
}

/**
 * Queue one native-validated avatar lookup for an exact account locator.
 * Duplicate visible avatars share the same bounded request and never consume
 * an untrusted URL: only the native command's validated JPEG bytes are used.
 */
export function requestNativeAvatar(
  identity: PhaseprintIdentity,
  loader: NativeAvatarLoader,
  minimumProfileVersion?: string | null,
): Promise<boolean> {
  const exact = exactLocator(identity);
  const minimum = minimumProfileVersion === null || minimumProfileVersion === undefined
    ? null
    : canonicalProfileVersion(minimumProfileVersion);
  if (!exact || (minimumProfileVersion != null && !minimum)) return Promise.resolve(false);
  const key = locatorKey(exact)!;
  const record = hydrationRecords.get(key);
  if (record && versionSatisfies(record.profileVersion, minimum)) {
    touchHydrationRecord(key, record);
    return Promise.resolve(true);
  }
  if (!minimum && entries.has(key)) return Promise.resolve(true);

  const existing = hydrationJobs.get(key);
  if (existing) {
    existing.minimumProfileVersion = newerProfileVersion(
      existing.minimumProfileVersion,
      minimum,
    );
    return existing.promise;
  }
  if (hydrationJobs.size >= MAX_HYDRATION_JOBS) return Promise.resolve(false);

  let resolve!: (installed: boolean) => void;
  const promise = new Promise<boolean>((done) => { resolve = done; });
  const job: HydrationJob = {
    key,
    identity: exact,
    loader,
    minimumProfileVersion: minimum,
    registryEpoch,
    started: false,
    promise,
    resolve,
  };
  hydrationJobs.set(key, job);
  hydrationQueue.push(job);
  pumpHydrationQueue();
  return promise;
}

export function rejectAvatarSource(source: string): void {
  for (const [key, entry] of entries) {
    if (entry.source === source) {
      revoke(key);
      hydrationRecords.delete(key);
      publish();
      return;
    }
  }
}

export function clearAvatarRegistry(): void {
  registryEpoch += 1;
  hydrationRecords.clear();
  hydrationQueue.splice(0, hydrationQueue.length);
  for (const job of hydrationJobs.values()) {
    if (!job.started) job.resolve(false);
  }
  hydrationJobs.clear();
  for (const key of [...entries.keys()]) revoke(key);
  publish();
}
