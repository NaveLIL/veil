import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  avatarSourceForIdentity,
  clearAvatarRegistry,
  installNativeAvatar,
  rejectAvatarSource,
  requestNativeAvatar,
} from "@/components/identity/avatarRegistry";

const identity = {
  canonicalServerOrigin: "https://profiles.example.test:443",
  userId: "550e8400-e29b-41d4-a716-446655440002",
  identityKey: "41".repeat(32),
};

describe("native avatar registry", () => {
  const revoke = vi.fn();
  beforeEach(() => {
    vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:https://veil.local/avatar-1");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(revoke);
  });
  afterEach(() => { clearAvatarRegistry(); vi.restoreAllMocks(); revoke.mockClear(); });

  it("binds only native JPEG bytes to the exact identity and revokes failures", () => {
    installNativeAvatar(identity, "550e8400-e29b-41d4-a716-446655440000", "/9j/2Q==");
    expect(avatarSourceForIdentity(identity)).toBe("blob:https://veil.local/avatar-1");
    expect(avatarSourceForIdentity({ ...identity, identityKey: "42".repeat(32) })).toBeNull();
    rejectAvatarSource("blob:https://veil.local/avatar-1");
    expect(avatarSourceForIdentity(identity)).toBeNull();
    expect(revoke).toHaveBeenCalledWith("blob:https://veil.local/avatar-1");
  });

  it("keeps Phaseprint active for malformed or incomplete payloads", () => {
    installNativeAvatar(identity, "550e8400-e29b-41d4-a716-446655440000", btoa("not-jpeg"));
    expect(avatarSourceForIdentity(identity)).toBeNull();
    installNativeAvatar(identity, null, "/9j/2Q==");
    expect(avatarSourceForIdentity(identity)).toBeNull();
  });

  it("replaces, touches and evicts entries using the bounded LRU order", () => {
    let nextUrl = 0;
    vi.mocked(URL.createObjectURL).mockImplementation(() => `blob:https://veil.local/avatar-${++nextUrl}`);
    const at = (index: number) => ({
      ...identity,
      userId: `550e8400-e29b-41d4-a716-${String(index).padStart(12, "0")}`,
      identityKey: (index + 1).toString(16).padStart(64, "0"),
    });
    for (let index = 0; index < 128; index += 1) {
      installNativeAvatar(at(index), "550e8400-e29b-41d4-a716-446655440000", "/9j/2Q==");
    }
    expect(avatarSourceForIdentity(at(0))).toBe("blob:https://veil.local/avatar-1");
    installNativeAvatar(at(128), "550e8400-e29b-41d4-a716-446655440000", "/9j/2Q==");
    expect(avatarSourceForIdentity(at(0))).toBe("blob:https://veil.local/avatar-1");
    expect(avatarSourceForIdentity(at(1))).toBeNull();
    expect(revoke).toHaveBeenCalledWith("blob:https://veil.local/avatar-2");

    installNativeAvatar(at(0), "550e8400-e29b-41d4-a716-446655440001", "/9j/2Q==");
    expect(revoke).toHaveBeenCalledWith("blob:https://veil.local/avatar-1");
    expect(avatarSourceForIdentity(at(0))).toBe("blob:https://veil.local/avatar-130");
  });

  it("deduplicates native hydration for one exact locator", async () => {
    let resolveProfile!: (value: any) => void;
    const loader = vi.fn(() => new Promise<any>((resolve) => { resolveProfile = resolve; }));
    const first = requestNativeAvatar(identity, loader);
    const duplicate = requestNativeAvatar(identity, loader);
    expect(duplicate).toBe(first);
    expect(loader).toHaveBeenCalledOnce();

    resolveProfile({
      ...identity,
      avatarAssetId: "550e8400-e29b-41d4-a716-446655440000",
      avatarJpegBase64: "/9j/2Q==",
      profileVersion: "1",
    });
    await expect(first).resolves.toBe(true);
    expect(avatarSourceForIdentity(identity)).toBe("blob:https://veil.local/avatar-1");
    await expect(requestNativeAvatar(identity, loader)).resolves.toBe(true);
    expect(loader).toHaveBeenCalledOnce();
  });

  it("drops late hydration after registry clear and refreshes for a newer profile version", async () => {
    let resolveStale!: (value: any) => void;
    const staleLoader = vi.fn(() => new Promise<any>((resolve) => { resolveStale = resolve; }));
    const stale = requestNativeAvatar(identity, staleLoader);
    clearAvatarRegistry();
    resolveStale({
      ...identity,
      avatarAssetId: "550e8400-e29b-41d4-a716-446655440000",
      avatarJpegBase64: "/9j/2Q==",
      profileVersion: "1",
    });
    await expect(stale).resolves.toBe(false);
    expect(avatarSourceForIdentity(identity)).toBeNull();

    const initial = vi.fn(async () => ({
      ...identity,
      avatarAssetId: null,
      avatarJpegBase64: null,
      profileVersion: "1",
    }));
    await expect(requestNativeAvatar(identity, initial)).resolves.toBe(true);
    await expect(requestNativeAvatar(identity, initial)).resolves.toBe(true);
    expect(initial).toHaveBeenCalledOnce();

    const updated = vi.fn(async () => ({
      ...identity,
      avatarAssetId: "550e8400-e29b-41d4-a716-446655440003",
      avatarJpegBase64: "/9j/2Q==",
      profileVersion: "2",
    }));
    await expect(requestNativeAvatar(identity, updated, "2")).resolves.toBe(true);
    expect(updated).toHaveBeenCalledOnce();
    expect(avatarSourceForIdentity(identity)).toBe("blob:https://veil.local/avatar-1");
  });

  it("limits concurrent native avatar work", async () => {
    let active = 0;
    let peak = 0;
    const releases: Array<() => void> = [];
    const identities = Array.from({ length: 8 }, (_, index) => ({
      ...identity,
      userId: `550e8400-e29b-41d4-a716-${String(index + 100).padStart(12, "0")}`,
      identityKey: (index + 100).toString(16).padStart(64, "0"),
    }));
    const requests = identities.map((candidate) => requestNativeAvatar(candidate, async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise<void>((resolve) => releases.push(resolve));
      active -= 1;
      return {
        ...candidate,
        avatarAssetId: null,
        avatarJpegBase64: null,
        profileVersion: "1",
      };
    }));
    expect(peak).toBe(4);
    releases.splice(0).forEach((release) => release());
    await Promise.all(requests.slice(0, 4));
    await vi.waitFor(() => expect(active).toBe(4));
    releases.splice(0).forEach((release) => release());
    await expect(Promise.all(requests)).resolves.toEqual(Array(8).fill(true));
    expect(peak).toBe(4);
  });
});
