import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  avatarSourceForIdentity,
  clearAvatarRegistry,
  installNativeAvatar,
  rejectAvatarSource,
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
});
