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
});
