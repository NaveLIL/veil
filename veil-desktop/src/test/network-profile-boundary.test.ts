import { describe, expect, it } from "vitest";
import {
  validatedNetworkProfileView,
  type AuthenticatedServerScope,
} from "@/stores/app";

const scope: AuthenticatedServerScope = {
  userId: "550e8400-e29b-41d4-a716-446655440001",
  canonicalServerOrigin: "https://profiles.example.test:443",
  bindingGeneration: "7",
};
const targetUserId = "550e8400-e29b-41d4-a716-446655440002";
const identityKey = "41".repeat(32);

const validProfile = {
  canonicalServerOrigin: scope.canonicalServerOrigin,
  userId: targetUserId,
  identityKey,
  username: "quiet-orbit",
  displayName: "Quiet Orbit",
  about: "Profile text",
  profileVersion: "18446744073709551615",
  profileUpdatedAt: "2026-07-13T05:00:00Z",
  observedAt: "2026-07-13T05:00:01Z",
  proofState: "not_compared",
};

describe("network profile renderer boundary", () => {
  it("preserves the canonical u64 revision without JavaScript precision loss", () => {
    expect(validatedNetworkProfileView(
      validProfile,
      scope,
      targetUserId,
      identityKey,
    ).profileVersion).toBe("18446744073709551615");
  });

  it("rejects locator substitution and non-canonical revisions", () => {
    for (const invalid of [
      { ...validProfile, canonicalServerOrigin: "https://other.example.test:443" },
      { ...validProfile, userId: scope.userId },
      { ...validProfile, identityKey: "42".repeat(32) },
      { ...validProfile, profileVersion: "01" },
      { ...validProfile, proofState: "verified" },
    ]) {
      expect(() => validatedNetworkProfileView(
        invalid,
        scope,
        targetUserId,
        identityKey,
      )).toThrow();
    }
  });
});
