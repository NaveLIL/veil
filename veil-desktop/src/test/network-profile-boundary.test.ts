import { describe, expect, it } from "vitest";
import {
  validatedCachedIdentityProofView,
  validatedIdentityVerificationView,
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
  avatarAssetId: null,
  avatarJpegBase64: null,
  profileVersion: "9223372036854775807",
  profileUpdatedAt: "2026-07-13T05:00:00Z",
  observedAt: "2026-07-13T05:00:01Z",
  proofState: "not_compared",
};

describe("network profile renderer boundary", () => {
  it("preserves the canonical PostgreSQL revision without JavaScript precision loss", () => {
    expect(validatedNetworkProfileView(
      validProfile,
      scope,
      targetUserId,
      identityKey,
    ).profileVersion).toBe("9223372036854775807");
  });

  it("rejects locator substitution and non-canonical revisions", () => {
    for (const invalid of [
      { ...validProfile, canonicalServerOrigin: "https://other.example.test:443" },
      { ...validProfile, userId: scope.userId },
      { ...validProfile, identityKey: "42".repeat(32) },
      { ...validProfile, profileVersion: "01" },
      { ...validProfile, profileVersion: "9223372036854775808" },
      { ...validProfile, proofState: "verified" },
      { ...validProfile, avatarAssetId: "https://cdn.example.test/avatar.jpg" },
      { ...validProfile, avatarAssetId: null, avatarJpegBase64: "/9j/2Q==" },
      { ...validProfile, displayName: "safe\u00adhidden" },
      { ...validProfile, about: "safe\u2028hidden" },
      { ...validProfile, username: "safe\u206ahidden" },
    ]) {
      expect(() => validatedNetworkProfileView(
        invalid,
        scope,
        targetUserId,
        identityKey,
      )).toThrow();
    }
  });

  it("rejects fingerprint proof state or locator substitution at the renderer boundary", () => {
    const validVerification = {
      canonicalServerOrigin: scope.canonicalServerOrigin,
      userId: targetUserId,
      identityKey,
      signingKey: "42".repeat(32),
      fingerprintVersion: "account_v2",
      fingerprintHex: "51".repeat(32),
      fingerprintEmoji: "🔒".repeat(32),
      proofState: "not_compared",
    };
    expect(validatedIdentityVerificationView(
      validVerification,
      scope,
      targetUserId,
      identityKey,
    ).fingerprintHex).toBe("51".repeat(32));
    for (const invalid of [
      { ...validVerification, userId: scope.userId },
      { ...validVerification, identityKey: "42".repeat(32) },
      { ...validVerification, signingKey: "00".repeat(32) },
      { ...validVerification, fingerprintVersion: "identity_v1" },
      { ...validVerification, fingerprintHex: "51".repeat(31) },
      { ...validVerification, proofState: "verified" },
    ]) {
      expect(() => validatedIdentityVerificationView(
        invalid,
        scope,
        targetUserId,
        identityKey,
      )).toThrow();
    }
  });

  it("keeps offline partial proof separate from comparable account fingerprints", () => {
    const proof = {
      canonicalServerOrigin: scope.canonicalServerOrigin,
      userId: targetUserId,
      identityKey,
      proofState: "identity_changed",
    };
    expect(validatedCachedIdentityProofView(
      proof,
      scope.canonicalServerOrigin,
      targetUserId,
      identityKey,
    ).proofState).toBe("identity_changed");
    expect(() => validatedCachedIdentityProofView(
      { ...proof, fingerprintHex: "51".repeat(32) },
      scope.canonicalServerOrigin,
      targetUserId,
      identityKey,
    )).toThrow();
  });
});
