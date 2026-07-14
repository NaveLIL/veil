import { describe, expect, test } from "@jest/globals";
import {
  createPhaseprintModel,
  resolvePhaseprintSeed,
} from "../Phaseprint";

const ORIGIN_A = "https://alpha.example.test:443";
const ORIGIN_B = "https://beta.example.test:443";
const USER_ID = "550e8400-e29b-41d4-a716-446655440000";
const IDENTITY_KEY = "31".repeat(32);

describe("cross-platform Phaseprint v1", () => {
  test("matches the frozen desktop identity-key vector", () => {
    expect(createPhaseprintModel({
      identityKey: IDENTITY_KEY,
      canonicalServerOrigin: ORIGIN_A,
      userId: USER_ID,
      technicalUsername: "Sable",
    }).renderVector).toBe("505ea8c981828b4817ea1321992c7936");
  });

  test("uses the same origin-scoped UUID, username and anonymous vectors", () => {
    expect(createPhaseprintModel({
      canonicalServerOrigin: ORIGIN_A,
      userId: USER_ID,
      technicalUsername: "Sable",
    }).renderVector).toBe("152738c81bb332b4401ce09a3baafe1a");
    expect(createPhaseprintModel({
      canonicalServerOrigin: ORIGIN_A,
      identityKey: "00".repeat(32),
      userId: "00000000-0000-0000-0000-000000000000",
      technicalUsername: "Phase\u0301",
    }).renderVector).toBe("6421a3aea1b7233ac1bf0d8daf4a95f9");
    expect(createPhaseprintModel({ canonicalServerOrigin: ORIGIN_A }).renderVector)
      .toBe("db6e905fbb568f50e8186bf5d85a7caa");
  });

  test("isolates self-hosted origins and rejects malformed identity coordinates", () => {
    const alpha = createPhaseprintModel({ canonicalServerOrigin: ORIGIN_A, userId: USER_ID });
    const beta = createPhaseprintModel({ canonicalServerOrigin: ORIGIN_B, userId: USER_ID });
    expect(alpha.renderVector).not.toBe(beta.renderVector);
    expect(resolvePhaseprintSeed({
      identityKey: "not-a-key",
      canonicalServerOrigin: ORIGIN_A,
      userId: "not-a-uuid",
      technicalUsername: "fallback",
    }).kind).toBe("username");
    expect(resolvePhaseprintSeed({
      canonicalServerOrigin: "https://alpha.example.test/profile",
      userId: USER_ID,
    }).kind).toBe("anonymous");
  });

  test("nickname and display-name changes cannot alter the model", () => {
    const identity = {
      identityKey: IDENTITY_KEY,
      canonicalServerOrigin: ORIGIN_A,
      userId: USER_ID,
      technicalUsername: "stable-username",
    };
    expect(createPhaseprintModel({ ...identity, nickname: "First" } as typeof identity))
      .toEqual(createPhaseprintModel({ ...identity, nickname: "Second" } as typeof identity));
  });

  test("replaces lone UTF-16 surrogates exactly like desktop TextEncoder", () => {
    expect(createPhaseprintModel({
      canonicalServerOrigin: ORIGIN_A,
      technicalUsername: "bad\ud800name",
    }).renderVector).toBe("d6d87eccd1a7d52194ea15f9006dcb49");
  });
});
