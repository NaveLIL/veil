import { describe, expect, it } from "@jest/globals";

import {
  PUBLIC_FAILURE_CODES_V1,
  UNKNOWN_PUBLIC_FAILURE_CODE_V1,
  isPublicFailureCodeV1,
  normalizePublicFailureCodeV1,
  publicFailurePresentationV1,
} from "../publicFailureCodesV1";

describe("PublicFailureCodeV1 mobile catalog", () => {
  it("has one complete deterministic presentation for every registry consumer code", () => {
    expect(new Set(PUBLIC_FAILURE_CODES_V1).size).toBe(16);
    for (const code of PUBLIC_FAILURE_CODES_V1) {
      expect(code).toMatch(/^VEIL-[A-Z][A-Z0-9]*-[0-9]{3}$/);
      expect([...code].every((character) => character.charCodeAt(0) <= 0x7f)).toBe(true);
      expect(isPublicFailureCodeV1(code)).toBe(true);
      expect(publicFailurePresentationV1(code)).toEqual({
        code,
        title: expect.stringMatching(/\S/),
        description: expect.stringMatching(/\S/),
        nextAction: expect.stringMatching(/\S/),
      });
    }
  });

  it("fails closed to the reviewed unknown outcome for malformed values", () => {
    for (const value of [null, undefined, 7, "", "VEIL-SYNC-999", "VEIL-SYNC-001\nsecret"]) {
      expect(normalizePublicFailureCodeV1(value)).toBe(UNKNOWN_PUBLIC_FAILURE_CODE_V1);
      expect(publicFailurePresentationV1(value).code).toBe("VEIL-RUNTIME-999");
    }
  });
});
