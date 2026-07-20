import { describe, expect, it } from "@jest/globals";

import {
  PUBLIC_FAILURE_CODES_V1,
  UNKNOWN_PUBLIC_FAILURE_CODE_V1,
  directDeliveryPublicFailureCodeV1,
  isPublicFailureCodeV1,
  normalizePublicFailureCodeV1,
  publicFailurePresentationV1,
} from "../publicFailureCodesV1";

describe("PublicFailureCodeV1 mobile catalog", () => {
  it("has one complete deterministic presentation for every registry consumer code", () => {
    expect(new Set(PUBLIC_FAILURE_CODES_V1).size).toBe(18);
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

  it("maps only typed terminal Direct delivery states to operation-only codes", () => {
    expect(directDeliveryPublicFailureCodeV1("sending")).toBeNull();
    expect(directDeliveryPublicFailureCodeV1("sent")).toBeNull();
    expect(directDeliveryPublicFailureCodeV1("failed")).toBe("VEIL-DIRECT-001");
    expect(directDeliveryPublicFailureCodeV1("unknown")).toBe("VEIL-DIRECT-002");

    for (const malformed of [null, undefined, 5, "FAILED", "unknown\nsecret", {}]) {
      expect(directDeliveryPublicFailureCodeV1(malformed)).toBeNull();
    }
  });

  it("keeps definite rejection and unknown delivery recovery semantics distinct", () => {
    const rejected = publicFailurePresentationV1("VEIL-DIRECT-001");
    const unknown = publicFailurePresentationV1("VEIL-DIRECT-002");

    expect(rejected.nextAction).toContain("currently Ready");
    expect(unknown.description).toContain("may already have reached the peer");
    expect(unknown.nextAction).toContain("Never resend it blindly");
  });
});
