import { describe, expect, test } from "@jest/globals";
import { authoritativeIdentityLocator, canonicalIdentityOrigin } from "../IdentityProof";

describe("mobile identity proof boundary", () => {
  test("requires explicit authenticated provenance before making a TOFU claim", () => {
    const presentationOnlyRow = {
      canonicalServerOrigin: "https://veil.example:443",
      userId: "10000000-0000-4000-8000-000000000001",
      identityKey: "11".repeat(32),
      identityAuthority: "unavailable" as const,
    };
    expect(authoritativeIdentityLocator(presentationOnlyRow)).toBeNull();
    expect(authoritativeIdentityLocator({
      ...presentationOnlyRow,
      identityAuthority: "authenticated-directory",
    })).toEqual({
      canonicalServerOrigin: presentationOnlyRow.canonicalServerOrigin,
      userId: presentationOnlyRow.userId,
      identityKey: presentationOnlyRow.identityKey,
    });
  });

  test("rejects remote plaintext origins but permits explicit loopback development", () => {
    expect(canonicalIdentityOrigin("http://remote.example:80")).toBeNull();
    expect(canonicalIdentityOrigin("http://127.0.0.1:9080")).toBe("http://127.0.0.1:9080");
    expect(canonicalIdentityOrigin("https://VEIL.example")).toBe("https://veil.example:443");
  });
});
