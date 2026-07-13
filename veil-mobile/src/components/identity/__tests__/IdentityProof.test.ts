import { describe, expect, test } from "@jest/globals";
import { MEMBERS_BY_SERVER } from "../../../stores/chat";
import { authoritativeIdentityLocator, canonicalIdentityOrigin } from "../IdentityProof";

describe("mobile identity proof boundary", () => {
  test("requires explicit authenticated provenance before making a TOFU claim", () => {
    const prototypeRow = MEMBERS_BY_SERVER.veil[0];
    expect(authoritativeIdentityLocator(prototypeRow)).toBeNull();
    expect(authoritativeIdentityLocator({
      ...prototypeRow,
      identityAuthority: "authenticated-directory",
    })).toEqual({
      canonicalServerOrigin: prototypeRow.canonicalServerOrigin,
      userId: prototypeRow.userId,
      identityKey: prototypeRow.identityKey,
    });
  });

  test("rejects remote plaintext origins but permits explicit loopback development", () => {
    expect(canonicalIdentityOrigin("http://remote.example:80")).toBeNull();
    expect(canonicalIdentityOrigin("http://127.0.0.1:9080")).toBe("http://127.0.0.1:9080");
    expect(canonicalIdentityOrigin("https://VEIL.example")).toBe("https://veil.example:443");
  });
});
