import { fireEvent, render, screen } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createPhaseprintModel,
  resolvePhaseprintSeed,
} from "@/components/identity/Phaseprint";
import { UserAvatar } from "@/components/identity/UserAvatar";
import { phaseprintIdentityForFriendRequest } from "@/components/identity/avatarIdentity";
import { clearAvatarRegistry, installNativeAvatar } from "@/components/identity/avatarRegistry";

const ORIGIN_A = "https://alpha.example.test:443";
const ORIGIN_B = "https://beta.example.test:443";
const USER_ID = "550e8400-e29b-41d4-a716-446655440000";
const IDENTITY_KEY = "31".repeat(32);

describe("Phaseprint v1", () => {
  it("freezes the deterministic identity-key vector and seed precedence", () => {
    const model = createPhaseprintModel({
      identityKey: IDENTITY_KEY,
      canonicalServerOrigin: ORIGIN_A,
      userId: USER_ID,
      technicalUsername: "Sable",
    });

    expect(model.seedKind).toBe("identity-key");
    expect(model.renderVector).toBe("505ea8c981828b4817ea1321992c7936");
    expect(model.cells.length).toBeGreaterThan(8);
    expect(createPhaseprintModel({
      identityKey: IDENTITY_KEY.toUpperCase(),
      canonicalServerOrigin: ORIGIN_B,
      userId: "550e8400-e29b-41d4-a716-446655440099",
      technicalUsername: "Another name",
    })).toEqual(model);
  });

  it("scopes UUID and username fallbacks by canonical server origin", () => {
    const byUserA = createPhaseprintModel({
      canonicalServerOrigin: ORIGIN_A,
      userId: USER_ID,
      technicalUsername: "Sable",
    });
    const byUserB = createPhaseprintModel({
      canonicalServerOrigin: ORIGIN_B,
      userId: USER_ID,
      technicalUsername: "Sable",
    });
    expect(byUserA.seedKind).toBe("user-id");
    expect(byUserA.renderVector).toBe("152738c81bb332b4401ce09a3baafe1a");
    expect(byUserA.renderVector).not.toBe(byUserB.renderVector);

    const byNameA = createPhaseprintModel({
      identityKey: "00".repeat(32),
      canonicalServerOrigin: ORIGIN_A,
      userId: "00000000-0000-0000-0000-000000000000",
      technicalUsername: "Phase\u0301",
    });
    const byNameEquivalent = createPhaseprintModel({
      canonicalServerOrigin: ORIGIN_A,
      technicalUsername: "Phasé",
    });
    const byNameB = createPhaseprintModel({
      canonicalServerOrigin: ORIGIN_B,
      technicalUsername: "Phasé",
    });
    expect(byNameA.seedKind).toBe("username");
    expect(byNameA.renderVector).toBe("6421a3aea1b7233ac1bf0d8daf4a95f9");
    expect(byNameA).toEqual(byNameEquivalent);
    expect(byNameA.renderVector).not.toBe(byNameB.renderVector);
  });

  it("rejects malformed identity coordinates instead of presenting them as canonical", () => {
    expect(resolvePhaseprintSeed({
      identityKey: "not-a-key",
      canonicalServerOrigin: ORIGIN_A,
      userId: "not-a-uuid",
      technicalUsername: "fallback",
    }).kind).toBe("username");
    expect(resolvePhaseprintSeed({
      identityKey: IDENTITY_KEY,
      canonicalServerOrigin: "https://alpha.example.test/profile",
      userId: USER_ID,
    }).kind).toBe("identity-key");
    expect(resolvePhaseprintSeed({
      canonicalServerOrigin: "https://alpha.example.test/profile",
      userId: USER_ID,
    }).kind).toBe("anonymous");
  });

  it("canonicalizes origins and bounds technical usernames before hashing", () => {
    const implicitDefaultPort = resolvePhaseprintSeed({
      canonicalServerOrigin: "https://ALPHA.example.test",
      userId: USER_ID.toUpperCase(),
    });
    const explicitDefaultPort = resolvePhaseprintSeed({
      canonicalServerOrigin: ORIGIN_A,
      userId: USER_ID,
    });
    expect(implicitDefaultPort).toEqual(explicitDefaultPort);
    expect(resolvePhaseprintSeed({
      canonicalServerOrigin: "http://[::1]:9080",
      userId: USER_ID,
    }).kind).toBe("user-id");

    expect(resolvePhaseprintSeed({
      canonicalServerOrigin: ORIGIN_A,
      technicalUsername: "a".repeat(256),
    }).kind).toBe("username");
    expect(resolvePhaseprintSeed({
      canonicalServerOrigin: ORIGIN_A,
      technicalUsername: "a".repeat(257),
    }).kind).toBe("anonymous");
    expect(resolvePhaseprintSeed({
      canonicalServerOrigin: ORIGIN_A,
      technicalUsername: "é".repeat(128),
    }).kind).toBe("username");
    expect(resolvePhaseprintSeed({
      canonicalServerOrigin: ORIGIN_A,
      technicalUsername: "é".repeat(129),
    }).kind).toBe("anonymous");

    const scopedAnonymous = createPhaseprintModel({ canonicalServerOrigin: ORIGIN_A });
    expect(scopedAnonymous.seedKind).toBe("anonymous");
    expect(scopedAnonymous.renderVector).toBe("db6e905fbb568f50e8186bf5d85a7caa");
  });

  it("never seeds an outgoing friend request with the local from-user UUID", () => {
    const outgoing = phaseprintIdentityForFriendRequest({
      fromUserId: USER_ID,
      fromUsername: "counterpart-name",
      outgoing: true,
    }, ORIGIN_A);
    const incoming = phaseprintIdentityForFriendRequest({
      fromUserId: USER_ID,
      fromUsername: "counterpart-name",
      outgoing: false,
    }, ORIGIN_A);

    expect(resolvePhaseprintSeed(outgoing).kind).toBe("username");
    expect(resolvePhaseprintSeed(outgoing).canonical).not.toContain(USER_ID);
    expect(resolvePhaseprintSeed(incoming).kind).toBe("user-id");
  });
});

describe("UserAvatar", () => {
  let nextAvatarUrl = 0;
  beforeEach(() => {
    nextAvatarUrl = 0;
    vi.spyOn(URL, "createObjectURL").mockImplementation(() => `blob:https://veil.local/avatar-${++nextAvatarUrl}`);
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  });
  afterEach(() => {
    clearAvatarRegistry();
    vi.restoreAllMocks();
  });

  it("is decorative by default and labelled only when used standalone", () => {
    const { container } = render(() => (
      <>
        <UserAvatar identityKey={IDENTITY_KEY} size={32} />
        <UserAvatar identityKey={IDENTITY_KEY} size={32} label="Sable profile image" />
      </>
    ));

    expect(screen.getByRole("img", { name: "Sable profile image" })).toBeInTheDocument();
    expect(container.querySelector("[data-user-avatar][aria-hidden='true']")).toBeInTheDocument();
  });

  it("never exposes the raw identity seed and ignores nickname-only rerenders", () => {
    const [nickname, setNickname] = createSignal("Sable");
    const { container } = render(() => (
      <div>
        <UserAvatar
          identityKey={IDENTITY_KEY}
          canonicalServerOrigin={ORIGIN_A}
          userId={USER_ID}
          technicalUsername="technical-sable"
          size={36}
        />
        <span>{nickname()}</span>
        <button type="button" onClick={() => setNickname("Night Sable")}>Rename</button>
      </div>
    ));
    const phaseprint = container.querySelector("[data-phaseprint]")!;
    const before = phaseprint.innerHTML;

    fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    expect(screen.getByText("Night Sable")).toBeInTheDocument();
    expect(phaseprint.innerHTML).toBe(before);
    expect(container.innerHTML).not.toContain(IDENTITY_KEY);
    expect(container.innerHTML).not.toContain(USER_ID);
    expect(container.innerHTML).not.toContain("technical-sable");
    expect(container.innerHTML).not.toContain("505ea8c981828b4817ea1321992c7936");
  });

  it("never renders an avatar registered for a different exact identity", () => {
    installNativeAvatar({
      identityKey: IDENTITY_KEY,
      canonicalServerOrigin: ORIGIN_A,
      userId: USER_ID,
    }, "550e8400-e29b-41d4-a716-446655440001", "/9j/2Q==");
    const { container } = render(() => (
      <UserAvatar
        identityKey={"42".repeat(32)}
        canonicalServerOrigin={ORIGIN_A}
        userId={USER_ID}
      />
    ));
    expect(container.querySelector("img")).not.toBeInTheDocument();
    expect(container.querySelector("[data-phaseprint]")).toBeInTheDocument();
  });

  it("keeps Phaseprint visible until a local blob decodes and restores it on failure", () => {
    installNativeAvatar({
      identityKey: IDENTITY_KEY,
      canonicalServerOrigin: ORIGIN_A,
      userId: USER_ID,
    }, "550e8400-e29b-41d4-a716-446655440001", "/9j/2Q==");
    const { container } = render(() => (
      <UserAvatar
        identityKey={IDENTITY_KEY}
        canonicalServerOrigin={ORIGIN_A}
        userId={USER_ID}
      />
    ));
    const avatar = container.querySelector("[data-user-avatar]")!;
    const image = container.querySelector("img")!;

    expect(avatar).toHaveAttribute("data-avatar-source", "phaseprint");
    expect(container.querySelector("[data-phaseprint]")).toBeInTheDocument();
    expect(image).toHaveStyle({ opacity: "0" });

    fireEvent.load(image);
    expect(avatar).toHaveAttribute("data-avatar-source", "local-image");
    expect(image).toHaveStyle({ opacity: "1" });

    fireEvent.error(image);
    expect(avatar).toHaveAttribute("data-avatar-source", "phaseprint");
    expect(container.querySelector("img")).not.toBeInTheDocument();
    expect(container.querySelector("[data-phaseprint]")).toBeInTheDocument();
  });

  it("resets image readiness for a replacement blob and falls back on abort", () => {
    const avatarIdentity = {
      identityKey: IDENTITY_KEY,
      canonicalServerOrigin: ORIGIN_A,
      userId: USER_ID,
    };
    installNativeAvatar(avatarIdentity, "550e8400-e29b-41d4-a716-446655440001", "/9j/2Q==");
    const { container } = render(() => (
      <UserAvatar {...avatarIdentity} />
    ));
    const avatar = container.querySelector("[data-user-avatar]")!;
    const firstImage = container.querySelector("img")!;
    fireEvent.load(firstImage);
    expect(avatar).toHaveAttribute("data-avatar-source", "local-image");

    installNativeAvatar(avatarIdentity, "550e8400-e29b-41d4-a716-446655440002", "/9j/2Q==");
    const replacementImage = container.querySelector("img")!;
    expect(replacementImage).toHaveAttribute("src", "blob:https://veil.local/avatar-2");
    expect(replacementImage).toHaveStyle({ opacity: "0" });
    expect(avatar).toHaveAttribute("data-avatar-source", "phaseprint");

    fireEvent.load(firstImage);
    expect(avatar).toHaveAttribute("data-avatar-source", "phaseprint");
    fireEvent.load(replacementImage);
    expect(avatar).toHaveAttribute("data-avatar-source", "local-image");
    fireEvent.error(firstImage);
    expect(avatar).toHaveAttribute("data-avatar-source", "local-image");

    fireEvent.abort(replacementImage);
    expect(container.querySelector("img")).not.toBeInTheDocument();
    expect(avatar).toHaveAttribute("data-avatar-source", "phaseprint");

    installNativeAvatar(avatarIdentity, "550e8400-e29b-41d4-a716-446655440003", "/9j/2Q==");
    const remountedFirstSource = container.querySelector("img")!;
    expect(remountedFirstSource).toHaveAttribute("src", "blob:https://veil.local/avatar-3");
    fireEvent.load(replacementImage);
    expect(avatar).toHaveAttribute("data-avatar-source", "phaseprint");
    fireEvent.load(remountedFirstSource);
    expect(avatar).toHaveAttribute("data-avatar-source", "local-image");
    fireEvent.error(replacementImage);
    expect(avatar).toHaveAttribute("data-avatar-source", "local-image");
  });
});
