import { fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import userEvent from "@testing-library/user-event";
import { createSignal } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IdentityIslandContent } from "@/components/identity/IdentityIsland";
import {
  boundedIdentityRoles,
  canMessageIdentity,
  canonicalIdentityOrigin,
  identityAllowsKeylessDmResolution,
  identityProofState,
  IDENTITY_ROLE_PRESENTATION_BUDGET,
  isSameCanonicalIdentity,
  type IdentityIslandProfile,
} from "@/components/identity/identityProfile";
import { RightIsland, type RightIslandView } from "@/components/layout/RightIsland";
import type { GroupMember } from "@/stores/app";

const ORIGIN = "https://identity.example.test:443";
const USER_ID = "550e8400-e29b-41d4-a716-446655440010";
const SELF_ID = "550e8400-e29b-41d4-a716-446655440011";
const IDENTITY_KEY = "41".repeat(32);

const completeProfile: IdentityIslandProfile = {
  canonicalServerOrigin: ORIGIN,
  userId: USER_ID,
  identityKey: IDENTITY_KEY,
  signingKey: "42".repeat(32),
  technicalUsername: "quiet-orbit",
  displayName: "Quiet Orbit",
  nickname: "Navigator",
  contextKind: "server-member",
  contextLabel: "Server member",
  contextDetail: "Server · Secure Lab",
  joinedAt: "2026-07-12T10:00:00Z",
  roles: [{ name: "Operator", color: "#34d399" }],
};

const originalMatchMedia = globalThis.matchMedia;

afterEach(() => {
  Object.defineProperty(globalThis, "matchMedia", {
    configurable: true,
    value: originalMatchMedia,
  });
});

function narrowMatchMedia(query: string): MediaQueryList {
  return {
    matches: query === "(max-width: 1080px)",
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  };
}

const member: GroupMember = {
  userId: USER_ID,
  identityKey: IDENTITY_KEY,
  username: "quiet-orbit",
  role: 0,
  joinedAt: "2026-07-12T10:00:00Z",
};

const secondMember: GroupMember = {
  userId: "550e8400-e29b-41d4-a716-446655440012",
  identityKey: "43".repeat(32),
  username: "quiet-comet",
  role: 0,
  joinedAt: "2026-07-12T10:05:00Z",
};

describe("Identity Island", () => {
  it("keeps TOFU explicit and presentation context outside proof", async () => {
    const message = vi.fn();
    const [profile, setProfile] = createSignal(completeProfile);
    const { container } = render(() => (
      <IdentityIslandContent
        profile={profile()}
        canMessage
        onMessage={message}
      />
    ));

    expect(screen.getByRole("heading", { name: "Person" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Context" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Identity Proof" })).toBeInTheDocument();
    expect(screen.getByText("Not compared")).toBeInTheDocument();
    expect(screen.getByText(/service-mediated TOFU/)).toBeInTheDocument();
    expect(screen.queryByText(/^Verified$/i)).not.toBeInTheDocument();
    expect(identityProofState(profile())).toBe("not-compared");
    expect(canMessageIdentity(profile(), ORIGIN, SELF_ID)).toBe(true);
    expect(canMessageIdentity(profile(), "https://other.example.test:443", SELF_ID)).toBe(false);

    const phaseprint = container.querySelector("[data-phaseprint]")!;
    const vector = phaseprint.innerHTML;
    setProfile({ ...profile(), nickname: "Changed nickname", roles: [{ name: "Changed role" }] });
    expect(container.querySelector("[data-phaseprint]")).toBe(phaseprint);
    expect(phaseprint.innerHTML).toBe(vector);

    await userEvent.setup().click(screen.getByRole("button", { name: "Message" }));
    expect(message).toHaveBeenCalledOnce();
  });

  it("keeps incomplete account coordinates read-only and rejects insecure origins", () => {
    const incomplete: IdentityIslandProfile = {
      canonicalServerOrigin: ORIGIN,
      identityKey: IDENTITY_KEY,
      displayName: "Unresolved account",
      contextKind: "friend-request",
      contextLabel: "Outgoing friend request",
    };
    render(() => (
      <IdentityIslandContent
        profile={{ ...incomplete, selfIdentity: incomplete }}
        canMessage={false}
        onMessage={vi.fn()}
      />
    ));

    expect(screen.getByText("Identity unavailable")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copy identity key" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Message" })).toBeDisabled();
    expect(canMessageIdentity(incomplete, ORIGIN, SELF_ID)).toBe(false);
    expect(canonicalIdentityOrigin("http://remote.example.test:80")).toBeNull();
    expect(canonicalIdentityOrigin("http://127.0.0.1:9080")).toBe("http://127.0.0.1:9080");
    expect(identityProofState({ ...incomplete, selfIdentity: incomplete })).toBe("unavailable");
    expect(identityProofState({ ...completeProfile, selfIdentity: completeProfile })).toBe("self");
    expect(isSameCanonicalIdentity(completeProfile, { ...completeProfile })).toBe(true);
    expect(isSameCanonicalIdentity(completeProfile, {
      ...completeProfile,
      canonicalServerOrigin: "https://other.example.test:443",
    })).toBe(false);
    expect(identityAllowsKeylessDmResolution({
      ...incomplete,
      identityKey: undefined,
      contextKind: "friend",
    })).toBe(true);
    expect(identityAllowsKeylessDmResolution({
      ...incomplete,
      identityKey: "invalid",
      contextKind: "friend",
    })).toBe(false);
    expect(identityAllowsKeylessDmResolution({
      ...incomplete,
      identityKey: undefined,
      contextKind: "server-member",
    })).toBe(false);
  });

  it("morphs one wide island Members to Identity and restores the exact context-menu trigger", async () => {
    const [view, setView] = createSignal<RightIslandView>("members");
    const [profile, setProfile] = createSignal<IdentityIslandProfile | null>(null);
    const noop = vi.fn();
    const { container } = render(() => (
      <RightIsland
        present
        open
        visible
        view={view()}
        identityProfile={view() === "identity" ? profile() : null}
        identityBackToMembers={view() === "identity"}
        identityCanMessage={false}
        identityMessageBusy={false}
        serverId={null}
        contextName="Secure Lab"
        canonicalServerOrigin={ORIGIN}
        currentUserId={SELF_ID}
        serverMembers={[]}
        serverRoles={[]}
        groupMembers={[member, secondMember]}
        onOpenIdentity={(next) => { setProfile(next); setView("identity"); }}
        onBackToMembers={() => setView("members")}
        onClose={noop}
        onMessageIdentity={noop}
        onCreateDm={noop}
        onAssignRole={noop}
        onUnassignRole={noop}
        onKickMember={noop}
        onInviteMember={noop}
      />
    ));

    const island = screen.getByRole("complementary", { name: "Conversation members" });
    const memberTrigger = screen.getByRole("button", { name: "View identity for quiet-comet" });
    fireEvent.contextMenu(memberTrigger);
    await userEvent.setup().click(await screen.findByRole("menuitem", { name: "View Identity" }));

    expect(screen.getByRole("complementary", { name: "Identity" })).toBe(island);
    expect(screen.getByText("Not compared")).toBeInTheDocument();
    const back = screen.getByRole("button", { name: "Back to Members" });
    await waitFor(() => expect(back).toHaveFocus());
    await userEvent.setup().click(back);

    expect(screen.getByRole("complementary", { name: "Conversation members" })).toBe(island);
    const restoredTrigger = screen.getByRole("button", { name: "View identity for quiet-comet" });
    expect(restoredTrigger).toBe(memberTrigger);
    await waitFor(() => expect(restoredTrigger).toHaveFocus());
    expect(container.querySelectorAll("[data-user-avatar]")).toHaveLength(2);
  });

  it("focuses Close for a standalone wide Identity view and closes it with unhandled Escape", async () => {
    const [open, setOpen] = createSignal(true);
    const close = vi.fn(() => setOpen(false));
    const noop = vi.fn();
    render(() => (
      <RightIsland
        present={open()}
        open={open()}
        visible
        view="identity"
        identityProfile={completeProfile}
        identityBackToMembers={false}
        identityCanMessage={false}
        identityMessageBusy={false}
        serverId={null}
        canonicalServerOrigin={ORIGIN}
        currentUserId={SELF_ID}
        serverMembers={[]}
        serverRoles={[]}
        groupMembers={[]}
        onOpenIdentity={noop}
        onBackToMembers={noop}
        onClose={close}
        onMessageIdentity={noop}
        onCreateDm={noop}
        onAssignRole={noop}
        onUnassignRole={noop}
        onKickMember={noop}
        onInviteMember={noop}
      />
    ));

    const island = screen.getByRole("complementary", { name: "Identity" });
    const closeButton = screen.getByRole("button", { name: "Close Identity" });
    await waitFor(() => expect(closeButton).toHaveFocus());

    const handled = new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
    handled.preventDefault();
    closeButton.dispatchEvent(handled);
    expect(close).not.toHaveBeenCalled();

    fireEvent.keyDown(island, { key: "Escape" });
    expect(close).toHaveBeenCalledOnce();
  });

  it("retains bounded member rows for the non-interactive exit animation", async () => {
    const [open, setOpen] = createSignal(true);
    const [present, setPresent] = createSignal(true);
    const noop = vi.fn();
    const { container } = render(() => (
      <RightIsland
        present={present()}
        open={open()}
        visible={open()}
        view="members"
        identityProfile={null}
        identityBackToMembers={false}
        identityCanMessage={false}
        identityMessageBusy={false}
        serverId={null}
        canonicalServerOrigin={ORIGIN}
        currentUserId={SELF_ID}
        serverMembers={[]}
        serverRoles={[]}
        groupMembers={[member]}
        onOpenIdentity={noop}
        onBackToMembers={noop}
        onClose={() => setOpen(false)}
        onMessageIdentity={noop}
        onCreateDm={noop}
        onAssignRole={noop}
        onUnassignRole={noop}
        onKickMember={noop}
        onInviteMember={noop}
      />
    ));

    const trigger = container.querySelector("[data-identity-trigger='v1']");
    expect(trigger).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: /Close Members/ }));
    expect(container.querySelector("[data-identity-trigger='v1']")).toBe(trigger);

    setPresent(false);
    expect(container.querySelector("[data-identity-trigger='v1']")).toBeNull();
  });

  it("bounds contextual role presentation and reports omitted roles", () => {
    const roles = Array.from({ length: IDENTITY_ROLE_PRESENTATION_BUDGET + 10 }, (_, index) => ({
      name: `Role ${index + 1}`,
      color: "#34d399",
    }));
    expect(boundedIdentityRoles(roles)).toHaveLength(IDENTITY_ROLE_PRESENTATION_BUDGET);

    render(() => (
      <IdentityIslandContent
        profile={{ ...completeProfile, roles }}
        canMessage={false}
        onMessage={vi.fn()}
      />
    ));

    expect(screen.getByText(/Additional contextual roles/).closest('[role="status"]')).toBeInTheDocument();
    expect(screen.getByText("Role 1")).toBeInTheDocument();
    expect(screen.queryByText("Role 4")).not.toBeInTheDocument();
  });

  it("announces clipboard feedback and clears the previous feedback timer", async () => {
    const clipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, "clipboard");
    const writeText = vi.fn().mockResolvedValue(undefined);
    const clearTimeout = vi.spyOn(window, "clearTimeout");
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });

    try {
      const { unmount } = render(() => (
        <IdentityIslandContent profile={completeProfile} canMessage={false} onMessage={vi.fn()} />
      ));

      fireEvent.click(screen.getByRole("button", { name: "Copy account ID" }));
      const firstStatus = await screen.findByText("Account ID copied.");
      expect(firstStatus).toHaveAttribute("role", "status");
      expect(firstStatus).toHaveAttribute("aria-live", "polite");

      clearTimeout.mockClear();
      fireEvent.click(screen.getByRole("button", { name: "Copy identity key" }));
      await Promise.resolve();
      expect(screen.getByText("Identity key copied.")).toBeInTheDocument();
      expect(clearTimeout).toHaveBeenCalledTimes(1);

      clearTimeout.mockClear();
      unmount();
      expect(clearTimeout).toHaveBeenCalledTimes(1);
      expect(writeText).toHaveBeenNthCalledWith(1, USER_ID);
      expect(writeText).toHaveBeenNthCalledWith(2, IDENTITY_KEY);
    } finally {
      if (clipboardDescriptor) Object.defineProperty(navigator, "clipboard", clipboardDescriptor);
      else Reflect.deleteProperty(navigator, "clipboard");
    }
  });

  it("uses one focus-trapped narrow sheet and restores the external opener", async () => {
    Object.defineProperty(globalThis, "matchMedia", {
      configurable: true,
      value: narrowMatchMedia,
    });
    const [route, setRoute] = createSignal<"closed" | RightIslandView>("closed");
    const [profile, setProfile] = createSignal<IdentityIslandProfile | null>(null);
    const noop = vi.fn();
    const user = userEvent.setup();

    render(() => (
      <>
        <button type="button" onClick={() => setRoute("members")}>Open members</button>
        <RightIsland
          present={route() !== "closed"}
          open={route() !== "closed"}
          visible
          view={route() === "identity" ? "identity" : "members"}
          identityProfile={profile()}
          identityBackToMembers={route() === "identity"}
          identityCanMessage={false}
          identityMessageBusy={false}
          serverId={null}
          contextName="Secure Lab"
          canonicalServerOrigin={ORIGIN}
          currentUserId={SELF_ID}
          serverMembers={[]}
          serverRoles={[]}
          groupMembers={[member, secondMember]}
          onOpenIdentity={(next) => { setProfile(next); setRoute("identity"); }}
          onBackToMembers={() => setRoute("members")}
          onClose={() => setRoute("closed")}
          onMessageIdentity={noop}
          onCreateDm={noop}
          onAssignRole={noop}
          onUnassignRole={noop}
          onKickMember={noop}
          onInviteMember={noop}
        />
        <div id="island-portal" />
      </>
    ));

    const opener = screen.getByRole("button", { name: "Open members" });
    await user.click(opener);
    const dialog = await screen.findByRole("dialog", { name: /Members/ });
    const membersScroll = dialog.querySelector<HTMLElement>(".veil-right-island-scroll")!;
    membersScroll.scrollTop = 120;
    const selectedMember = screen.getByRole("button", { name: "View identity for quiet-comet" });
    await user.click(selectedMember);
    const identityDialog = await screen.findByRole("dialog", { name: "Identity" });
    expect(identityDialog).toBe(dialog);
    await waitFor(() => expect(screen.getByRole("button", { name: "Back to Members" })).toHaveFocus());

    await user.tab();
    expect(dialog.contains(document.activeElement)).toBe(true);
    await user.click(screen.getByRole("button", { name: "Back to Members" }));
    expect(await screen.findByRole("dialog", { name: /Members/ })).toBe(dialog);
    expect(screen.getByRole("button", { name: "View identity for quiet-comet" })).toBe(selectedMember);
    expect(membersScroll.scrollTop).toBe(120);
    await waitFor(() => expect(selectedMember).toHaveFocus());

    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await waitFor(() => expect(opener).toHaveFocus());
  });
});
