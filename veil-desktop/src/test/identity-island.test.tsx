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
  identityProfileMatchesAuthenticatedOrigin,
  identityProofState,
  identityVerificationMatchesProfile,
  IDENTITY_ROLE_PRESENTATION_BUDGET,
  isSameCanonicalIdentity,
  messageAuthorContextLabel,
  mergeIdentityProofState,
  type IdentityIslandProfile,
} from "@/components/identity/identityProfile";
import { RightIsland, type RightIslandView } from "@/components/layout/RightIsland";
import type { GroupMember, IdentityVerificationView } from "@/stores/app";

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
    expect(screen.getByText(ORIGIN)).toBeInTheDocument();
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

  it("keeps exact origin schemes visible and contains hostile bounded profile text", () => {
    const longUsername = "u".repeat(96);
    const longAbout = "a".repeat(280);
    render(() => (
      <IdentityIslandContent
        profile={{
          ...completeProfile,
          canonicalServerOrigin: "http://127.0.0.1:443",
          technicalUsername: longUsername,
          displayName: "Local account",
          about: longAbout,
        }}
        canMessage={false}
        onMessage={vi.fn()}
      />
    ));

    expect(screen.getByText("http://127.0.0.1:443")).toBeInTheDocument();
    const username = screen.getByText(`@${longUsername}`);
    expect(username).toHaveStyle({
      maxWidth: "100%",
      overflow: "hidden",
      textOverflow: "ellipsis",
      whiteSpace: "nowrap",
    });
    expect(screen.getByText(longAbout)).toHaveStyle({
      overflowWrap: "anywhere",
      wordBreak: "break-word",
      maxWidth: "100%",
    });
  });

  it("shows bounded network profile text and truthful device-local proof states", () => {
    const [profile, setProfile] = createSignal<IdentityIslandProfile>({
      ...completeProfile,
      about: "Quietly building secure things.",
      profileVersion: "9223372036854775807",
      localProofState: "verified_on_this_device",
    });
    render(() => (
      <IdentityIslandContent
        profile={profile()}
        canMessage={false}
        profileLoading={false}
        onMessage={vi.fn()}
      />
    ));

    expect(screen.getByText("Quietly building secure things.")).toBeInTheDocument();
    expect(screen.getByText("Verified on this device")).toBeInTheDocument();
    expect(screen.getByText("9223372036854775807")).toBeInTheDocument();
    expect(identityProofState(profile())).toBe("verified-on-device");

    setProfile({ ...profile(), localProofState: "identity_changed" });
    expect(screen.getByText("Identity changed")).toBeInTheDocument();
    expect(screen.getByText(/blocking identity change/)).toBeInTheDocument();
    expect(identityProofState(profile())).toBe("identity-changed");
  });

  it("never lets a stale async proof downgrade an identity-change quarantine", () => {
    const quarantined = mergeIdentityProofState(completeProfile, "identity_changed");
    const staleVerified = mergeIdentityProofState(quarantined, "verified_on_this_device");
    const staleNotCompared = mergeIdentityProofState(staleVerified, "not_compared");

    expect(staleVerified).toBe(quarantined);
    expect(staleNotCompared).toBe(quarantined);
    expect(identityProofState(staleNotCompared)).toBe("identity-changed");
  });

  it("labels immutable historical author snapshots as former members", () => {
    expect(messageAuthorContextLabel("former_member_at_observation", false)).toBe("Former member");
    expect(messageAuthorContextLabel("directory_member_at_observation", false)).toBe("Message author");
    expect(messageAuthorContextLabel("former_member_at_observation", true)).toBe("Your message");
    expect(messageAuthorContextLabel("untrusted_value", false)).toBe("Message author");
  });

  it("never applies proof from another self-hosted origin with the same UUID and key", () => {
    const sameLocatorOtherOrigin = {
      canonicalServerOrigin: "https://other.example.test:443",
      userId: completeProfile.userId,
      identityKey: completeProfile.identityKey,
      signingKey: completeProfile.signingKey,
    };

    expect(identityProfileMatchesAuthenticatedOrigin(completeProfile, ORIGIN)).toBe(true);
    expect(identityProfileMatchesAuthenticatedOrigin(
      completeProfile,
      sameLocatorOtherOrigin.canonicalServerOrigin,
    )).toBe(false);
    expect(identityVerificationMatchesProfile(sameLocatorOtherOrigin, completeProfile)).toBe(false);
    expect(identityVerificationMatchesProfile({
      canonicalServerOrigin: ORIGIN,
      userId: completeProfile.userId,
      identityKey: completeProfile.identityKey,
      signingKey: completeProfile.signingKey,
    }, completeProfile)).toBe(true);
    expect(identityVerificationMatchesProfile({
      canonicalServerOrigin: ORIGIN,
      userId: completeProfile.userId,
      identityKey: completeProfile.identityKey,
      signingKey: "99".repeat(32),
    }, completeProfile)).toBe(false);
  });

  it("keeps retained identity visible while live profile refresh fails", () => {
    render(() => (
      <IdentityIslandContent
        profile={completeProfile}
        canMessage={false}
        profileError="Live profile unavailable. Retained identity data is still shown."
        onMessage={vi.fn()}
      />
    ));

    expect(screen.getByText("Quiet Orbit")).toBeInTheDocument();
    expect(screen.getByText(/Live profile unavailable/).closest('[role="status"]')).toBeInTheDocument();
  });

  it("edits only the current account and keeps unsafe drafts local", async () => {
    const saveProfile = vi.fn().mockResolvedValue(true);
    const user = userEvent.setup();
    render(() => (
      <IdentityIslandContent
        profile={{
          ...completeProfile,
          selfIdentity: completeProfile,
          networkDisplayName: "Quiet Orbit",
          about: "Original",
          profileVersion: "7",
        }}
        canMessage={false}
        onMessage={vi.fn()}
        onSaveProfile={saveProfile}
      />
    ));

    await user.click(screen.getByRole("button", { name: "Edit profile" }));
    expect(screen.getByRole("note")).toHaveTextContent(/visible to this server.*not end-to-end encrypted/i);
    const displayName = screen.getByLabelText("Display name");
    const about = screen.getByLabelText("About");
    await user.clear(displayName);
    await user.type(displayName, "New Orbit");
    await user.clear(about);
    fireEvent.input(about, { target: { value: "safe\u202eevil" } });
    await user.click(screen.getByRole("button", { name: "Save profile" }));

    expect(screen.getByRole("alert")).toHaveTextContent("unsafe controls");
    expect(saveProfile).not.toHaveBeenCalled();

    fireEvent.input(about, { target: { value: "safe\u200bhidden" } });
    await user.click(screen.getByRole("button", { name: "Save profile" }));
    expect(screen.getByRole("alert")).toHaveTextContent("unsafe controls");
    expect(saveProfile).not.toHaveBeenCalled();

    await user.clear(about);
    await user.type(about, "Updated profile");
    await user.click(screen.getByRole("button", { name: "Save profile" }));
    expect(saveProfile).toHaveBeenCalledWith("New Orbit", "Updated profile", "7");
  });

  it("expands the remaining avatar action and restores focus after removal", async () => {
    const [profile, setProfile] = createSignal<IdentityIslandProfile>({
      ...completeProfile,
      selfIdentity: completeProfile,
      profileVersion: "7",
      avatarAssetId: "avatar-asset-7",
    });
    const removeAvatar = vi.fn(async () => {
      setProfile({ ...profile(), avatarAssetId: null });
      return true;
    });
    const user = userEvent.setup();
    render(() => (
      <IdentityIslandContent
        profile={profile()}
        canMessage={false}
        onMessage={vi.fn()}
        onChangeAvatar={vi.fn().mockResolvedValue(true)}
        onRemoveAvatar={removeAvatar}
      />
    ));

    const changeAvatar = screen.getByRole("button", { name: "Change avatar" });
    expect(changeAvatar.closest(".veil-identity-avatar-actions")?.children).toHaveLength(2);

    await user.click(screen.getByRole("button", { name: "Remove" }));

    await waitFor(() => expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument());
    expect(removeAvatar).toHaveBeenCalledOnce();
    expect(changeAvatar.closest(".veil-identity-avatar-actions")?.children).toHaveLength(1);
    await waitFor(() => expect(changeAvatar).toHaveFocus());
  });

  it("does not steal focus after a delayed avatar removal", async () => {
    const [profile, setProfile] = createSignal<IdentityIslandProfile>({
      ...completeProfile,
      selfIdentity: completeProfile,
      profileVersion: "7",
      avatarAssetId: "avatar-asset-7",
    });
    let finishRemoval: (() => void) | undefined;
    const removeAvatar = vi.fn(() => new Promise<boolean>((resolve) => {
      finishRemoval = () => {
        setProfile({ ...profile(), avatarAssetId: null });
        resolve(true);
      };
    }));
    const user = userEvent.setup();
    render(() => (
      <div>
        <button type="button">Outside action</button>
        <IdentityIslandContent
          profile={profile()}
          canMessage={false}
          onMessage={vi.fn()}
          onChangeAvatar={vi.fn().mockResolvedValue(true)}
          onRemoveAvatar={removeAvatar}
        />
      </div>
    ));

    await user.click(screen.getByRole("button", { name: "Remove" }));
    const outsideAction = screen.getByRole("button", { name: "Outside action" });
    await user.click(outsideAction);
    expect(outsideAction).toHaveFocus();

    finishRemoval?.();
    await waitFor(() => expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument());
    expect(outsideAction).toHaveFocus();
  });

  it("releases avatar focus listeners as soon as focus ownership moves", async () => {
    const addListener = vi.spyOn(document, "addEventListener");
    const removeListener = vi.spyOn(document, "removeEventListener");
    const removeAvatar = vi.fn(() => new Promise<boolean>(() => undefined));
    const user = userEvent.setup();
    render(() => (
      <div>
        <button type="button">Outside action</button>
        <IdentityIslandContent
          profile={{
            ...completeProfile,
            selfIdentity: completeProfile,
            profileVersion: "7",
            avatarAssetId: "avatar-asset-7",
          }}
          canMessage={false}
          onMessage={vi.fn()}
          onChangeAvatar={vi.fn().mockResolvedValue(true)}
          onRemoveAvatar={removeAvatar}
        />
      </div>
    ));

    try {
      await user.click(screen.getByRole("button", { name: "Remove" }));
      const focusListener = addListener.mock.calls.find(([type]) => type === "focusin")?.[1];
      const pointerListener = addListener.mock.calls.find(([type]) => type === "pointerdown")?.[1];
      expect(focusListener).toBeTypeOf("function");
      expect(pointerListener).toBeTypeOf("function");

      removeListener.mockClear();
      await user.click(screen.getByRole("button", { name: "Outside action" }));

      expect(removeListener).toHaveBeenCalledWith("focusin", focusListener);
      expect(removeListener).toHaveBeenCalledWith("pointerdown", pointerListener);
    } finally {
      addListener.mockRestore();
      removeListener.mockRestore();
    }
  });

  it("releases avatar focus listeners when removal IPC never settles and the island unmounts", async () => {
    const addListener = vi.spyOn(document, "addEventListener");
    const removeListener = vi.spyOn(document, "removeEventListener");
    const removeAvatar = vi.fn(() => new Promise<boolean>(() => undefined));
    const user = userEvent.setup();
    const view = render(() => (
      <IdentityIslandContent
        profile={{
          ...completeProfile,
          selfIdentity: completeProfile,
          profileVersion: "7",
          avatarAssetId: "avatar-asset-7",
        }}
        canMessage={false}
        onMessage={vi.fn()}
        onChangeAvatar={vi.fn().mockResolvedValue(true)}
        onRemoveAvatar={removeAvatar}
      />
    ));

    await user.click(screen.getByRole("button", { name: "Remove" }));
    const focusListener = addListener.mock.calls.find(([type]) => type === "focusin")?.[1];
    const pointerListener = addListener.mock.calls.find(([type]) => type === "pointerdown")?.[1];
    expect(focusListener).toBeTypeOf("function");
    expect(pointerListener).toBeTypeOf("function");

    view.unmount();

    expect(removeListener).toHaveBeenCalledWith("focusin", focusListener);
    expect(removeListener).toHaveBeenCalledWith("pointerdown", pointerListener);
    addListener.mockRestore();
    removeListener.mockRestore();
  });

  it("requires a deliberate full-fingerprint comparison before local verification", async () => {
    const fingerprintHex = "51".repeat(32);
    const loaded: IdentityVerificationView = {
      canonicalServerOrigin: ORIGIN,
      userId: USER_ID,
      identityKey: IDENTITY_KEY,
      signingKey: "42".repeat(32),
      fingerprintVersion: "account_v2",
      fingerprintHex,
      fingerprintEmoji: "🔒".repeat(32),
      proofState: "not_compared",
    };
    const [verification, setVerification] = createSignal<IdentityVerificationView | null>(null);
    const load = vi.fn(async () => {
      setVerification(loaded);
      return loaded;
    });
    const confirm = vi.fn().mockResolvedValue(true);
    const user = userEvent.setup();
    render(() => (
      <IdentityIslandContent
        profile={completeProfile}
        canMessage={false}
        verification={verification()}
        onMessage={vi.fn()}
        onLoadVerification={load}
        onConfirmVerification={confirm}
      />
    ));

    expect(screen.queryByText(/Compare the entire fingerprint/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Compare identity" }));
    expect(load).toHaveBeenCalledOnce();
    expect(screen.getByText(/Account fingerprint v2 binds this server origin/)).toBeInTheDocument();
    expect(screen.getByText(/Compare the entire fingerprint/)).toBeInTheDocument();
    expect(screen.getByText(/5151 5151 5151/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "I compared this exact fingerprint" }));
    expect(confirm).toHaveBeenCalledWith(fingerprintHex);
  });

  it("keeps a quarantined identity change blocking and non-dismissible", () => {
    const confirm = vi.fn();
    const changed: IdentityVerificationView = {
      canonicalServerOrigin: ORIGIN,
      userId: USER_ID,
      identityKey: IDENTITY_KEY,
      signingKey: "42".repeat(32),
      fingerprintVersion: "account_v2",
      fingerprintHex: "61".repeat(32),
      fingerprintEmoji: "⚠️".repeat(16),
      proofState: "identity_changed",
    };
    render(() => (
      <IdentityIslandContent
        profile={{ ...completeProfile, localProofState: "identity_changed" }}
        canMessage={false}
        verification={changed}
        onMessage={vi.fn()}
        onConfirmVerification={confirm}
      />
    ));

    expect(screen.getByText("Identity changed")).toBeInTheDocument();
    expect(screen.getByText(/different encryption or signing key/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "I compared this exact fingerprint" })).not.toBeInTheDocument();
    expect(confirm).not.toHaveBeenCalled();
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
    let focusDuringIdentityHandoff: Element | null = null;
    let focusDuringMembersHandoff: Element | null = null;
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
        onOpenIdentity={(next) => {
          focusDuringIdentityHandoff = document.activeElement;
          setProfile(next);
          setView("identity");
        }}
        onBackToMembers={() => {
          focusDuringMembersHandoff = document.activeElement;
          setView("members");
        }}
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

    await waitFor(() => expect(focusDuringIdentityHandoff).toBe(island));
    expect(screen.getByRole("complementary", { name: "Identity" })).toBe(island);
    expect(screen.getByText("Not compared")).toBeInTheDocument();
    const back = screen.getByRole("button", { name: "Back to Members" });
    await waitFor(() => expect(back).toHaveFocus());
    await userEvent.setup().click(back);

    expect(focusDuringMembersHandoff).toBe(island);
    expect(screen.getByRole("complementary", { name: "Conversation members" })).toBe(island);
    const restoredTrigger = screen.getByRole("button", { name: "View identity for quiet-comet" });
    expect(restoredTrigger).toBe(memberTrigger);
    await waitFor(() => expect(restoredTrigger).toHaveFocus());
    expect(container.querySelectorAll("[data-user-avatar]")).toHaveLength(2);
  });

  it("falls back to the Members header when the selected member disappears", async () => {
    const [view, setView] = createSignal<RightIslandView>("members");
    const [members, setMembers] = createSignal<readonly GroupMember[]>([member]);
    const [profile, setProfile] = createSignal<IdentityIslandProfile | null>(null);
    const noop = vi.fn();
    render(() => (
      <RightIsland
        present
        open
        visible
        view={view()}
        identityProfile={profile()}
        identityBackToMembers={view() === "identity"}
        identityCanMessage={false}
        identityMessageBusy={false}
        serverId={null}
        canonicalServerOrigin={ORIGIN}
        currentUserId={SELF_ID}
        serverMembers={[]}
        serverRoles={[]}
        groupMembers={members()}
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

    await userEvent.setup().click(screen.getByRole("button", { name: "View identity for quiet-orbit" }));
    const back = screen.getByRole("button", { name: "Back to Members" });
    await waitFor(() => expect(back).toHaveFocus());
    setMembers([]);
    expect(screen.queryByRole("button", { name: "View identity for quiet-orbit" })).not.toBeInTheDocument();

    await userEvent.setup().click(back);
    await waitFor(() => expect(screen.getByRole("button", { name: "Close Members — 0" })).toHaveFocus());
  });

  it("focuses Close for a standalone wide Identity view and closes it with unhandled Escape", async () => {
    const [open, setOpen] = createSignal(true);
    const [returnTarget, setReturnTarget] = createSignal<HTMLButtonElement | null>(null);
    const close = vi.fn(() => {
      expect(returnTarget()).toHaveFocus();
      setOpen(false);
    });
    const noop = vi.fn();
    render(() => (
      <>
        <button ref={setReturnTarget} type="button">Return to chat</button>
        <RightIsland
          present={open()}
          open={open()}
          visible
          view="identity"
          identityProfile={completeProfile}
          identityBackToMembers={false}
          identityCanMessage={false}
          identityMessageBusy={false}
          returnFocusTo={returnTarget()}
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
      </>
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
    expect(screen.getByRole("button", { name: "Return to chat" })).toHaveFocus();
  });

  it("blurs the wide island when a connected inert return target rejects focus", async () => {
    const [open, setOpen] = createSignal(true);
    const [returnTarget, setReturnTarget] = createSignal<HTMLButtonElement | null>(null);
    let activeDuringClose: Element | null = null;
    const noop = vi.fn();
    render(() => (
      <>
        <div inert><button ref={setReturnTarget} type="button">Inert member trigger</button></div>
        <RightIsland
          present={open()}
          open={open()}
          visible
          view="identity"
          identityProfile={completeProfile}
          identityBackToMembers={false}
          identityCanMessage={false}
          identityMessageBusy={false}
          returnFocusTo={returnTarget()}
          serverId={null}
          canonicalServerOrigin={ORIGIN}
          currentUserId={SELF_ID}
          serverMembers={[]}
          serverRoles={[]}
          groupMembers={[]}
          onOpenIdentity={noop}
          onBackToMembers={noop}
          onClose={() => {
            activeDuringClose = document.activeElement;
            setOpen(false);
          }}
          onMessageIdentity={noop}
          onCreateDm={noop}
          onAssignRole={noop}
          onUnassignRole={noop}
          onKickMember={noop}
          onInviteMember={noop}
        />
      </>
    ));

    const island = screen.getByRole("complementary", { name: "Identity" });
    const closeButton = screen.getByRole("button", { name: "Close Identity" });
    await waitFor(() => expect(closeButton).toHaveFocus());
    const blockedTarget = returnTarget()!;
    vi.spyOn(blockedTarget, "focus").mockImplementation(() => undefined);

    fireEvent.keyDown(island, { key: "Escape" });
    expect(blockedTarget.focus).toHaveBeenCalledOnce();
    expect(activeDuringClose).toBe(document.body);
    expect(blockedTarget).not.toHaveFocus();
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
