import { describe, expect, it } from "vitest";

const appModules = import.meta.glob("../App.tsx", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const appSource = Object.values(appModules)[0];

function section(start: string, end: string): string {
  const startIndex = appSource.indexOf(start);
  const endIndex = appSource.indexOf(end, startIndex + start.length);
  expect(startIndex, `missing section start: ${start}`).toBeGreaterThanOrEqual(0);
  expect(endIndex, `missing section end: ${end}`).toBeGreaterThan(startIndex);
  return appSource.slice(startIndex, endIndex);
}

describe("origin-local App cleanup", () => {
  it("scrubs plaintext, deferred drafts, busy state, and origin-owned overlays", () => {
    const cleanup = section(
      "const resetOriginLocalState = () => {",
      "// Store state is not the only place where plaintext lives.",
    );

    for (const required of [
      "activeSendToken = null",
      "setDeferredSendDrafts({})",
      'setInputText("")',
      'setSearch("")',
      'setNewGroupName("")',
      "setGroupMembers([])",
      "setReplyingTo(null)",
      "setEditingMessage(null)",
      'setEditText("")',
      "setCreatingGroup(false)",
      'setGroupCreateError("")',
      "setSendBusy(false)",
      "setDeletingIds(new Set<string>())",
      "closeRightIsland(true)",
      "setShowFriendsPanel(false)",
      "setShowNewGroup(false)",
      "setShowCreateServer(false)",
      "setShowSpaceCreateMenu(false)",
      "setShowCreateChannel(false)",
      "setShowCreateInvite(false)",
      "toast.clear()",
    ]) {
      expect(cleanup, `origin cleanup is missing ${required}`).toContain(required);
    }

    // Reusing a token while an older Promise is settling could let the old
    // completion release the next origin's busy state.
    expect(cleanup).not.toMatch(/sendTokenCounter\s*=/);
  });

  it("runs after every referenced signal is initialized and on lock or origin epoch change", () => {
    const cleanupIndex = appSource.indexOf("const resetOriginLocalState = () => {");
    expect(cleanupIndex).toBeGreaterThan(appSource.indexOf("let activeSendToken"));
    expect(cleanupIndex).toBeGreaterThan(appSource.indexOf("const [showCreateInvite"));

    const boundary = section(
      "let lastClearedOriginEpoch = appStore.originEpoch();",
      "// Collapsed category IDs",
    );
    expect(boundary).toContain("const currentOriginEpoch = appStore.originEpoch()");
    expect(boundary).toContain('const locked = appStore.screen() === "locked"');
    expect(boundary).toContain("resetOriginLocalState()");
  });

  it("prevents old create completions from releasing or repopulating new-origin state", () => {
    const groupFlow = section("const handleNewGroup = async () => {", "const restoreFailedDraft");
    expect(groupFlow).toContain("const sessionEpoch = captureUiSessionEpoch()");
    expect(groupFlow).toContain("if (!isUiSessionEpochCurrent(sessionEpoch)) return");
    expect(groupFlow).toContain("openConversation(conversationId)");
    expect(groupFlow).toContain(
      "if (isUiSessionEpochCurrent(sessionEpoch)) setCreatingGroup(false)",
    );
  });

  it("releases retired same-origin binding operations without deleting drafts", () => {
    const bindingCleanup = section(
      "if (!appStore.bindingTransitioning()) return;",
      "// Store state is not the only place where plaintext lives.",
    );
    expect(bindingCleanup).toContain("activeSendToken = null");
    expect(bindingCleanup).toContain("setSendBusy(false)");
    expect(bindingCleanup).toContain("setCreatingGroup(false)");
    expect(bindingCleanup).toContain("setDeletingIds(new Set<string>())");
    expect(bindingCleanup).toContain("closeRightIsland(true)");
    expect(bindingCleanup).not.toContain("setDeferredSendDrafts({})");
    expect(bindingCleanup).not.toContain('setInputText("")');
  });

  it("invalidates late Identity DM actions and binds creation to the displayed key", () => {
    const routeLifecycle = section(
      "const showRightIslandRoute =",
      "const conv = () => appStore.activeConversation();",
    );
    expect(routeLifecycle.match(/identityDmActionToken \+= 1/g)).toHaveLength(2);
    expect(routeLifecycle).toContain("const route = untrack(rightIslandRoute)");
    expect(routeLifecycle).toContain('if (untrack(rightIslandRoute).kind !== "closed")');
    expect(routeLifecycle).toContain("setIsland4Vis(false)");
    expect(routeLifecycle).toContain("prefers-reduced-motion: reduce");
    const closeFlow = section(
      "const closeRightIsland =",
      "const conv = () => appStore.activeConversation();",
    );
    expect(closeFlow).toContain("activeAtClose.blur()");
    expect(closeFlow.indexOf("opener.focus({ preventScroll: true })"))
      .toBeLessThan(closeFlow.indexOf("setIsland4Vis(false)"));

    const identityDmFlow = section(
      "const handleIdentityMessage = async () => {",
      "const handleRightIslandCreateDm = async",
    );
    expect(identityDmFlow).toContain("const actionToken = ++identityDmActionToken");
    expect(identityDmFlow).toContain("actionToken === identityDmActionToken");
    expect(identityDmFlow).toContain("isUiSessionEpochCurrent(sessionEpoch)");
    expect(identityDmFlow).toContain("identityProfileKey(currentRoute.profile) === profileKey");
    expect(identityDmFlow).toContain("identityAllowsKeylessDmResolution(profile)");
    expect(identityDmFlow).toContain("This identity-bearing context has no valid identity key");
    expect(identityDmFlow).toContain("targetIdentityKey || undefined");
    expect(identityDmFlow.indexOf("if (selectedIdentityCanOpenLocalDm())"))
      .toBeLessThan(identityDmFlow.indexOf("appStore.createDm("));
  });

  it("applies live profiles only to the exact still-open identity route", () => {
    const refreshFlow = section(
      "const refreshIdentityProfile = async",
      "const cancelRightIslandAnimationFrame =",
    );
    expect(refreshFlow).toContain("canonicalIdentityOrigin(profile.canonicalServerOrigin)");
    expect(refreshFlow).toContain("canonicalIdentityUserId(profile.userId)");
    expect(refreshFlow).toContain("canonicalIdentityKey(profile.identityKey)");
    expect(refreshFlow).toContain("targetOrigin !== canonicalIdentityOrigin(scope.canonicalServerOrigin)");
    expect(refreshFlow).toContain("const actionToken = ++identityProfileActionToken");
    expect(refreshFlow).toContain("actionToken === identityProfileActionToken");
    expect(refreshFlow).toContain("identityProfileKey(route.profile) === routeKey");
    expect(refreshFlow).toContain("Retained identity data is still shown");
  });

  it("keeps profile writes self-only and refreshes an explicit CAS conflict", () => {
    const saveFlow = section(
      "const saveIdentityProfile = async",
      "const cancelRightIslandAnimationFrame =",
    );
    expect(saveFlow).toContain("isSameCanonicalIdentity(route.profile, currentIdentityLocator())");
    expect(saveFlow).toContain("const saveToken = ++identityProfileSaveToken");
    expect(saveFlow).toContain("identityProfileKey(current.profile) === routeKey");
    expect(saveFlow).toContain("appStore.updateNetworkProfile(expectedVersion, displayName, about)");
    expect(saveFlow).toContain('includes("profile was updated elsewhere")');
    expect(saveFlow).toContain("await refreshIdentityProfile(current.profile)");
    expect(saveFlow).toContain("review before saving again");
  });

  it("refreshes only the open exact profile after a newer origin-scoped event", () => {
    const refreshEffect = section(
      "const notice = appStore.profileUpdateNotice()",
      "createEffect(() => {\n    const conversationId",
    );
    expect(refreshEffect).toContain("canonicalIdentityOrigin(route.profile.canonicalServerOrigin) !== notice.canonicalServerOrigin");
    expect(refreshEffect).toContain("canonicalIdentityUserId(route.profile.userId) !== notice.userId");
    expect(refreshEffect).toContain("BigInt(currentVersionText) >= BigInt(notice.profileVersion)");
    expect(refreshEffect).toContain("refreshIdentityProfile(route.profile)");
  });

  it("makes an authenticated identity-change notice monotonic across async responses", () => {
    const quarantineEffect = section(
      "const notice = appStore.identityChangeNotice()",
      "const notice = appStore.profileUpdateNotice()",
    );
    expect(quarantineEffect).toContain("identityProfileActionToken += 1");
    expect(quarantineEffect).toContain("identityVerificationActionToken += 1");
    expect(quarantineEffect).toContain('mergeIdentityProofState(current.profile, "identity_changed")');
    expect(quarantineEffect).toContain("hydrateLocalIdentityProof(route.profile)");
    expect(quarantineEffect).toContain("lastIdentityProofBindingGeneration");
    expect(quarantineEffect).toContain("scope.bindingGeneration === lastIdentityProofBindingGeneration");
  });

  it("binds physical verification to the exact displayed fingerprint and route", () => {
    const verificationFlow = section(
      "const loadSelectedIdentityVerification = async",
      "const cancelRightIslandAnimationFrame =",
    );
    expect(verificationFlow).toContain("isSameCanonicalIdentity(route.profile, currentIdentityLocator())");
    expect(verificationFlow).toContain("const actionToken = ++identityVerificationActionToken");
    expect(verificationFlow).toContain("identityProfileKey(current.profile) !== routeKey");
    expect(verificationFlow).toContain("identityProfileMatchesAuthenticatedOrigin(route.profile, scope.canonicalServerOrigin)");
    expect(verificationFlow).toContain("identityVerificationMatchesProfile(verification, current.profile)");
    expect(verificationFlow).toContain("identityVerificationMatchesProfile(displayed, route.profile)");
    expect(verificationFlow).toContain("appStore.bindingTransitioning()");
    expect(verificationFlow).toContain("appStore.originTransitioning()");
    expect(verificationFlow).toContain("displayed.fingerprintHex !== expectedFingerprintHex");
    expect(verificationFlow).toContain("appStore.confirmIdentityVerification(");
    expect(verificationFlow).toContain('verified.proofState === "verified_on_this_device"');
  });

  it("installs native event listeners before the first transport connect", () => {
    const boot = section("onMount(async () => {", "let stopWindowResizeListener");
    expect(boot.indexOf("await appStore.setupEventListeners()"))
      .toBeLessThan(boot.indexOf("appStore.connectToServer()"));
  });
});
