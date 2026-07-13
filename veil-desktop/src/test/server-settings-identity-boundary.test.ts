import { describe, expect, it } from "vitest";

const serverSettingsModules = import.meta.glob("../components/server/ServerSettingsScreen.tsx", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const source = Object.values(serverSettingsModules)[0];

function section(start: string, end: string): string {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  expect(startIndex, `missing section start: ${start}`).toBeGreaterThanOrEqual(0);
  expect(endIndex, `missing section end: ${end}`).toBeGreaterThan(startIndex);
  return source.slice(startIndex, endIndex);
}

describe("server-settings Identity Island boundary", () => {
  it("defers settings Escape until the topmost Kobalte layer has handled it", () => {
    const escapeFlow = section(
      "const handleKey = (e: KeyboardEvent) => {",
      "const copyText = async",
    );

    expect(escapeFlow).toContain("queueMicrotask(() => {");
    expect(escapeFlow).toContain("if (!e.defaultPrevented) goBack()");
    expect(escapeFlow).not.toContain("stopImmediatePropagation");
    expect(escapeFlow).not.toContain("closeSelectedIdentity()");
  });

  it("uses an exact authenticated self locator and no configured-origin fallback", () => {
    const selfFlow = section(
      "const authenticatedIdentityLocator = () => {",
      "const selectedIdentityDmState = createMemo",
    );

    expect(selfFlow).toContain("canonicalIdentityOrigin(scope?.canonicalServerOrigin)");
    expect(selfFlow).toContain("canonicalIdentityUserId(scope?.userId)");
    expect(selfFlow).toContain("canonicalIdentityKey(appStore.identity())");
    expect(selfFlow).toContain("canonicalIdentityKey(identityKey) === current.identityKey");
    expect(source).not.toContain("canonicalServerOriginFromHttpUrl");
  });

  it("opens only an exact local DM offline and binds creation to the shown key", () => {
    const dmFlow = section(
      "const selectedIdentityDmState = createMemo",
      "const visibleMembers = createMemo",
    );

    for (const locatorCoordinate of [
      "canonicalIdentityOrigin(conversation.serverOrigin) === targetOrigin",
      "canonicalIdentityUserId(conversation.peerUserId) === targetUserId",
      "canonicalIdentityKey(conversation.peerKey) === targetIdentityKey",
    ]) {
      expect(dmFlow).toContain(locatorCoordinate);
    }
    expect(dmFlow).toContain("currentAccountConflict");
    expect(dmFlow).toContain("localConversationId: !blocked");
    expect(dmFlow.indexOf("if (dmState.localConversationId)"))
      .toBeLessThan(dmFlow.indexOf("appStore.createDm("));
    expect(dmFlow).toContain("appStore.connected()");
    expect(dmFlow).toContain("!appStore.bindingTransitioning()");
    expect(dmFlow).toContain("!appStore.originTransitioning()");
    expect(dmFlow).toContain("dmState.targetIdentityKey,");
  });

  it("guards late DM completion by token, session, and selected profile", () => {
    const messageFlow = section(
      "const messageSelectedIdentity = async () => {",
      "const visibleMembers = createMemo",
    );

    expect(messageFlow).toContain("const actionToken = ++identityMessageActionToken");
    expect(messageFlow).toContain("const sessionEpoch = captureUiSessionEpoch()");
    expect(messageFlow).toContain("identityMessageActionToken === actionToken");
    expect(messageFlow).toContain("isUiSessionEpochCurrent(sessionEpoch)");
    expect(messageFlow).toContain("identityProfileKey(currentProfile) === profileKey");
    expect(messageFlow.match(/if \(!actionIsCurrent\(\)\) return;/g)).toHaveLength(2);
    expect(messageFlow).toContain(
      "if (identityMessageActionToken === actionToken) setIdentityMessageBusy(false)",
    );
  });

  it("uses the same durable proof and quarantine boundary inside settings", () => {
    const proofFlow = section(
      "const hydrateSelectedIdentityProof = async",
      "const selectedIdentityDmState = createMemo",
    );

    expect(proofFlow).toContain("appStore.loadCachedIdentityVerification(");
    expect(proofFlow).toContain("appStore.loadIdentityVerification(");
    expect(proofFlow).toContain("appStore.confirmIdentityVerification(");
    expect(proofFlow).toContain("const sessionEpoch = captureUiSessionEpoch()");
    expect(proofFlow).toContain("isUiSessionEpochCurrent(sessionEpoch)");
    expect(proofFlow).toContain("identityProfileKey(current) !== routeKey");
    expect(proofFlow).toContain("identityProfileMatchesAuthenticatedOrigin(profile, scope.canonicalServerOrigin)");
    expect(proofFlow).toContain("identityVerificationMatchesProfile(verification, current)");
    expect(proofFlow).toContain("identityVerificationMatchesProfile(displayed, profile)");
    expect(proofFlow).toContain("appStore.bindingTransitioning()");
    expect(proofFlow).toContain("appStore.originTransitioning()");
    expect(proofFlow).toContain("const notice = appStore.identityChangeNotice()");
    expect(proofFlow).toContain('mergeIdentityProofState(profile, "identity_changed")');
    expect(proofFlow).toContain("scope.bindingGeneration === lastIdentityProofBindingGeneration");
    expect(source).toContain("verification={identityVerification()}");
    expect(source).toContain("onLoadVerification={loadSelectedIdentityVerification}");
    expect(source).toContain("onConfirmVerification={confirmSelectedIdentityVerification}");
  });

  it("bounds identity role presentation without truncating authorization state", () => {
    expect(source).toContain("boundedIdentityRoles(source)");
    expect(source).toContain("new Set(boundedIdentityRoles(m.roleIds))");
    expect(source).toContain("<For each={assignableIdentityRoles()}>");
    expect(source).toContain("Manage remaining roles in the Roles tab.");
    expect(source).toContain("<For each={roles()}>");
  });
});
