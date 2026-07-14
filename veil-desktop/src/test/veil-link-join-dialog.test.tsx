import { fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";

interface MockPendingVeilLink {
  flowId: string;
  canonicalOrigin: string;
  selectorRef: string;
  expiresInSeconds: number;
}

const harness = vi.hoisted(() => ({
  pending: (() => null) as () => MockPendingVeilLink | null,
  setPending: (() => undefined) as (value: MockPendingVeilLink | null) => void,
  sessionEpoch: 1,
}));

const previewInvite = vi.hoisted(() => vi.fn());
const useInvite = vi.hoisted(() => vi.fn());
const loadChannels = vi.hoisted(() => vi.fn(async () => undefined));
const loadServerMembers = vi.hoisted(() => vi.fn(async () => undefined));
const selectServer = vi.hoisted(() => vi.fn());
const cancelPendingVeilLink = vi.hoisted(() => vi.fn());

vi.mock("@/stores/app", async () => {
  const { createSignal } = await import("solid-js");
  const [pending, setPending] = createSignal<MockPendingVeilLink | null>(null);
  harness.pending = pending;
  harness.setPending = (value) => setPending(value);

  return {
    captureUiSessionEpoch: () => harness.sessionEpoch,
    isUiSessionEpochCurrent: (epoch: number) => epoch === harness.sessionEpoch,
    appStore: {
      pendingVeilLink: pending,
      authenticatedServerScope: () => ({ canonicalServerOrigin: "https://node.example.test:443" }),
      connected: () => true,
      bindingTransitioning: () => false,
      originTransitioning: () => false,
      identity: () => "11".repeat(32),
      userId: () => "550e8400-e29b-41d4-a716-446655440000",
      previewInvite,
      useInvite,
      loadChannels,
      loadServerMembers,
      selectServer,
      cancelPendingVeilLink,
    },
  };
});

vi.mock("@/components/identity/UserAvatar", () => ({
  UserAvatar: () => <span aria-hidden="true">avatar</span>,
}));

import { VeilLinkJoinDialog } from "@/components/spaces/VeilLinkJoinDialog";

const validPreview = (alreadyMember: boolean) => ({
  version: 1,
  type: "space",
  space_id: "550e8400-e29b-41d4-a716-446655440001",
  space: {
    name: "Atlas",
    description: "Private planning",
    mark_seed: "A".repeat(43),
  },
  expires_at: "2026-07-15T10:00:00Z",
  join_policy: "immediate_after_native_confirmation",
  already_member: alreadyMember,
});

const TWO_BYTE_SCALAR = "\u017D";
const utf8Length = (value: string): number => new TextEncoder().encode(value).byteLength;
const FLOW_A = "a".repeat(64);
const FLOW_B = "b".repeat(64);
const SPACE_A = "550e8400-e29b-41d4-a716-446655440001";
const SPACE_B = "550e8400-e29b-41d4-a716-446655440002";

const pendingLink = (flowId: string, selectorRef: string): MockPendingVeilLink => ({
  flowId,
  canonicalOrigin: "https://node.example.test:443",
  selectorRef,
  expiresInSeconds: 300,
});

const namedPreview = (name: string, spaceId: string) => ({
  ...validPreview(false),
  space_id: spaceId,
  space: { ...validPreview(false).space, name },
});

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe("VeilLinkJoinDialog", () => {
  beforeEach(() => {
    harness.sessionEpoch = 1;
    previewInvite.mockReset();
    useInvite.mockReset();
    loadChannels.mockReset().mockResolvedValue(undefined);
    loadServerMembers.mockReset().mockResolvedValue(undefined);
    selectServer.mockReset();
    cancelPendingVeilLink.mockReset().mockImplementation(async (flowId: string) => {
      if (harness.pending()?.flowId !== flowId) return false;
      harness.setPending(null);
      return true;
    });
    harness.setPending(pendingLink(FLOW_A, "ref-a"));
  });

  it("opens an existing Space without consuming the Veil Link again", async () => {
    previewInvite.mockResolvedValue(validPreview(true));
    render(() => <><VeilLinkJoinDialog /><div id="island-portal" /></>);

    const open = await screen.findByRole("button", { name: "Open Space" });
    expect(previewInvite).toHaveBeenCalledWith(FLOW_A);
    expect(screen.getByText("You are already a member")).toBeInTheDocument();
    fireEvent.click(open);

    await waitFor(() => expect(selectServer).toHaveBeenCalledWith("550e8400-e29b-41d4-a716-446655440001"));
    expect(useInvite).not.toHaveBeenCalled();
    expect(loadChannels).toHaveBeenCalledOnce();
    expect(loadServerMembers).toHaveBeenCalledOnce();
    expect(cancelPendingVeilLink).toHaveBeenCalledOnce();
    expect(cancelPendingVeilLink).toHaveBeenCalledWith(FLOW_A);
  });

  it("fails closed when authenticated preview metadata is malformed", async () => {
    previewInvite.mockResolvedValue({ ...validPreview(false), space_id: "not-a-uuid" });
    render(() => <><VeilLinkJoinDialog /><div id="island-portal" /></>);

    expect(await screen.findByRole("alert")).toHaveTextContent("invalid invitation preview");
    expect(screen.getByRole("button", { name: "Join Space" })).toBeDisabled();
    expect(useInvite).not.toHaveBeenCalled();
  });

  it("accepts exact 100/2000-byte UTF-8 bounds in a keyboard-scrollable layout", async () => {
    const boundedName = TWO_BYTE_SCALAR.repeat(50);
    const boundedDescription = TWO_BYTE_SCALAR.repeat(1000);
    expect(utf8Length(boundedName)).toBe(100);
    expect(utf8Length(boundedDescription)).toBe(2000);
    previewInvite.mockResolvedValue({
      ...validPreview(false),
      space: {
        ...validPreview(false).space,
        name: boundedName,
        description: boundedDescription,
      },
    });
    render(() => <><VeilLinkJoinDialog /><div id="island-portal" /></>);

    expect(await screen.findByText(boundedName)).toBeInTheDocument();
    expect(screen.getByText(boundedDescription)).toBeInTheDocument();
    const join = await screen.findByRole("button", { name: "Join Space" });

    const details = screen.getByRole("region", { name: "Veil Link invitation details" });
    expect(details).toHaveAttribute("tabindex", "0");
    expect(details).toHaveStyle({
      overflowX: "hidden",
      overflowY: "auto",
      overscrollBehavior: "contain",
    });
    expect(details.style.maxHeight).toContain("520px");
    details.focus();
    expect(details).toHaveFocus();

    const actions = screen.getByRole("group", { name: "Veil Link actions" });
    expect(actions).toHaveStyle({ position: "sticky", bottom: "0px" });
    expect(actions).toContainElement(screen.getByRole("button", { name: "Cancel" }));
    expect(actions).toContainElement(join);
    expect(details).not.toContainElement(join);
    expect(join).toBeEnabled();
  });

  it("rejects a 101-byte UTF-8 Space name", async () => {
    const oversizedName = `${TWO_BYTE_SCALAR.repeat(50)}x`;
    expect(utf8Length(oversizedName)).toBe(101);
    previewInvite.mockResolvedValue({
      ...validPreview(false),
      space: { ...validPreview(false).space, name: oversizedName },
    });
    render(() => <><VeilLinkJoinDialog /><div id="island-portal" /></>);

    expect(await screen.findByRole("alert")).toHaveTextContent("invalid invitation preview");
    expect(screen.getByRole("button", { name: "Join Space" })).toBeDisabled();
  });

  it("rejects a 2001-byte UTF-8 Space description", async () => {
    const oversizedDescription = `${TWO_BYTE_SCALAR.repeat(1000)}x`;
    expect(utf8Length(oversizedDescription)).toBe(2001);
    previewInvite.mockResolvedValue({
      ...validPreview(false),
      space: { ...validPreview(false).space, description: oversizedDescription },
    });
    render(() => <><VeilLinkJoinDialog /><div id="island-portal" /></>);

    expect(await screen.findByRole("alert")).toHaveTextContent("invalid invitation preview");
    expect(screen.getByRole("button", { name: "Join Space" })).toBeDisabled();
  });

  it("drops preview A when same-origin flow B replaces it and B preview fails", async () => {
    previewInvite.mockImplementation((flowId: string) => {
      if (flowId === FLOW_A) return Promise.resolve(namedPreview("Space Alpha", SPACE_A));
      if (flowId === FLOW_B) return Promise.reject(new Error("Flow B preview failed"));
      return Promise.reject(new Error("unexpected flow"));
    });
    render(() => <><VeilLinkJoinDialog /><div id="island-portal" /></>);

    expect(await screen.findByText("Space Alpha")).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Join Space" })).toBeEnabled();

    harness.setPending(pendingLink(FLOW_B, "ref-b"));

    expect(await screen.findByRole("alert")).toHaveTextContent("Flow B preview failed");
    expect(previewInvite).toHaveBeenNthCalledWith(1, FLOW_A);
    expect(previewInvite).toHaveBeenNthCalledWith(2, FLOW_B);
    expect(screen.queryByText("Space Alpha")).not.toBeInTheDocument();
    const join = screen.getByRole("button", { name: "Join Space" });
    expect(join).toBeDisabled();
    fireEvent.click(join);
    expect(useInvite).not.toHaveBeenCalled();
    expect(harness.pending()?.flowId).toBe(FLOW_B);
  });

  it("suppresses stale A navigation and preserves flow B when B replaces A during use", async () => {
    const useA = deferred<{ id: string }>();
    previewInvite.mockImplementation((flowId: string) => {
      if (flowId === FLOW_A) return Promise.resolve(namedPreview("Space Alpha", SPACE_A));
      if (flowId === FLOW_B) return Promise.resolve(namedPreview("Space Beta", SPACE_B));
      return Promise.reject(new Error("unexpected flow"));
    });
    useInvite.mockImplementation((flowId: string) => {
      if (flowId === FLOW_A) return useA.promise;
      return Promise.reject(new Error("unexpected flow"));
    });
    render(() => <><VeilLinkJoinDialog /><div id="island-portal" /></>);

    fireEvent.click(await screen.findByRole("button", { name: "Join Space" }));
    await waitFor(() => expect(useInvite).toHaveBeenCalledWith(FLOW_A));

    harness.setPending(pendingLink(FLOW_B, "ref-b"));
    expect(await screen.findByText("Space Beta")).toBeInTheDocument();
    expect(previewInvite).toHaveBeenCalledWith(FLOW_B);

    useA.resolve({ id: SPACE_A });
    await waitFor(() => expect(screen.getByRole("button", { name: "Join Space" })).toBeEnabled());

    expect(useInvite).toHaveBeenCalledTimes(1);
    expect(loadChannels).not.toHaveBeenCalled();
    expect(loadServerMembers).not.toHaveBeenCalled();
    expect(selectServer).not.toHaveBeenCalled();
    expect(cancelPendingVeilLink).not.toHaveBeenCalled();
    expect(harness.pending()?.flowId).toBe(FLOW_B);
    expect(screen.getByText("Space Beta")).toBeInTheDocument();
  });

  it("suppresses navigation when the account session changes during roster loading", async () => {
    const channels = deferred<undefined>();
    const members = deferred<undefined>();
    previewInvite.mockResolvedValue(namedPreview("Space Alpha", SPACE_A));
    useInvite.mockResolvedValue({ id: SPACE_A });
    loadChannels.mockReturnValue(channels.promise);
    loadServerMembers.mockReturnValue(members.promise);
    render(() => <><VeilLinkJoinDialog /><div id="island-portal" /></>);

    fireEvent.click(await screen.findByRole("button", { name: "Join Space" }));
    await waitFor(() => {
      expect(loadChannels).toHaveBeenCalledWith(SPACE_A);
      expect(loadServerMembers).toHaveBeenCalledWith(SPACE_A);
    });

    harness.sessionEpoch = 2;
    channels.resolve(undefined);
    members.resolve(undefined);

    await waitFor(() => expect(screen.getByRole("button", { name: "Join Space" })).toBeEnabled());
    expect(useInvite).toHaveBeenCalledWith(FLOW_A);
    expect(selectServer).not.toHaveBeenCalled();
  });

  it("disables Cancel and X throughout the irreversible join", async () => {
    const useA = deferred<{ id: string }>();
    previewInvite.mockResolvedValue(namedPreview("Space Alpha", SPACE_A));
    useInvite.mockReturnValue(useA.promise);
    render(() => <><VeilLinkJoinDialog /><div id="island-portal" /></>);

    fireEvent.click(await screen.findByRole("button", { name: "Join Space" }));
    await waitFor(() => expect(useInvite).toHaveBeenCalledWith(FLOW_A));

    const cancel = screen.getByRole("button", { name: "Cancel" });
    const close = screen.getByRole("button", { name: "Close Veil Link" });
    expect(screen.getByRole("button", { name: /Joining/ })).toBeDisabled();
    expect(cancel).toBeDisabled();
    expect(close).toBeDisabled();
    fireEvent.click(cancel);
    fireEvent.click(close);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(cancelPendingVeilLink).not.toHaveBeenCalled();
    expect(harness.pending()?.flowId).toBe(FLOW_A);
    expect(screen.getByRole("dialog", { name: "Veil Link" })).toBeInTheDocument();

    harness.sessionEpoch = 2;
    useA.resolve({ id: SPACE_A });
    await waitFor(() => expect(screen.getByRole("button", { name: "Join Space" })).toBeEnabled());
    expect(selectServer).not.toHaveBeenCalled();
  });
});
