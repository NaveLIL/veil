import { fireEvent, render, screen, waitFor } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";

const harness = vi.hoisted(() => ({
  pending: {
    canonicalOrigin: "https://node.example.test:443",
    selectorRef: "ref-1234",
    expiresInSeconds: 300,
  } as object | null,
  preview: {} as unknown,
}));

const previewInvite = vi.hoisted(() => vi.fn());
const useInvite = vi.hoisted(() => vi.fn());
const loadChannels = vi.hoisted(() => vi.fn(async () => undefined));
const loadServerMembers = vi.hoisted(() => vi.fn(async () => undefined));
const selectServer = vi.hoisted(() => vi.fn());
const cancelPendingVeilLink = vi.hoisted(() => vi.fn(async () => { harness.pending = null; }));

vi.mock("@/stores/app", () => ({
  captureUiSessionEpoch: () => 1,
  isUiSessionEpochCurrent: () => true,
  appStore: {
    pendingVeilLink: () => harness.pending,
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
}));

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

describe("VeilLinkJoinDialog", () => {
  beforeEach(() => {
    harness.pending = {
      canonicalOrigin: "https://node.example.test:443",
      selectorRef: "ref-1234",
      expiresInSeconds: 300,
    };
    previewInvite.mockReset();
    useInvite.mockReset();
    loadChannels.mockClear();
    loadServerMembers.mockClear();
    selectServer.mockClear();
    cancelPendingVeilLink.mockClear();
  });

  it("opens an existing Space without consuming the Veil Link again", async () => {
    previewInvite.mockResolvedValue(validPreview(true));
    render(() => <><VeilLinkJoinDialog /><div id="island-portal" /></>);

    const open = await screen.findByRole("button", { name: "Open Space" });
    expect(screen.getByText("You are already a member")).toBeInTheDocument();
    fireEvent.click(open);

    await waitFor(() => expect(selectServer).toHaveBeenCalledWith("550e8400-e29b-41d4-a716-446655440001"));
    expect(useInvite).not.toHaveBeenCalled();
    expect(loadChannels).toHaveBeenCalledOnce();
    expect(loadServerMembers).toHaveBeenCalledOnce();
    expect(cancelPendingVeilLink).toHaveBeenCalledOnce();
  });

  it("fails closed when authenticated preview metadata is malformed", async () => {
    previewInvite.mockResolvedValue({ ...validPreview(false), space_id: "not-a-uuid" });
    render(() => <><VeilLinkJoinDialog /><div id="island-portal" /></>);

    expect(await screen.findByRole("alert")).toHaveTextContent("invalid invitation preview");
    expect(screen.getByRole("button", { name: "Join Space" })).toBeDisabled();
    expect(useInvite).not.toHaveBeenCalled();
  });
});
