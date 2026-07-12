import { fireEvent, render, screen } from "@solidjs/testing-library";
import userEvent from "@testing-library/user-event";
import { createSignal } from "solid-js";
import { describe, expect, it, vi } from "vitest";
import { RightIsland } from "@/components/layout/RightIsland";
import { ServerRail } from "@/components/layout/ServerRail";
import { WindowTitlebar } from "@/components/layout/WindowTitlebar";
import type { GroupMember, Role, Server, ServerMember } from "@/stores/app";
import {
  boundedIdentityRows,
  IDENTITY_ROW_RENDER_BUDGET,
} from "@/components/identity/identityRenderBudget";

describe("active AppShell components", () => {
  it("exposes labelled window controls and delegates native actions", async () => {
    const user = userEvent.setup();
    const minimize = vi.fn();
    const maximize = vi.fn();
    const close = vi.fn();
    const [maximized, setMaximized] = createSignal(false);

    render(() => (
      <WindowTitlebar
        maximized={maximized()}
        onMinimize={minimize}
        onToggleMaximize={() => {
          maximize();
          setMaximized(true);
        }}
        onClose={close}
      />
    ));

    const minimizeButton = screen.getByRole("button", { name: "Minimize window" });
    await user.tab();
    expect(minimizeButton).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(minimize).toHaveBeenCalledOnce();

    await user.click(screen.getByRole("button", { name: "Maximize window" }));
    expect(maximize).toHaveBeenCalledOnce();
    expect(screen.getByRole("button", { name: "Restore window" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Close window" }));
    expect(close).toHaveBeenCalledOnce();
    expect(screen.getByRole("banner", { name: "Application window" })).toHaveAttribute("data-tauri-drag-region");
  });

  it("keeps server navigation and creation actions on the active rail", async () => {
    const user = userEvent.setup();
    const selectServer = vi.fn();
    const openSettings = vi.fn();
    const createServer = vi.fn();
    const joinServer = vi.fn();
    const servers: Server[] = [{
      id: "server-1",
      name: "Private Room",
      ownerId: "owner-1",
    }];

    const { container } = render(() => (
      <ServerRail
        activeServerId="server-1"
        servers={servers}
        visible
        onSelectServer={selectServer}
        onOpenServerSettings={openSettings}
        onCreateServer={createServer}
        onJoinServer={joinServer}
      />
    ));

    expect(screen.getByRole("navigation", { name: "Servers" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Private Room" })).toHaveAttribute("aria-current", "page");
    expect(container.querySelector(".veil-server-rail-island")).toHaveStyle({ opacity: "1" });

    await user.click(screen.getByRole("button", { name: "Home — direct messages and groups" }));
    expect(selectServer).toHaveBeenCalledWith(null);
    await user.click(screen.getByRole("button", { name: "Private Room" }));
    expect(selectServer).toHaveBeenCalledWith("server-1");
    fireEvent.contextMenu(screen.getByRole("button", { name: "Private Room" }));
    expect(openSettings).toHaveBeenCalledWith("server-1");
    await user.click(screen.getByRole("button", { name: "Create a server" }));
    await user.click(screen.getByRole("button", { name: "Join a server with an invite" }));
    expect(createServer).toHaveBeenCalledOnce();
    expect(joinServer).toHaveBeenCalledOnce();
  });

  it("renders the extracted members island in group and server contexts", async () => {
    const user = userEvent.setup();
    const invite = vi.fn();
    const groupMembers: GroupMember[] = [{
      userId: "550e8400-e29b-41d4-a716-446655440010",
      identityKey: "41".repeat(32),
      username: "Group Owner",
      role: 2,
      joinedAt: "2026-07-11T00:00:00Z",
    }];
    const [serverNickname, setServerNickname] = createSignal("Server Owner");
    const serverMembers = (): ServerMember[] => [{
      serverId: "server-1",
      userId: "550e8400-e29b-41d4-a716-446655440011",
      identityKey: "42".repeat(32),
      username: "server-owner",
      nickname: serverNickname(),
      roleIds: [],
      joinedAt: "2026-07-11T00:00:00Z",
    }];
    const roles: Role[] = [];
    const noop = vi.fn();
    const [serverId, setServerId] = createSignal<string | null>(null);

    const { container } = render(() => (
      <RightIsland
        present
        open
        visible
        serverId={serverId()}
        canonicalServerOrigin="https://members.example.test:443"
        serverOwnerId="550e8400-e29b-41d4-a716-446655440011"
        currentUserId="550e8400-e29b-41d4-a716-446655440011"
        serverMembers={serverMembers()}
        serverRoles={roles}
        groupMembers={groupMembers}
        view="members"
        identityProfile={null}
        identityBackToMembers={false}
        identityCanMessage={false}
        identityMessageBusy={false}
        onOpenIdentity={noop}
        onBackToMembers={noop}
        onClose={noop}
        onMessageIdentity={noop}
        onCreateDm={noop}
        onAssignRole={noop}
        onUnassignRole={noop}
        onKickMember={noop}
        onInviteMember={invite}
      />
    ));

    expect(screen.getByRole("complementary", { name: "Conversation members" })).toHaveAttribute("aria-hidden", "false");
    expect(screen.getByText("Members — 1")).toBeInTheDocument();
    expect(screen.getByText("Group Owner")).toBeInTheDocument();
    expect(screen.getByText("OWNER")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Invite a member to this server" })).not.toBeInTheDocument();

    setServerId("server-1");
    expect(screen.getByText("Server Owner")).toBeInTheDocument();
    const phaseprint = container.querySelector("[data-phaseprint]")!;
    const stableIdentityVisual = phaseprint.innerHTML;
    expect(phaseprint).toHaveAttribute("data-phaseprint-seed-kind", "identity-key");
    setServerNickname("Renamed Owner");
    expect(screen.getByText("Renamed Owner")).toBeInTheDocument();
    const phaseprintAfterRename = container.querySelector("[data-phaseprint]")!;
    expect(phaseprintAfterRename).toBe(phaseprint);
    expect(phaseprintAfterRename.innerHTML).toBe(stableIdentityVisual);
    await user.click(screen.getByRole("button", { name: "Invite a member to this server" }));
    expect(invite).toHaveBeenCalledOnce();
  });

  it("does not mount an unbounded member directory while the island is closed", () => {
    const [open, setOpen] = createSignal(false);
    const serverMembers: ServerMember[] = Array.from({ length: 300 }, (_, index) => ({
      serverId: "server-large",
      userId: `550e8400-e29b-41d4-a716-${(index + 1).toString(16).padStart(12, "0")}`,
      identityKey: (index + 1).toString(16).padStart(64, "0"),
      username: `member-${index + 1}`,
      roleIds: [],
      joinedAt: "2026-07-11T00:00:00Z",
    }));
    const noop = vi.fn();
    const { container } = render(() => (
      <RightIsland
        present={open()}
        open={open()}
        visible={open()}
        serverId="server-large"
        canonicalServerOrigin="https://members.example.test:443"
        serverOwnerId={serverMembers[0].userId}
        currentUserId={serverMembers[0].userId}
        serverMembers={serverMembers}
        serverRoles={[]}
        groupMembers={[]}
        view="members"
        identityProfile={null}
        identityBackToMembers={false}
        identityCanMessage={false}
        identityMessageBusy={false}
        onOpenIdentity={noop}
        onBackToMembers={noop}
        onClose={noop}
        onMessageIdentity={noop}
        onCreateDm={noop}
        onAssignRole={noop}
        onUnassignRole={noop}
        onKickMember={noop}
        onInviteMember={noop}
      />
    ));

    expect(screen.getByText("Members — 300")).toBeInTheDocument();
    expect(container.querySelectorAll("[data-user-avatar]")).toHaveLength(0);

    setOpen(true);
    expect(container.querySelectorAll("[data-user-avatar]")).toHaveLength(256);
    expect(screen.getByRole("status")).toHaveTextContent("Showing the first 256 of 300 members");
  });

  it("bounds member rows without mutating an in-budget or oversized source", () => {
    const inBudget = Array.from({ length: IDENTITY_ROW_RENDER_BUDGET }, (_, index) => index);
    const oversized = [...inBudget, IDENTITY_ROW_RENDER_BUDGET];

    expect(boundedIdentityRows(inBudget)).toBe(inBudget);
    expect(boundedIdentityRows(oversized)).toEqual(inBudget);
    expect(oversized).toHaveLength(IDENTITY_ROW_RENDER_BUDGET + 1);
  });
});
