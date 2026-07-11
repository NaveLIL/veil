import { fireEvent, render, screen } from "@solidjs/testing-library";
import userEvent from "@testing-library/user-event";
import { createSignal } from "solid-js";
import { describe, expect, it, vi } from "vitest";
import { MembersIsland } from "@/components/layout/MembersIsland";
import { ServerRail } from "@/components/layout/ServerRail";
import { WindowTitlebar } from "@/components/layout/WindowTitlebar";
import type { GroupMember, Role, Server, ServerMember } from "@/stores/app";

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
      userId: "group-owner",
      identityKey: "identity",
      username: "Group Owner",
      role: 2,
      joinedAt: "2026-07-11T00:00:00Z",
    }];
    const serverMembers: ServerMember[] = [{
      serverId: "server-1",
      userId: "owner-1",
      username: "Server Owner",
      roleIds: [],
      joinedAt: "2026-07-11T00:00:00Z",
    }];
    const roles: Role[] = [];
    const noop = vi.fn();
    const [serverId, setServerId] = createSignal<string | null>(null);

    render(() => (
      <MembersIsland
        open
        visible
        serverId={serverId()}
        serverOwnerId="owner-1"
        currentUserId="owner-1"
        serverMembers={serverMembers}
        serverRoles={roles}
        groupMembers={groupMembers}
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
    await user.click(screen.getByRole("button", { name: "Invite a member to this server" }));
    expect(invite).toHaveBeenCalledOnce();
  });
});
