import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({}),
}));

import {
  centerAndFocusExactSearchTarget,
  publishExactSearchRoute,
  renderedExactSearchTarget,
  shouldLoadConversationHistory,
  waitForRenderedExactSearchTarget,
} from "@/App";
import type { Conversation } from "@/stores/app";

type TestChannel = { id: string; serverId: string; conversationId?: string };

function routeStore(initialConversations: Conversation[] = []) {
  let conversations = initialConversations;
  let servers: Array<{ id: string }> = [];
  let channels: Record<string, TestChannel[]> = {};
  let activeServerId: string | null = null;
  let activeChannelId: string | null = null;
  let activeConversationId: string | null = null;
  const loadConversations = vi.fn(async () => undefined);
  const loadServers = vi.fn(async () => true);
  const loadChannels = vi.fn(async () => true);
  const store = {
    conversations: () => conversations,
    loadConversations,
    servers: () => servers,
    loadServers,
    channelsByServer: () => channels,
    loadChannels,
    activeServerId: () => activeServerId,
    activeChannelId: () => activeChannelId,
    activeConversationId: () => activeConversationId,
    selectServer: vi.fn((serverId: string | null) => { activeServerId = serverId; }),
    selectChannel: vi.fn((channelId: string | null) => {
      activeChannelId = channelId;
      const room = activeServerId
        ? (channels[activeServerId] ?? []).find((candidate) => candidate.id === channelId)
        : undefined;
      activeConversationId = room?.conversationId ?? null;
    }),
  };
  return {
    store,
    loadConversations,
    loadServers,
    loadChannels,
    setConversations: (value: Conversation[]) => { conversations = value; },
    setServers: (value: Array<{ id: string }>) => { servers = value; },
    setChannels: (value: Record<string, TestChannel[]>) => { channels = value; },
    openConversation: (conversationId: string) => { activeConversationId = conversationId; },
  };
}

const conversation = (id: string, type: "dm" | "group"): Conversation => ({
  id,
  type,
  name: id,
  unreadCount: 0,
});

describe("App exact search navigation", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it.each(["dm", "group"] as const)(
    "publishes the authenticated %s route and never substitutes another conversation",
    async (type) => {
      const conversationId = `${type}-conversation`;
      const fixture = routeStore();
      fixture.loadConversations.mockImplementation(async () => {
        fixture.setConversations([conversation(conversationId, type)]);
      });
      const requireCurrentAction = vi.fn();
      const prepareConversationView = vi.fn();

      await publishExactSearchRoute(
        { conversationId },
        { conversationType: type, serverId: undefined },
        {
          store: fixture.store,
          requireCurrentAction,
          prepareConversationView,
          openConversation: fixture.openConversation,
        },
      );

      expect(fixture.loadConversations).toHaveBeenCalledOnce();
      expect(requireCurrentAction).toHaveBeenCalledOnce();
      expect(fixture.store.activeConversationId()).toBe(conversationId);
      expect(fixture.store.selectServer).not.toHaveBeenCalled();
      expect(prepareConversationView).not.toHaveBeenCalled();
    },
  );

  it("refreshes and publishes the exact Space/Room route without a Direct fallback", async () => {
    const fixture = routeStore();
    const serverId = "space-1";
    const conversationId = "room-conversation";
    fixture.loadServers.mockImplementation(async () => {
      fixture.setServers([{ id: serverId }]);
      return true;
    });
    fixture.loadChannels.mockImplementation(async () => {
      fixture.setChannels({
        [serverId]: [{ id: "room-1", serverId, conversationId }],
      });
      return true;
    });
    const requireCurrentAction = vi.fn();
    const prepareConversationView = vi.fn();
    const openConversation = vi.fn();

    await publishExactSearchRoute(
      { conversationId },
      { conversationType: "channel", serverId },
      { store: fixture.store, requireCurrentAction, prepareConversationView, openConversation },
    );

    expect(fixture.loadServers).toHaveBeenCalledOnce();
    expect(fixture.loadChannels).toHaveBeenCalledWith(serverId, false);
    expect(requireCurrentAction).toHaveBeenCalledTimes(2);
    expect(prepareConversationView).toHaveBeenCalledOnce();
    expect(fixture.store.selectServer).toHaveBeenCalledWith(serverId, false);
    expect(fixture.store.selectChannel).toHaveBeenCalledWith("room-1");
    expect(fixture.store.activeConversationId()).toBe(conversationId);
    expect(openConversation).not.toHaveBeenCalled();
  });

  it("fails closed when the authenticated Room does not exist", async () => {
    const fixture = routeStore();
    fixture.setServers([{ id: "space-1" }]);
    fixture.setChannels({
      "space-1": [{ id: "wrong-room", serverId: "space-1", conversationId: "other" }],
    });

    await expect(publishExactSearchRoute(
      { conversationId: "target" },
      { conversationType: "channel", serverId: "space-1" },
      {
        store: fixture.store,
        requireCurrentAction: () => undefined,
        prepareConversationView: () => undefined,
        openConversation: vi.fn(),
      },
    )).rejects.toThrow("Room is unavailable");
    expect(fixture.store.selectServer).not.toHaveBeenCalled();
  });

  it("keeps the bounded exact context instead of triggering the normal history load", () => {
    expect(shouldLoadConversationHistory("conversation-1", "conversation-1")).toBe(false);
    expect(shouldLoadConversationHistory("conversation-1", "conversation-2")).toBe(false);
    expect(shouldLoadConversationHistory("conversation-1", null)).toBe(true);
    expect(shouldLoadConversationHistory(null, "conversation-1")).toBe(false);
  });

  it("does not confirm navigation before the exact message exists in the active DOM", async () => {
    const viewport = document.createElement("div");
    document.body.append(viewport);
    let frameCallback: FrameRequestCallback | undefined;
    vi.stubGlobal("requestAnimationFrame", vi.fn((callback: FrameRequestCallback) => {
      frameCallback = callback;
      return 1;
    }));
    let settled = false;
    const targetPromise = waitForRenderedExactSearchTarget(
      () => viewport,
      () => "conversation-1",
      "conversation-1",
      "message-1",
      () => true,
      1,
    ).then((target) => {
      settled = true;
      return target;
    });
    await Promise.resolve();
    expect(settled).toBe(false);

    const target = document.createElement("div");
    target.id = "msg-message-1";
    target.tabIndex = -1;
    viewport.append(target);
    frameCallback?.(0);

    await expect(targetPromise).resolves.toBe(target);
    expect(renderedExactSearchTarget(
      viewport,
      "different-conversation",
      "conversation-1",
      "message-1",
    )).toBeNull();
  });

  it("centers and focuses the authenticated target after the modal handoff", () => {
    const viewport = document.createElement("div");
    const target = document.createElement("div");
    target.tabIndex = -1;
    viewport.append(target);
    document.body.append(viewport);
    Object.defineProperty(viewport, "clientHeight", { configurable: true, value: 400 });
    Object.defineProperty(viewport, "scrollTop", { configurable: true, value: 50, writable: true });
    vi.spyOn(viewport, "getBoundingClientRect").mockReturnValue({
      top: 100, bottom: 500, left: 0, right: 600, width: 600, height: 400, x: 0, y: 100,
      toJSON: () => ({}),
    });
    vi.spyOn(target, "getBoundingClientRect").mockReturnValue({
      top: 300, bottom: 340, left: 0, right: 600, width: 600, height: 40, x: 0, y: 300,
      toJSON: () => ({}),
    });
    const scrollTo = vi.fn();
    Object.defineProperty(viewport, "scrollTo", { configurable: true, value: scrollTo });

    centerAndFocusExactSearchTarget(viewport, target, true);

    expect(scrollTo).toHaveBeenCalledWith({ top: 70, behavior: "auto" });
    expect(target).toHaveFocus();
  });
});
