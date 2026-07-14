import { describe, expect, test } from "@jest/globals";
import {
  canonicalPhaseprintIdentityKey,
  canonicalPhaseprintOrigin,
  canonicalPhaseprintUserId,
  resolvePhaseprintSeed,
} from "../../components/identity/Phaseprint";
import {
  DM_HOME_ID,
  MEMBERS_BY_DM,
  MEMBERS_BY_SERVER,
  type Member,
  useChatStore,
} from "../chat";

function expectExactLocator(profile: Member): void {
  expect(canonicalPhaseprintOrigin(profile.canonicalServerOrigin)).toBe(profile.canonicalServerOrigin);
  expect(canonicalPhaseprintUserId(profile.userId)).toBe(profile.userId);
  expect(canonicalPhaseprintIdentityKey(profile.identityKey)).toBe(profile.identityKey);
  expect(resolvePhaseprintSeed(profile).kind).toBe("identity-key");
}

describe("mobile identity routing", () => {
  test("every server and DM roster carries an exact origin-scoped identity", () => {
    for (const roster of [...Object.values(MEMBERS_BY_SERVER), ...Object.values(MEMBERS_BY_DM)]) {
      expect(roster.length).toBeGreaterThan(0);
      for (const member of roster) expectExactLocator(member);
    }
  });

  test("message snapshots never recover authors from local row ids", () => {
    const store = useChatStore.getState();
    for (const server of store.servers.filter((candidate) => candidate.id !== DM_HOME_ID)) {
      store.selectServer(server.id);
      const channel = useChatStore.getState().channels.find((candidate) => candidate.serverId === server.id);
      expect(channel).toBeDefined();
      useChatStore.getState().selectChannel(channel!.id);
      const messages = useChatStore.getState().messagesByChannel[channel!.id] ?? [];
      expect(messages.length).toBeGreaterThan(0);
      for (const message of messages) expectExactLocator(message.author);
    }

    for (const dm of useChatStore.getState().dms) {
      useChatStore.getState().selectDm(dm.id);
      const messages = useChatStore.getState().messagesByChannel[dm.id] ?? [];
      expect(messages.length).toBeGreaterThan(0);
      for (const message of messages) expectExactLocator(message.author);
    }
  });

  test("group artwork is stable but cannot impersonate an account identity", () => {
    for (const dm of useChatStore.getState().dms) {
      if (dm.isGroup) {
        expect(dm.avatarIdentity).toBeNull();
      } else {
        expect(dm.avatarIdentity).not.toBeNull();
        expect(resolvePhaseprintSeed({
          canonicalServerOrigin: dm.avatarIdentity!.canonicalServerOrigin,
          userId: dm.avatarIdentity!.userId,
          identityKey: dm.avatarIdentity!.identityKey,
          technicalUsername: dm.avatarIdentity!.username,
        }).kind).toBe("identity-key");
      }
    }
  });

  test("rejects channel/context mismatches and snapshots the exact current account", () => {
    useChatStore.getState().selectServer("veil");
    const beforeChannel = useChatStore.getState().selectedChannelId;
    useChatStore.getState().selectChannel("rust-help");
    expect(useChatStore.getState().selectedServerId).toBe("veil");
    expect(useChatStore.getState().selectedChannelId).toBe(beforeChannel);

    useChatStore.getState().selectServer("rust");
    useChatStore.getState().selectChannel("rust-help");
    const before = useChatStore.getState().messagesByChannel["rust-help"]?.length ?? 0;
    useChatStore.getState().sendMessage("exact author");
    const messages = useChatStore.getState().messagesByChannel["rust-help"] ?? [];
    expect(messages).toHaveLength(before + 1);
    expectExactLocator(messages[messages.length - 1].author);
    expect(messages[messages.length - 1].author).toMatchObject({
      canonicalServerOrigin: "https://veil.example:443",
      userId: "10000000-0000-4000-8000-000000000001",
      identityKey: "11".repeat(32),
    });
  });
});
