import { afterAll, describe, expect, it, jest } from "@jest/globals";
import { NativeModules } from "react-native";

const originalModule = NativeModules.VeilMobileRuntime;
const peerId = "33333333-3333-4333-8333-333333333333";
const conversationId = "22222222-2222-4222-8222-222222222222";
const actionId = "veil-contact-1";

function installContacts() {
  const searchContact = jest.fn<() => Promise<unknown>>()
    .mockResolvedValue({ userId: peerId, username: "alice" });
  const createDirect = jest.fn<() => Promise<unknown>>().mockResolvedValue({ conversationId });
  const cancelContacts = jest.fn<() => Promise<unknown>>().mockResolvedValue(true);
  Object.defineProperty(NativeModules, "VeilMobileRuntime", {
    configurable: true,
    value: { searchContact, createDirect, cancelContacts, addListener: jest.fn(), removeListeners: jest.fn() },
  });
  jest.resetModules();
  const loaded: { runtime?: typeof import("../runtime").default } = {};
  jest.isolateModules(() => {
    loaded.runtime = jest.requireActual<typeof import("../runtime")>("../runtime").default;
  });
  if (!loaded.runtime) throw new Error("runtime did not load");
  return { runtime: loaded.runtime, searchContact, createDirect, cancelContacts };
}

afterAll(() => {
  Object.defineProperty(NativeModules, "VeilMobileRuntime", {
    configurable: true, value: originalModule,
  });
});

describe("native contact operation boundary", () => {
  it("passes one action scope, returns only public DTOs and exposes no signer/parser", async () => {
    const { runtime, searchContact, createDirect, cancelContacts } = installContacts();
    await expect(runtime.searchContact("alice", 7, actionId))
      .resolves.toEqual({ userId: peerId, username: "alice" });
    await expect(runtime.createDirect(peerId, 7, actionId)).resolves.toEqual({ conversationId });
    await expect(runtime.cancelContacts(7, actionId)).resolves.toBe(true);
    expect(searchContact).toHaveBeenCalledWith("alice", 7, actionId);
    expect(createDirect).toHaveBeenCalledWith(peerId, 7, actionId);
    expect(cancelContacts).toHaveBeenCalledWith(7, actionId);
    for (const legacy of ["prepareContactSearch", "prepareCreateDirect",
      "parseContactSearchResponse", "parseCreateDirectResponse"]) {
      expect(Object.keys(runtime)).not.toContain(legacy);
    }
  });

  it("represents native not-found by null without a request body", async () => {
    const { runtime, searchContact } = installContacts();
    searchContact.mockResolvedValue(null);
    await expect(runtime.searchContact("alice", 7, actionId)).resolves.toBeNull();
  });

  it.each([
    { userId: peerId, username: "bob" },
    { userId: peerId, username: "alice", identityKey: "must-not-cross" },
    { userId: peerId, username: "alice", signature: { signatureBase64url: "secret" } },
    { userId: "invalid", username: "alice" },
    undefined,
  ])("rejects malformed or authority-bearing search output %p", async (result) => {
    const { runtime, searchContact } = installContacts();
    searchContact.mockResolvedValue(result);
    await expect(runtime.searchContact("alice", 7, actionId)).rejects.toThrow("invalid result");
  });

  it.each([
    { conversationId: "invalid" },
    { conversationId, bodyBase64: "must-not-cross" },
    { conversationId, peerSigningKey: "must-not-cross" },
    null,
  ])("rejects malformed or authority-bearing create output %p", async (result) => {
    const { runtime, createDirect } = installContacts();
    createDirect.mockResolvedValue(result);
    await expect(runtime.createDirect(peerId, 7, actionId)).rejects.toThrow("invalid result");
  });

  it("rejects invalid scope and UTF-8 query before invoking native", async () => {
    const { runtime, searchContact, createDirect, cancelContacts } = installContacts();
    for (const generation of [0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(runtime.searchContact("alice", generation, actionId)).rejects.toThrow();
      await expect(runtime.createDirect(peerId, generation, actionId)).rejects.toThrow();
      await expect(runtime.cancelContacts(generation, actionId)).rejects.toThrow();
    }
    for (const username of ["", "\u0000alice", "\u0085alice", "x".repeat(129), "\ud800"]) {
      await expect(runtime.searchContact(username, 7, actionId)).rejects.toThrow();
    }
    await expect(runtime.searchContact("alice", 7, "invalid action")).rejects.toThrow();
    await expect(runtime.createDirect("invalid", 7, actionId)).rejects.toThrow();
    expect(searchContact).not.toHaveBeenCalled();
    expect(createDirect).not.toHaveBeenCalled();
    expect(cancelContacts).not.toHaveBeenCalled();
  });
});
