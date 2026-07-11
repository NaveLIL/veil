import { describe, expect, it } from "vitest";
import { conversationCryptoUiState } from "@/security/conversationCrypto";
import type { ConversationCryptoDiagnostic } from "@/stores/app";

describe("conversation crypto quarantine", () => {
  it("blocks only the affected group and leaves an unrelated DM composer ready", () => {
    const groupId = "00000000-0000-0000-0000-000000000201";
    const dmId = "00000000-0000-0000-0000-000000000202";
    const diagnostic: ConversationCryptoDiagnostic = {
      conversationId: groupId,
      code: "retained_sender_key_rejected",
      detail: "A required historical generation is unavailable.",
    };
    const diagnostics = { [groupId]: diagnostic };

    const group = conversationCryptoUiState(diagnostics, groupId);
    expect(group.blocked).toBe(true);
    expect(group.diagnostic).toBe(diagnostic);
    expect(group.headerLabel).toContain("sending blocked");
    expect(group.composerPlaceholder).toContain("revalidated");

    const dm = conversationCryptoUiState(diagnostics, dmId);
    expect(dm).toEqual({
      blocked: false,
      diagnostic: null,
      headerLabel: null,
      composerPlaceholder: null,
    });
  });
});
