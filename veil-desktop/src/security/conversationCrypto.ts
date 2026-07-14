import type { ConversationCryptoDiagnostic } from "@/stores/app";

export interface ConversationCryptoUiState {
  blocked: boolean;
  diagnostic: ConversationCryptoDiagnostic | null;
  headerLabel: string | null;
  composerPlaceholder: string | null;
}

/** Derive quarantine UI strictly by conversation ID. A bad group must never
 * leak its blocked state into an unrelated DM's header or composer. */
export function conversationCryptoUiState(
  diagnostics: Record<string, ConversationCryptoDiagnostic>,
  conversationId: string | null | undefined,
): ConversationCryptoUiState {
  const diagnostic = conversationId ? diagnostics[conversationId] ?? null : null;
  if (!diagnostic) {
    return {
      blocked: false,
      diagnostic: null,
      headerLabel: null,
      composerPlaceholder: null,
    };
  }
  return {
    blocked: true,
    diagnostic,
    headerLabel: "Secure conversation unavailable · sending blocked",
    composerPlaceholder: "Sending blocked until this conversation is revalidated",
  };
}
