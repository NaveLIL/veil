import { useEffect, useRef, useState } from "react";
import { DM_HOME_ID, type Message, useChatStore } from "../stores/chat";

const EMPTY_MESSAGES: Message[] = [];

/** Transient screen controller. Native and the existing scoped store own messages. */
export function useDirectTimelinePresenter() {
  const binding = useChatStore((s) => s.runtimeBinding);
  const generation = useChatStore((s) => s.directGeneration);
  const selectedServerId = useChatStore((s) => s.selectedServerId);
  const conversationId = useChatStore((s) => s.selectedDmId);
  const directoryRevision = useChatStore((s) => s.directoryRevision);
  const messagesByChannel = useChatStore((s) => s.messagesByChannel);
  const projectionStates = useChatStore((s) => s.projectionStateByConversation);
  const dms = useChatStore((s) => s.dms);
  const load = useChatStore((s) => s.loadSelectedDirectMessages);
  const send = useChatStore((s) => s.sendSelectedDirectText);
  const pending = useChatStore((s) => s.directSendPending);
  const error = useChatStore((s) => s.directSendError);
  const scope = binding && generation !== null && conversationId
    ? `${binding.canonicalServerOrigin}\u0000${binding.userId}\u0000${generation}\u0000${conversationId}`
    : null;
  const projectionState = conversationId ? projectionStates[conversationId] ?? "idle" : "idle";
  const messages = scope && projectionState === "available"
    ? messagesByChannel[conversationId!] ?? EMPTY_MESSAGES
    : EMPTY_MESSAGES;
  const [draftState, setDraftState] = useState<{ scope: string | null; text: string }>({ scope, text: "" });
  const draft = draftState.scope === scope ? draftState.text : "";
  const mounted = useRef(true);
  const sendingScope = useRef<string | null>(null);
  const canCompose = scope !== null && selectedServerId === DM_HOME_ID && projectionState === "available" && !pending;

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  useEffect(() => { setDraftState({ scope, text: "" }); }, [scope]);

  useEffect(() => {
    if (scope && selectedServerId === DM_HOME_ID) void load();
  }, [scope, selectedServerId, directoryRevision, load]);

  const setDraft = (text: string) => setDraftState({ scope, text });
  const sendDraft = async () => {
    if (!canCompose || !draft.length || sendingScope.current === scope) return;
    const submitted = draft;
    const submittedScope = scope;
    sendingScope.current = submittedScope;
    try {
      const result = await send(submitted);
      const current = useChatStore.getState();
      const currentScope = current.runtimeBinding && current.directGeneration !== null && current.selectedDmId
        ? `${current.runtimeBinding.canonicalServerOrigin}\u0000${current.runtimeBinding.userId}\u0000${current.directGeneration}\u0000${current.selectedDmId}`
        : null;
      if (mounted.current && result === "accepted" && currentScope === submittedScope) {
        setDraftState((value) => value.scope === submittedScope && value.text === submitted
          ? { scope: submittedScope, text: "" } : value);
      }
    } finally {
      if (sendingScope.current === submittedScope) sendingScope.current = null;
    }
  };

  return {
    scope, conversationId, messages, projectionState,
    title: dms.find((dm) => dm.id === conversationId)?.name ?? "Direct messages",
    draft, setDraft, canCompose, pending, error, reload: load, sendDraft,
  };
}
