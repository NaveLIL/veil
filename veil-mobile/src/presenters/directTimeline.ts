import { useEffect, useRef } from 'react';
import { DM_HOME_ID, directDraftScope, type Message, useChatStore } from '../stores/chat';
import { useDirectHistoryWait } from './useDirectHistoryWait';

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
  const projectionRequestRevision = useChatStore((s) => s.projectionRequestRevision);
  const dms = useChatStore((s) => s.dms);
  const load = useChatStore((s) => s.loadSelectedDirectMessages);
  const send = useChatStore((s) => s.sendSelectedDirectText);
  const transportPending = useChatStore((s) => s.directSendPending);
  const pendingScope = useChatStore((s) => s.directSendScope);
  const error = useChatStore((s) => s.directSendError);
  const scope = directDraftScope({ runtimeBinding: binding, directGeneration: generation, selectedDmId: conversationId });
  const projectionState = conversationId
    ? (projectionStates[conversationId] ?? 'idle')
    : 'idle';
  const historyWaitExpired = useDirectHistoryWait(scope, projectionRequestRevision, projectionState);
  const pending = transportPending && pendingScope === scope;
  const messages =
    scope && projectionState === 'available'
      ? (messagesByChannel[conversationId!] ?? EMPTY_MESSAGES)
      : EMPTY_MESSAGES;
  const drafts = useChatStore((s) => s.directDrafts);
  const draft = scope ? (drafts[scope] ?? '') : '';
  const sendingScope = useRef<string | null>(null);
  const canCompose =
    scope !== null &&
    selectedServerId === DM_HOME_ID &&
    projectionState === 'available' &&
    !transportPending;

  useEffect(() => {
    if (scope && selectedServerId === DM_HOME_ID) void load();
  }, [scope, selectedServerId, directoryRevision, load]);

  const setDraft = (text: string) => {
    if (scope) useChatStore.getState().setDirectDraft(scope, text);
  };
  const sendDraft = async () => {
    if (!canCompose || !draft.length || sendingScope.current === scope) return;
    const submitted = draft;
    const submittedScope = scope;
    sendingScope.current = submittedScope;
    try {
      const result = await send(submitted);
      if (result === 'accepted' && submittedScope)
        useChatStore.getState().consumeDirectDraft(submittedScope, submitted);
    } finally {
      if (sendingScope.current === submittedScope) sendingScope.current = null;
    }
  };

  return {
    scope,
    conversationId,
    messages,
    projectionState,
    historyWaitExpired,
    title:
      dms.find((dm) => dm.id === conversationId)?.name ?? 'Direct messages',
    draft,
    setDraft,
    canCompose,
    pending,
    busyElsewhere: transportPending && pendingScope !== scope,
    error,
    reload: load,
    sendDraft,
  };
}
