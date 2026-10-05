import { useCallback, useEffect, useRef, useState } from 'react';
import { AccessibilityInfo } from 'react-native';
import type { TimelineMessage } from '../interfacePreview/conversationContract';
import { copyAccountText } from '../presentation/account/clipboard';
import { directDraftScope, useChatStore } from '../stores/chat';

/** Read-only message UI commands, scoped to the current verified projection. */
export function useNativeMessageActions(scope: string | null, messages: TimelineMessage[]) {
  const [selection, setSelection] = useState<{scope:string;id:string} | null>(null);
  const [notice, setNotice] = useState('');
  const current = useRef(scope); current.current = scope;
  const alive = useRef(true), operation = useRef(0);
  useEffect(() => { alive.current = true; return () => { alive.current = false; operation.current += 1; }; }, []);
  useEffect(() => { operation.current += 1; setSelection(null); setNotice(''); }, [scope]);
  useEffect(() => { if (!notice) return; const timer = setTimeout(() => setNotice(''),3500); return () => clearTimeout(timer); }, [notice]);
  const selected = selection?.scope === scope ? messages.find(m => m.id === selection.id) : undefined;
  const open = useCallback((message: TimelineMessage) => {
    if (scope && messages.some(m => m.id === message.id)) setSelection({scope,id:message.id});
  }, [scope, messages]);
  const close = useCallback(() => setSelection(null), []);
  const copy = async () => {
    if (!selected || !scope) return;
    const origin = scope, revision = ++operation.current;
    close();
    let feedback: string;
    try { await copyAccountText(selected.text); feedback = 'Текст скопирован'; }
    catch { feedback = 'Не удалось скопировать текст'; }
    const state = useChatStore.getState();
    const authority = directDraftScope(state);
    if (!alive.current || current.current !== origin || authority !== origin || revision !== operation.current) return;
    setNotice(feedback);
    AccessibilityInfo.announceForAccessibility(feedback);
  };
  return { selected, notice, open, close, copy };
}
