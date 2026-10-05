import { useEffect, useMemo, useRef } from 'react';
import { directDraftScope, useChatStore } from '../stores/chat';

/** A queued list event belongs to one mounted visit, not just a conversation ID. */
export function useDirectViewportOwner(scope: string | null): () => boolean {
  const visit = useMemo(() => ({ scope }), [scope]);
  const currentVisit = useRef(visit);
  currentVisit.current = visit;
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  return useMemo(() => () => mounted.current
    && visit === currentVisit.current
    && visit.scope !== null
    && directDraftScope(useChatStore.getState()) === visit.scope, [visit]);
}
