import { useEffect, useMemo, useState } from 'react';
import type { DirectProjectionState } from '../stores/chat';

export const SLOW_DIRECT_HISTORY_MS = 10_000;

/** Presentation deadline only: does not cancel native work or invent a failure/status. */
export function useDirectHistoryWait(scope: string | null, requestRevision: number,
  projection: DirectProjectionState): boolean {
  const owner = useMemo(() => ({ scope, requestRevision, projection }),
    [scope, requestRevision, projection]);
  const [expired, setExpired] = useState<typeof owner | null>(null);
  useEffect(() => {
    setExpired(null);
    if (!owner.scope || owner.projection !== 'loading') return;
    let current = true;
    const timer = setTimeout(() => {
      if (current) setExpired(owner);
    }, SLOW_DIRECT_HISTORY_MS);
    return () => { current = false; clearTimeout(timer); };
  }, [owner]);
  return expired === owner;
}
