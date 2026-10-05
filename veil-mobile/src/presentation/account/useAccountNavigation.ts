import { useCallback } from 'react';
import { useChatStore } from '../../stores/chat';

/** Commands cannot outlive the binding/generation that made this directory visible. */
export function useAccountNavigation(onSelected: (id: string) => void) {
  const binding = useChatStore(s => s.runtimeBinding), generation = useChatStore(s => s.directGeneration);
  return useCallback((id: string) => {
    const state = useChatStore.getState();
    if (!binding || state.runtimeBinding?.canonicalServerOrigin !== binding.canonicalServerOrigin
      || state.runtimeBinding.userId !== binding.userId || state.directGeneration !== generation) return;
    state.selectDm(id);
    if (useChatStore.getState().selectedDmId === id) onSelected(id);
  }, [binding, generation, onSelected]);
}
