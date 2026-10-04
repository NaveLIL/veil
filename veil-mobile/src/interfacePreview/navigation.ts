/** The navigation destination belongs to the layer below the retained chat. */
export type DeckState = { activeChatId: string | null; navigationOpen: boolean };
export type DeckAction = { type: 'choose'; id: string } | { type: 'reveal' } | { type: 'resume' };
export const initialDeck: DeckState = { activeChatId: null, navigationOpen: true };
export function deckReducer(state: DeckState, action: DeckAction): DeckState {
  if (action.type === 'choose') return { activeChatId: action.id, navigationOpen: false };
  if (action.type === 'reveal') return { ...state, navigationOpen: true };
  return state.activeChatId ? { ...state, navigationOpen: false } : state;
}
export function swipeDestination(progress: number, velocity: number, width: number): boolean {
  'worklet';
  const predicted = progress + Math.max(-1400, Math.min(1400, velocity)) * 0.18 / Math.max(1, width);
  return predicted >= 0.5;
}
