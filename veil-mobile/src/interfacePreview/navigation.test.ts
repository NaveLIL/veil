import { expect, test } from '@jest/globals';
import { deckReducer, initialDeck, swipeDestination } from './navigation';
test('browsing without selecting retains the last chat; selecting another replaces it', () => {
  const selected = deckReducer(initialDeck, {
    type: 'choose',
    id: 'demo-anna',
  });
  const revealed = deckReducer(selected, { type: 'reveal' });
  expect(revealed).toEqual({ activeChatId: 'demo-anna', navigationOpen: true });
  expect(deckReducer(revealed, { type: 'resume' })).toEqual(selected);
  expect(
    deckReducer(revealed, { type: 'choose', id: 'demo-studio-general' }),
  ).toEqual({ activeChatId: 'demo-studio-general', navigationOpen: false });
  expect(deckReducer(initialDeck, { type: 'resume' })).toBe(initialDeck);
});
test('release uses distance and velocity in both directions and remains finite at zero width', () => {
  expect(swipeDestination(0.2, 0, 360)).toBe(false);
  expect(swipeDestination(0.8, 0, 360)).toBe(true);
  expect(swipeDestination(0.2, 1200, 360)).toBe(true);
  expect(swipeDestination(0.8, -1200, 360)).toBe(false);
  expect(swipeDestination(0.8, 0, 0)).toBe(true);
});
