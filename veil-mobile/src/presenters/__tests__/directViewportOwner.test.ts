import { act, cleanup, renderHook } from '@testing-library/react-native';
import { afterEach, beforeEach, expect, test } from '@jest/globals';
import { directDraftScope, resetChatStoreForTests, useChatStore } from '../../stores/chat';
import { useDirectViewportOwner } from '../useDirectViewportOwner';

const account = '11111111-1111-4111-8111-111111111111';
const a = '22222222-2222-4222-8222-222222222222';
const b = '33333333-3333-4333-8333-333333333333';
function owner() { return directDraftScope(useChatStore.getState()); }
beforeEach(() => {
  resetChatStoreForTests();
  useChatStore.setState({ runtimeBinding: { canonicalServerOrigin: 'https://veil.example:443', userId: account },
    directGeneration: 1, selectedDmId: a });
});
afterEach(cleanup);

test('queued measurements cannot scroll a different chat before or after its render', () => {
  const ui = renderHook(({scope}: {scope: string | null}) => useDirectViewportOwner(scope), {initialProps: {scope: owner()}});
  const fromA = ui.result.current;
  expect(fromA()).toBe(true);
  act(() => useChatStore.setState({selectedDmId: b}));
  expect(fromA()).toBe(false);
  ui.rerender({scope: owner()});
  expect(fromA()).toBe(false);
  expect(ui.result.current()).toBe(true);
});
test('A -> B -> A rejects callbacks from the earlier visit to A', () => {
  const ui = renderHook(({scope}: {scope: string | null}) => useDirectViewportOwner(scope), {initialProps: {scope: owner()}});
  const oldA = ui.result.current;
  act(() => useChatStore.setState({selectedDmId: b}));
  ui.rerender({scope: owner()});
  const oldB = ui.result.current;
  act(() => useChatStore.setState({selectedDmId: a}));
  ui.rerender({scope: owner()});
  expect(oldA()).toBe(false);
  expect(oldB()).toBe(false);
  expect(ui.result.current()).toBe(true);
});
test('unmount, privacy clear and changed generation invalidate old list callbacks', () => {
  const ui = renderHook(() => useDirectViewportOwner(owner()));
  const original = ui.result.current;
  act(() => useChatStore.setState({directGeneration: 2}));
  expect(original()).toBe(false);
  ui.rerender(undefined);
  const regenerated = ui.result.current;
  expect(regenerated()).toBe(true);
  act(() => useChatStore.getState().clearRenderableChat());
  expect(regenerated()).toBe(false);
  ui.unmount();
  expect(regenerated()).toBe(false);
});
test('an unrelated re-render retains ownership; null scope never owns a list', () => {
  const ui = renderHook(({scope}: {scope: string | null}) => useDirectViewportOwner(scope), {initialProps: {scope: owner()}});
  const current = ui.result.current;
  ui.rerender({scope: owner()});
  expect(ui.result.current).toBe(current);
  expect(current()).toBe(true);
  ui.rerender({scope: null});
  expect(current()).toBe(false);
  expect(ui.result.current()).toBe(false);
});
test('another account or origin with the same chat ID does not own the earlier viewport', () => {
  const ui = renderHook(() => useDirectViewportOwner(owner()));
  const original = ui.result.current;
  act(() => useChatStore.setState({runtimeBinding: {
    canonicalServerOrigin: 'https://veil.example:443', userId: b,
  }}));
  expect(original()).toBe(false);
  ui.rerender(undefined);
  const otherAccount = ui.result.current;
  expect(otherAccount()).toBe(true);
  act(() => useChatStore.setState({runtimeBinding: {
    canonicalServerOrigin: 'https://another.example:443', userId: b,
  }}));
  expect(otherAccount()).toBe(false);
  ui.rerender(undefined);
  expect(ui.result.current()).toBe(true);
});
test('an unmounted list stays invalid even if the exact original authority remains ready', () => {
  const ui = renderHook(() => useDirectViewportOwner(owner()));
  const callback = ui.result.current;
  expect(callback()).toBe(true);
  ui.unmount();
  expect(owner()).not.toBeNull();
  expect(callback()).toBe(false);
});
