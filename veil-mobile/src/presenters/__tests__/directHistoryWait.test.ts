import { act, cleanup, renderHook } from '@testing-library/react-native';
import { afterEach, beforeEach, expect, jest, test } from '@jest/globals';
import type { DirectProjectionState } from '../../stores/chat';
import { SLOW_DIRECT_HISTORY_MS, useDirectHistoryWait } from '../useDirectHistoryWait';

const loading = {scope: 'scope-a', requestRevision: 1, projection: 'loading' as DirectProjectionState};
const mount = () => renderHook((props: typeof loading) =>
  useDirectHistoryWait(props.scope, props.requestRevision, props.projection), {initialProps: loading});
beforeEach(() => { jest.useFakeTimers(); });
afterEach(() => { cleanup(); jest.useRealTimers(); });

test('a stalled native projection offers bounded wait feedback without changing runtime state', () => {
  const ui = mount();
  act(() => jest.advanceTimersByTime(SLOW_DIRECT_HISTORY_MS - 1));
  expect(ui.result.current).toBe(false);
  act(() => jest.advanceTimersByTime(1));
  expect(ui.result.current).toBe(true);
  expect(jest.getTimerCount()).toBe(0);
});
test('available/unavailable results remove the waiting notice and timer', () => {
  const ui = mount();
  ui.rerender({...loading, projection: 'available'});
  expect(ui.result.current).toBe(false);
  expect(jest.getTimerCount()).toBe(0);
  ui.rerender({...loading, projection: 'loading', requestRevision: 2});
  act(() => jest.advanceTimersByTime(SLOW_DIRECT_HISTORY_MS));
  expect(ui.result.current).toBe(true);
  ui.rerender({...loading, projection: 'unavailable', requestRevision: 2});
  expect(ui.result.current).toBe(false);
  expect(jest.getTimerCount()).toBe(0);
});
test('manual retry starts a new request wait instead of retaining an expired one', () => {
  const ui = mount();
  act(() => jest.advanceTimersByTime(SLOW_DIRECT_HISTORY_MS));
  expect(ui.result.current).toBe(true);
  ui.rerender({...loading, requestRevision: 2});
  expect(ui.result.current).toBe(false);
  act(() => jest.advanceTimersByTime(SLOW_DIRECT_HISTORY_MS - 1));
  expect(ui.result.current).toBe(false);
  act(() => jest.advanceTimersByTime(1));
  expect(ui.result.current).toBe(true);
});
test('another conversation starts its own deadline and idle has no waiting notice', () => {
  const ui = mount();
  act(() => jest.advanceTimersByTime(SLOW_DIRECT_HISTORY_MS));
  ui.rerender({...loading, scope: 'scope-b'});
  expect(ui.result.current).toBe(false);
  act(() => jest.advanceTimersByTime(SLOW_DIRECT_HISTORY_MS));
  expect(ui.result.current).toBe(true);
  ui.rerender({...loading, scope: 'scope-b', projection: 'idle'});
  expect(ui.result.current).toBe(false);
  expect(jest.getTimerCount()).toBe(0);
});
test('privacy clear and unmount remove the timer rather than leaving a stale callback', () => {
  const ui = renderHook(({scope}: {scope: string | null}) =>
    useDirectHistoryWait(scope, 1, 'loading'), {initialProps: {scope: 'scope-a'}});
  ui.rerender({scope: null});
  expect(ui.result.current).toBe(false);
  expect(jest.getTimerCount()).toBe(0);
  ui.rerender({scope: 'scope-a'});
  expect(jest.getTimerCount()).toBe(1);
  ui.unmount();
  expect(jest.getTimerCount()).toBe(0);
});
