import { act, renderHook } from '@testing-library/react-native';
import { afterEach, expect, jest, test } from '@jest/globals';
import { useAppearanceState, AppearanceStorage } from './useAppearanceState';
import { defaultPreferences, AppearancePreferences } from './appearancePreferences';
afterEach(() => { jest.useRealTimers(); });
test('a blocked appearance read has a bounded safe fallback and cannot replace it with a stale late value', async () => {
  jest.useFakeTimers();
  let resolve: ((value: AppearancePreferences) => void) | undefined;
  const savePreferences = jest.fn<() => Promise<string | null>>().mockResolvedValue(null);
  const storage = {loadPreferences:() => new Promise<AppearancePreferences>(done => {resolve=done;}), savePreferences};
  const hook = renderHook(() => useAppearanceState(storage));
  expect(hook.result.current.ready).toBe(false);
  act(() => { jest.advanceTimersByTime(5000); });
  expect(hook.result.current).toMatchObject({ready:true, theme:'OLED', wallpaper:null});
  await act(async () => { resolve?.({...defaultPreferences,theme:'Ocean'}); });
  expect(hook.result.current.theme).toBe('OLED');
  act(() => { jest.advanceTimersByTime(1000); });
  expect(savePreferences).not.toHaveBeenCalled();
});
test('a replaced storage owner rejects the first owners late settings', async () => {
  let old: ((value: AppearancePreferences) => void) | undefined;
  const first = {loadPreferences:() => new Promise<AppearancePreferences>(done => {old=done;}), savePreferences:async()=>null};
  const next = {loadPreferences:async()=>({...defaultPreferences,theme:'Forest' as const}), savePreferences:async()=>null};
  const hook=renderHook(({storage}: {storage:AppearanceStorage})=>useAppearanceState(storage),{initialProps:{storage:first as AppearanceStorage}});
  await act(async () => {hook.rerender({storage:next});});
  await act(async () => {old?.({...defaultPreferences,theme:'Ocean'});});
  expect(hook.result.current.theme).toBe('Forest');
});
