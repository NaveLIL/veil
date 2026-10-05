import { act, renderHook, waitFor } from '@testing-library/react-native';
import { afterEach, beforeEach, expect, jest, test } from '@jest/globals';
import {
  defaultPreferences,
  loadPreferences,
  savePreferences,
} from './preferencesBridge';
import { useAppearancePreferences } from './useAppearancePreferences';
jest.mock('./preferencesBridge', () => ({
  ...jest.requireActual<typeof import('./preferencesBridge')>(
    './preferencesBridge',
  ),
  loadPreferences: jest.fn(),
  savePreferences: jest.fn(),
}));
const load = jest.mocked(loadPreferences);
const save = jest.mocked(savePreferences);
beforeEach(() => {
  jest.useFakeTimers();
  jest.clearAllMocks();
});
afterEach(() => {
  jest.useRealTimers();
});
test('hydration gates default rendering and restores all appearance fields without saving defaults', async () => {
  const saved = {
    ...defaultPreferences,
    theme: 'Ocean' as const,
    dim: 35,
    blur: 8,
    wallpaper: 'file:///managed.jpg',
  };
  let resolve!: (value: typeof saved) => void;
  load.mockImplementationOnce(
    () =>
      new Promise((r) => {
        resolve = r;
      }),
  );
  const { result } = renderHook(useAppearancePreferences);
  expect(result.current.ready).toBe(false);
  await act(async () => {
    resolve(saved);
  });
  expect(result.current).toMatchObject({ ...saved, ready: true });
  await act(async () => {
    jest.advanceTimersByTime(1000);
  });
  expect(save).not.toHaveBeenCalled();
});
test('rapid changes are serialized; an older save cannot overwrite a newer selection', async () => {
  load.mockResolvedValue(defaultPreferences);
  let finish!: (wallpaper: string | null) => void;
  save
    .mockImplementationOnce(
      () =>
        new Promise((r) => {
          finish = r;
        }),
    )
    .mockResolvedValue(null);
  const { result } = renderHook(useAppearancePreferences);
  await waitFor(() => expect(result.current.ready).toBe(true));
  act(() => result.current.setTheme('Ocean'));
  await act(async () => {
    jest.advanceTimersByTime(301);
  });
  act(() => result.current.setTheme('Forest'));
  await act(async () => {
    jest.advanceTimersByTime(301);
  });
  expect(save).toHaveBeenCalledTimes(1);
  await act(async () => {
    finish(null);
  });
  expect(save).toHaveBeenCalledTimes(2);
  expect(result.current.theme).toBe('Forest');
  expect(save.mock.calls[1][0].theme).toBe('Forest');
});
test('storage rejection exits hydration with an honest error and safe default', async () => {
  load.mockRejectedValueOnce(new Error('fixture unavailable'));
  const { result } = renderHook(useAppearancePreferences);
  await waitFor(() => expect(result.current.ready).toBe(true));
  expect(result.current.theme).toBe(defaultPreferences.theme);
  expect(result.current.error).not.toBe('');
  expect(save).not.toHaveBeenCalled();
});
test('unmount discards pending saves and ignores late hydration', async () => {
  let resolve!: (value: typeof defaultPreferences) => void;
  load.mockImplementationOnce(
    () =>
      new Promise((r) => {
        resolve = r;
      }),
  );
  const { unmount } = renderHook(useAppearancePreferences);
  unmount();
  await act(async () => {
    resolve(defaultPreferences);
    jest.advanceTimersByTime(1000);
  });
  expect(save).not.toHaveBeenCalled();
});
