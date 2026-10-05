import { expect, test, jest } from '@jest/globals';
import { NativeModules } from 'react-native';
import {
  parsePreferences,
  savePreferences,
  defaultPreferences,
} from './preferencesBridge';
test('unknown/corrupt legacy settings use defaults and reject non-owned image paths', () => {
  expect(parsePreferences(null)).toEqual(defaultPreferences);
  expect(
    parsePreferences({
      theme: 'constructor',
      dim: Infinity,
      blur: -1,
      showWallpaper: 'yes',
      wallpaper: 'https://example.invalid/a.jpg',
    }),
  ).toEqual(defaultPreferences);
  expect(
    parsePreferences({ theme: 'Forest', dim: 90, blur: 24, reduceMotion: true })
      .theme,
  ).toBe('Forest');
});
test('save sends exactly the public appearance allowlist, never extra data', async () => {
  const save = jest
    .fn<(value: string) => Promise<null>>()
    .mockResolvedValue(null);
  NativeModules.VeilDesignPreferences = {
    loadPreferences: jest.fn(),
    savePreferences: save,
  };
  await savePreferences({
    ...defaultPreferences,
    draft: 'secret-like test sentinel',
  } as typeof defaultPreferences);
  expect(JSON.parse(save.mock.calls[0][0] as string)).toEqual(
    defaultPreferences,
  );
});
