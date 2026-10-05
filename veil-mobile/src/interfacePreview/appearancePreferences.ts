import { palettes, ThemeName } from './appearance';
export type AppearancePreferences = {
  theme: ThemeName;
  dim: number;
  blur: number;
  showWallpaper: boolean;
  reduceMotion: boolean;
  wallpaper: string | null;
};
export const defaultPreferences: AppearancePreferences = {
  theme: 'OLED',
  dim: 20,
  blur: 4,
  showWallpaper: true,
  reduceMotion: false,
  wallpaper: null,
};
export function parsePreferences(value: unknown): AppearancePreferences {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    return { ...defaultPreferences };
  const v = value as Record<string, unknown>;
  const number = (key: string, max: number) =>
    typeof v[key] === 'number' &&
    Number.isFinite(v[key]) &&
    v[key] >= 0 &&
    v[key] <= max
      ? (v[key] as number)
      : defaultPreferences[key as 'dim' | 'blur'];
  return {
    theme:
      typeof v.theme === 'string' &&
      Object.prototype.hasOwnProperty.call(palettes, v.theme)
        ? (v.theme as ThemeName)
        : 'OLED',
    dim: number('dim', 90),
    blur: number('blur', 24),
    showWallpaper:
      typeof v.showWallpaper === 'boolean' ? v.showWallpaper : true,
    reduceMotion: typeof v.reduceMotion === 'boolean' ? v.reduceMotion : false,
    wallpaper:
      typeof v.wallpaper === 'string' &&
      /^file:\/\/\/(?:[A-Za-z0-9_.-]+\/)*files\/(?:design-appearance|appearance)\/wallpaper-[a-f0-9-]{36}\.jpg$/.test(
        v.wallpaper,
      ) &&
      !v.wallpaper.split('/').some((p) => p === '..' || p === '.')
        ? v.wallpaper
        : null,
  };
}
