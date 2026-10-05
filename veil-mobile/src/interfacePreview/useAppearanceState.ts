import { Dispatch, SetStateAction, useEffect, useRef, useState } from 'react';
import { AppearancePreferences, defaultPreferences } from './appearancePreferences';
export type AppearanceStorage = { loadPreferences: () => Promise<AppearancePreferences>; savePreferences: (value: AppearancePreferences) => Promise<string | null> };

export function useAppearanceState(storage: AppearanceStorage) {
  const [preferences, setPreferences] =
    useState<AppearancePreferences>(defaultPreferences);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState('');
  const mounted = useRef(true);
  const pending = useRef<AppearancePreferences | null>(null);
  const saving = useRef(false);
  const hydrated = useRef<AppearancePreferences>(defaultPreferences);
  const loadRevision = useRef(0);
  useEffect(() => {
    mounted.current = true;
    const revision = ++loadRevision.current;
    let settled = false;
    const valid = () => mounted.current && loadRevision.current === revision && !settled;
    const deadline = setTimeout(() => {
      if (!valid()) return;
      settled = true;
      setError('Локальное оформление пока недоступно. Используется стандартная тема.');
      setReady(true);
    }, 5000);
    storage.loadPreferences()
      .then((value) => {
        if (!valid()) return;
        hydrated.current = value;
        setPreferences(value);
      })
      .catch(() => {
        if (valid())
          setError(
            'Настройки пока только в памяти: локальное хранилище недоступно.',
          );
      })
      .finally(() => {
        if (valid()) setReady(true);
        settled = true;
        clearTimeout(deadline);
      });
    return () => {
      mounted.current = false;
      loadRevision.current += 1;
      clearTimeout(deadline);
      pending.current = null;
    };
  }, [storage]);
  useEffect(() => {
    if (!ready || preferences === hydrated.current) return;
    const timer = setTimeout(() => {
      pending.current = preferences;
      const flush = async () => {
        if (saving.current) return;
        saving.current = true;
        try {
          while (mounted.current && pending.current) {
            const value = pending.current;
            pending.current = null;
            try {
              const wallpaper = await storage.savePreferences(value);
              if (mounted.current) {
                setError('');
                setPreferences((current) =>
                  current === value && current.wallpaper !== wallpaper
                    ? { ...current, wallpaper }
                    : current,
                );
              }
            } catch {
              if (mounted.current)
                setError(
                  'Не удалось сохранить оформление. Изменения остаются в памяти.',
                );
            }
          }
        } finally {
          saving.current = false;
        }
      };
      void flush();
    }, 300);
    return () => clearTimeout(timer);
  }, [preferences, ready, storage]);
  function setter<K extends keyof AppearancePreferences>(
    key: K,
  ): Dispatch<SetStateAction<AppearancePreferences[K]>> {
    return (value) =>
      setPreferences((current) => ({
        ...current,
        [key]:
          typeof value === 'function'
            ? (
                value as (
                  old: AppearancePreferences[K],
                ) => AppearancePreferences[K]
              )(current[key])
            : value,
      }));
  }
  return {
    ...preferences,
    ready,
    error,
    setTheme: setter('theme'),
    setDim: setter('dim'),
    setBlur: setter('blur'),
    setShowWallpaper: setter('showWallpaper'),
    setReduceMotion: setter('reduceMotion'),
    setWallpaper: setter('wallpaper'),
  };
}
