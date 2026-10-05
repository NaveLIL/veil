import { useAppearanceState } from './useAppearanceState';
import { loadPreferences, savePreferences } from './preferencesBridge';
const storage = { loadPreferences, savePreferences };
export function useAppearancePreferences() { return useAppearanceState(storage); }
