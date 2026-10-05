import React, { createContext, useContext, useEffect, useRef, useState } from 'react';
import { useAppearanceState } from '../../interfacePreview/useAppearanceState';
import { palettes } from '../../interfacePreview/appearance';
import { AppearanceSettings } from '../../interfacePreview/AppearanceSettings';
import { PresentationBoundary } from '../../interfacePreview/PresentationContext';
import { accountAppearanceStorage, pickAccountWallpaper } from './storage';
import { useReducedMotionPreference, useSystemReducedMotion } from '../../hooks/useReducedMotionPreference';
import { useMobileSettingsStore } from '../../stores/settings';

type State = ReturnType<typeof useAppearanceState> & { picking: boolean; pickerError: string; chooseWallpaper: () => Promise<void> };
const Context = createContext<State | null>(null);
/** Device-local public appearance only. It outlives account scopes, never stores conversation data. */
export function AccountAppearanceProvider({ children }: { children: React.ReactNode }) {
  const state = useAppearanceState(accountAppearanceStorage);
  const [picking, setPicking] = useState(false), [pickerError, setPickerError] = useState('');
  const alive = useRef(true), pending = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  // OS picker locks the account shell. Its device-local appearance owner survives;
  // conversations and old modals still follow the existing privacy gate.
  const chooseWallpaper = async () => {
    if (pending.current) return;
    pending.current = true; setPicking(true); setPickerError('');
    try { const uri = await pickAccountWallpaper(); if (alive.current && uri) { state.setWallpaper(uri); state.setShowWallpaper(true); } }
    catch { if (alive.current) setPickerError('Не удалось выбрать изображение. Оформление не изменено.'); }
    finally { pending.current = false; if (alive.current) setPicking(false); }
  };
  const reduceMotion = useReducedMotionPreference();
  const setReduce = useMobileSettingsStore((s) => s.setReduceMotion);
  useEffect(() => { if (state.ready) setReduce(state.reduceMotion); }, [state.ready, state.reduceMotion, setReduce]);
  return <Context.Provider value={{ ...state, picking, pickerError, chooseWallpaper }}>
    <PresentationBoundary c={palettes[state.theme]} reduceMotion={reduceMotion}>{children}</PresentationBoundary>
  </Context.Provider>;
}
export function useAccountAppearance() {
  const value = useContext(Context);
  if (!value) throw Error('Appearance provider missing');
  return value;
}
export function AccountAppearanceSettings({ onLock, onAbout }: { onLock: () => void; onAbout: () => void }) {
  const state = useAccountAppearance();
  const systemReduceMotion = useSystemReducedMotion();
  return <AppearanceSettings {...state} c={palettes[state.theme]} ownershipLabel="Настройки этого устройства"
    pickerError={state.pickerError || state.error} lockLabel="Аккаунт и безопасность"
    systemReduceMotion={systemReduceMotion} onLock={onLock} onAbout={onAbout} />;
}
