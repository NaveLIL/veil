import React, { createContext, useContext, useMemo } from 'react';
import { Palette, palettes } from './appearance';
const Context = createContext({ c: palettes.OLED as Palette, reduceMotion: false });
export function PresentationBoundary({ c, reduceMotion, children }: {
  c: Palette; reduceMotion: boolean; children: React.ReactNode;
}) {
  const value = useMemo(() => ({ c, reduceMotion }), [c, reduceMotion]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}
export function usePresentation() { return useContext(Context); }
