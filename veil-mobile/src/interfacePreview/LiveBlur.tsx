import React, { createContext, useContext, useId, useLayoutEffect, useState } from 'react';
import { Platform, requireNativeComponent, View, ViewProps } from 'react-native';
import Animated from 'react-native-reanimated';
import { motion } from './appearance';
import { usePresentation } from './PresentationContext';

type Props = ViewProps & { blurRadius?: number; blurTransitionMs?: number };
const NativeBlur: React.ComponentType<Props> = Platform.OS === 'android'
  ? requireNativeComponent<Props>('VeilLiveBlurView') : View;
export const LiveBlur = Animated.createAnimatedComponent(NativeBlur);
type Owner = { id: string; engaged: boolean; reduceMotion: boolean };
const Backdrop = createContext<{ owners: Owner[]; change: (id: string, owner?: Omit<Owner, 'id'>) => void }>({ owners: [], change: () => {} });

/** Count simultaneous modal owners; closing one must not reveal another's background. */
export function ModalBlurBoundary({ children }: { children: React.ReactNode }) {
  const [{ owners, lastReduceMotion }, setBackdrop] = useState({ owners: [] as Owner[], lastReduceMotion: false });
  const { reduceMotion } = usePresentation();
  const change = React.useCallback((id: string, next?: Omit<Owner, 'id'>) => {
    setBackdrop(state => {
      const previous = state.owners.find(owner => owner.id === id);
      // Retain the final owner's preference for its unblur frame: immediate
      // dismissal can remove that owner before a separate closing render.
      const lastReduceMotion = next?.reduceMotion ?? previous?.reduceMotion ?? state.lastReduceMotion;
      if (!next) return previous ? { owners: state.owners.filter(owner => owner.id !== id), lastReduceMotion } : state;
      if (!previous) return { owners: [...state.owners, { id, ...next }], lastReduceMotion };
      if (previous.engaged === next.engaged && previous.reduceMotion === next.reduceMotion) return state;
      // Update in place: a closing/reopening lower sheet must not become the top owner.
      return { owners: state.owners.map(owner => owner.id === id ? { id, ...next } : owner), lastReduceMotion };
    });
  }, []);
  const value = React.useMemo(() => ({ owners, change }), [owners, change]);
  return <Backdrop.Provider value={value}>
    <LiveBlur testID="modal-blur-background" blurRadius={owners.some(owner => owner.engaged) ? 12 : 0}
      blurTransitionMs={reduceMotion || lastReduceMotion || owners.some(owner => owner.reduceMotion) ? 0 : motion.transitionDuration}
      style={{ flex: 1 }}>
      {children}
    </LiveBlur>
  </Backdrop.Provider>;
}
export function useModalBackdrop(presented: boolean, engaged = presented, reduceMotion = false) {
  const { owners, change } = useContext(Backdrop);
  const id = useId();
  useLayoutEffect(() => {
    change(id, presented ? { engaged, reduceMotion } : undefined);
  }, [presented, engaged, reduceMotion, change, id]);
  useLayoutEffect(() => () => change(id), [change, id]);
  const index = owners.findIndex(owner => owner.id === id);
  return index >= 0 && owners.slice(index + 1).some(owner => owner.engaged) ? 12 : 0;
}
