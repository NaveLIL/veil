import React, { createContext, useContext, useId, useLayoutEffect, useState } from 'react';
import { Platform, requireNativeComponent, View, ViewProps } from 'react-native';
import Animated from 'react-native-reanimated';

type Props = ViewProps & { blurRadius?: number };
const NativeBlur: React.ComponentType<Props> = Platform.OS === 'android'
  ? requireNativeComponent<Props>('VeilLiveBlurView') : View;
export const LiveBlur = Animated.createAnimatedComponent(NativeBlur);
const Backdrop = createContext<{ owners: string[]; change: (id: string, active: boolean) => void }>({ owners: [], change: () => {} });

/** Count simultaneous modal owners; closing one must not reveal another's background. */
export function ModalBlurBoundary({ children }: { children: React.ReactNode }) {
  const [owners, setOwners] = useState<string[]>([]);
  const change = React.useCallback((id: string, active: boolean) => {
    setOwners(value => active ? value.includes(id) ? value : [...value, id] : value.filter(owner => owner !== id));
  }, []);
  const value = React.useMemo(() => ({ owners, change }), [owners, change]);
  return <Backdrop.Provider value={value}>
    <LiveBlur testID="modal-blur-background" blurRadius={owners.length > 0 ? 12 : 0} style={{ flex: 1 }}>
      {children}
    </LiveBlur>
  </Backdrop.Provider>;
}
export function useModalBackdrop(active: boolean) {
  const { owners, change } = useContext(Backdrop);
  const id = useId();
  useLayoutEffect(() => {
    if (!active) return;
    change(id, true);
    return () => change(id, false);
  }, [active, change, id]);
  return owners.includes(id) && owners[owners.length - 1] !== id ? 12 : 0;
}
