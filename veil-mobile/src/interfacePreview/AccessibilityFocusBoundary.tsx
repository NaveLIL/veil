import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
} from 'react';
import { AccessibilityInfo, findNodeHandle, View } from 'react-native';

const FocusContext = createContext({
  cancel: () => {},
  remember: (ref: React.RefObject<View | null>) =>
    findNodeHandle(ref.current) ?? undefined,
  restore: (handle: number) => AccessibilityInfo.setAccessibilityFocus(handle),
});
/** Android modal dismissal completes after the JS visibility update. */
export function AccessibilityFocusBoundary({
  children,
  requestFocus,
}: {
  children: React.ReactNode;
  requestFocus?: (target: View, handle: number) => void;
}) {
  const pending = useRef<ReturnType<typeof setTimeout> | null>(null);
  const targets = useRef(new Map<number, React.RefObject<View | null>>());
  const remember = useCallback((ref: React.RefObject<View | null>) => {
    const handle = findNodeHandle(ref.current);
    if (!handle) return undefined;
    targets.current.delete(handle);
    targets.current.set(handle, ref);
    if (targets.current.size > 32)
      targets.current.delete(targets.current.keys().next().value!);
    return handle;
  }, []);
  const cancel = useCallback(() => {
    if (pending.current) clearTimeout(pending.current);
    pending.current = null;
  }, []);
  useEffect(() => cancel, [cancel]);
  const restore = useCallback(
    (handle: number) => {
      cancel();
      pending.current = setTimeout(() => {
        pending.current = null;
        const target = targets.current.get(handle);
        if (target) {
          if (target.current) {
            if (requestFocus) requestFocus(target.current, handle);
            else
              AccessibilityInfo.sendAccessibilityEvent(target.current, 'focus');
          }
        } else AccessibilityInfo.setAccessibilityFocus(handle);
      }, 350);
    },
    [cancel, requestFocus],
  );
  const value = useMemo(
    () => ({ cancel, restore, remember }),
    [cancel, restore, remember],
  );
  return (
    <FocusContext.Provider value={value}>{children}</FocusContext.Provider>
  );
}
export const useAccessibilityFocus = () => useContext(FocusContext);
