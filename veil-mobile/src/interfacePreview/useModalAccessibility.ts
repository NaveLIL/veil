import { useEffect, useRef } from 'react';
import { AccessibilityInfo, Text } from 'react-native';
import { useAccessibilityFocus } from './AccessibilityFocusBoundary';

/** Focus belongs to the visible modal, then returns to its explicit trigger. */
export function useModalAccessibility(open: boolean, returnFocus?: number) {
  const heading = useRef<Text>(null);
  const wasOpen = useRef(false);
  const focus = useAccessibilityFocus();
  useEffect(() => {
    if (wasOpen.current && !open && returnFocus) focus.restore(returnFocus);
    wasOpen.current = open;
  }, [open, returnFocus, focus]);
  useEffect(
    () => () => {
      if (wasOpen.current && returnFocus) focus.restore(returnFocus);
    },
    [returnFocus, focus],
  );
  return {
    heading,
    onShow: () => {
      focus.cancel();
      if (heading.current)
        AccessibilityInfo.sendAccessibilityEvent(heading.current, 'focus');
    },
  };
}
