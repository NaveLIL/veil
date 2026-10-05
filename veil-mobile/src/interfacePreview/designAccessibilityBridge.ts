import { AccessibilityInfo, NativeModules, View } from 'react-native';

/** Platform UI focus only; this capability is absent from the account runtime. */
export function requestDesignAccessibilityFocus(target: View, handle: number) {
  const host = NativeModules.VeilDesignAccessibility as
    | { focusView: (tag: number) => Promise<boolean> }
    | undefined;
  if (host?.focusView) void host.focusView(handle).catch(() => {});
  else AccessibilityInfo.sendAccessibilityEvent(target, 'focus');
}
