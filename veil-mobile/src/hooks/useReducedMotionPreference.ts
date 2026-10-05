import { useEffect, useState } from "react";
import { AccessibilityInfo } from "react-native";
import { useMobileSettingsStore } from '../stores/settings';

export function useSystemReducedMotion(): boolean {
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    let active = true;
    void AccessibilityInfo.isReduceMotionEnabled()
      .then((enabled) => {
        if (active) setReducedMotion(enabled);
      })
      .catch(() => undefined);
    const subscription = AccessibilityInfo.addEventListener(
      "reduceMotionChanged",
      setReducedMotion,
    );
    return () => {
      active = false;
      subscription.remove();
    };
  }, []);

  return reducedMotion;
}

export function useReducedMotionPreference(): boolean {
  const local = useMobileSettingsStore((s) => s.reduceMotion);
  return useSystemReducedMotion() || local;
}
