import React, { useEffect, useRef, useState } from 'react';
import {
  AccessibilityInfo,
  Animated,
} from 'react-native';
import { WallpaperSurface } from './WallpaperSurface';
import { motion, palettes } from './appearance';
import { AppearanceSettings } from './AppearanceSettings';
import { useAppearancePreferences } from './useAppearancePreferences';
import { pickWallpaper } from './appearanceBridge';

/** Appearance owns hydration, picker lifetime and motion; no conversation data. */
export function useDesignAppearance(
  destination: string,
  locked: boolean,
  actions: {
    onLock: () => void;
    onScenarios: () => void;
    onAbout: () => void;
  },
) {
  const preferences = useAppearancePreferences();
  const { theme, wallpaper, showWallpaper, dim, blur, reduceMotion, ready } =
    preferences;
  const [systemReduceMotion, setSystemReduceMotion] = useState(false);
  const [pickerError, setPickerError] = useState('');
  const [picking, setPicking] = useState(false);
  const mounted = useRef(true);
  const pickerPending = useRef(false);
  const transition = useRef(new Animated.Value(1)).current;
  const c = palettes[theme];
  const noMotion = reduceMotion || systemReduceMotion;
  useEffect(() => {
    mounted.current = true;
    AccessibilityInfo.isReduceMotionEnabled()
      .then((value) => {
        if (mounted.current) setSystemReduceMotion(value);
      })
      .catch(() => {});
    const subscription = AccessibilityInfo.addEventListener(
      'reduceMotionChanged',
      setSystemReduceMotion,
    );
    return () => {
      mounted.current = false;
      subscription.remove();
    };
  }, []);
  useEffect(() => {
    transition.stopAnimation();
    if (noMotion) {
      transition.setValue(1);
      return;
    }
    transition.setValue(0);
    const animation = Animated.timing(transition, {
      toValue: 1,
      duration: motion.transitionDuration,
      useNativeDriver: true,
    });
    animation.start();
    return () => animation.stop();
  }, [destination, locked, noMotion, transition]);
  async function chooseWallpaper() {
    if (pickerPending.current) return;
    pickerPending.current = true;
    setPicking(true);
    setPickerError('');
    try {
      const uri = await pickWallpaper();
      if (mounted.current && uri) {
        preferences.setWallpaper(uri);
        preferences.setShowWallpaper(true);
      }
    } catch {
      if (mounted.current)
        setPickerError(
          'Не удалось открыть изображение. Выберите другое или меньшего размера.',
        );
    } finally {
      pickerPending.current = false;
      if (mounted.current) setPicking(false);
    }
  }
  const settings = (
    <AppearanceSettings
      {...preferences}
      c={c}
      systemReduceMotion={systemReduceMotion}
      picking={picking}
      pickerError={pickerError || preferences.error}
      chooseWallpaper={chooseWallpaper}
      {...actions}
    />
  );
  const animatedStyle = {
    opacity: transition,
    transform: [
      {
        translateY: transition.interpolate({
          inputRange: [0, 1],
          outputRange: [8, 0],
        }),
      },
    ],
  };
  const background = <WallpaperSurface c={c} wallpaper={wallpaper} showWallpaper={showWallpaper && !locked} blur={blur} dim={dim} />;
  return { c, ready, noMotion, animatedStyle, settings, background };
}
