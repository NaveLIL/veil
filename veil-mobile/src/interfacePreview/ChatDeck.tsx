import React, { useEffect } from 'react';
import { Keyboard, StyleSheet, useWindowDimensions, View } from 'react-native';
import { Gesture, GestureDetector } from 'react-native-gesture-handler';
import Animated, { cancelAnimation, ReduceMotion, runOnJS, useAnimatedStyle, useSharedValue, withSpring } from 'react-native-reanimated';
import { swipeDestination } from './navigation';

type Props = { navigation: React.ReactNode; conversation: React.ReactNode; navigationOpen: boolean;
  hasChat: boolean; enabled: boolean; reduceMotion: boolean; onNavigationChange: (open: boolean) => void };
/** Both layers retain their native views and scroll positions between swipes. */
export function ChatDeck({ navigation, conversation, navigationOpen, hasChat, enabled, reduceMotion, onNavigationChange }: Props) {
  const { width: screenWidth } = useWindowDimensions();
  const width = Math.max(1, screenWidth - 12);
  const progress = useSharedValue(navigationOpen ? 1 : 0);
  const start = useSharedValue(1);
  const target = useSharedValue(navigationOpen ? 1 : 0);
  const spring = { stiffness: 260, damping: 30, mass: 1, overshootClamping: true,
    reduceMotion: reduceMotion ? ReduceMotion.Always : ReduceMotion.System };
  useEffect(() => {
    const next = navigationOpen ? 1 : 0;
    if (target.value !== next || reduceMotion) {
      target.value = next;
      progress.value = reduceMotion ? next : withSpring(next, spring);
    }
    // A completed gesture already set target; don't replace its velocity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navigationOpen, reduceMotion, progress, target]);
  const pan = Gesture.Pan().enabled(enabled && hasChat).maxPointers(1)
    .activeOffsetX([-14, 14]).failOffsetY([-10, 10])
    .onStart(() => { cancelAnimation(progress); start.value = progress.value; runOnJS(Keyboard.dismiss)(); })
    .onUpdate(event => { progress.value = Math.max(0, Math.min(1, start.value + event.translationX / width)); })
    .onEnd(event => {
      const open = swipeDestination(progress.value, event.velocityX, width);
      target.value = open ? 1 : 0;
      progress.value = reduceMotion ? target.value : withSpring(target.value, { ...spring, velocity: event.velocityX / width });
      runOnJS(onNavigationChange)(open);
    })
    .onFinalize((_event, success) => {
      if (!success) progress.value = reduceMotion ? target.value : withSpring(target.value, spring);
    });
  const chatStyle = useAnimatedStyle(() => ({ transform: [{ translateX: progress.value * width }] }));
  const navigationStyle = useAnimatedStyle(() => ({ transform: [{ translateX: hasChat ? (progress.value - 1) * 12 : 0 }] }));
  return <GestureDetector gesture={pan}><View style={styles.root} collapsable={false}>
    <Animated.View testID="navigation-layer" pointerEvents={navigationOpen ? 'auto' : 'none'}
      accessibilityElementsHidden={!navigationOpen} importantForAccessibility={navigationOpen ? 'auto' : 'no-hide-descendants'} style={[styles.layer, navigationStyle]}>{navigation}</Animated.View>
    {hasChat && <Animated.View testID="chat-layer" pointerEvents={navigationOpen ? 'none' : 'auto'}
      accessibilityElementsHidden={navigationOpen} importantForAccessibility={navigationOpen ? 'no-hide-descendants' : 'auto'} style={[styles.layer, styles.chat, chatStyle]}>{conversation}</Animated.View>}
  </View></GestureDetector>;
}
const styles = StyleSheet.create({ root: { flex: 1, overflow: 'hidden' }, layer: { ...StyleSheet.absoluteFillObject },
  chat: { shadowColor: '#000000', shadowOpacity: 0.4, shadowRadius: 20, shadowOffset: { width: -6, height: 0 }, elevation: 12 } });
