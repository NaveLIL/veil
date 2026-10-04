import React, { useCallback, useEffect } from 'react';
import { Keyboard, StyleProp, StyleSheet, useWindowDimensions, View, ViewStyle } from 'react-native';
import { Gesture, GestureDetector } from 'react-native-gesture-handler';
import Animated, { cancelAnimation, ReduceMotion, runOnJS, useAnimatedStyle, useSharedValue, withSpring } from 'react-native-reanimated';
import { swipeDestination } from './navigation';
import { geometry } from './appearance';

type Props = { navigation: (dimStyle: StyleProp<ViewStyle>) => React.ReactNode; profile: React.ReactNode; conversation: React.ReactNode; navigationOpen: boolean;
  surfaceColor: string; edgeColor: string;
  hasChat: boolean; enabled: boolean; reduceMotion: boolean; onNavigationChange: (open: boolean) => void };
/** Both layers retain their native views and scroll positions between swipes. */
export function ChatDeck({ navigation, profile, conversation, navigationOpen, surfaceColor, edgeColor, hasChat, enabled, reduceMotion, onNavigationChange }: Props) {
  const { width: screenWidth } = useWindowDimensions();
  // Travel through the physical viewport, not the inset navigation frame.
  const width = Math.max(1, screenWidth);
  const progress = useSharedValue(navigationOpen ? 1 : 0);
  const start = useSharedValue(1);
  const target = useSharedValue(navigationOpen ? 1 : 0);
  // Capture a JS function, never the native Keyboard object, in a UI worklet.
  const dismissKeyboard = useCallback(() => { Keyboard.dismiss(); }, []);
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
    .onStart(() => { cancelAnimation(progress); start.value = progress.value; runOnJS(dismissKeyboard)(); })
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
  // Dim opaque islands; fading their surfaces would leak wallpaper through text.
  const backdropStyle = useAnimatedStyle(() => ({ opacity: hasChat ? (1 - progress.value) * 0.48 : 0 }));
  return <GestureDetector gesture={pan}><View style={styles.root} collapsable={false}>
    <View testID="navigation-layer" pointerEvents={navigationOpen ? 'auto' : 'none'}
      accessibilityElementsHidden={!navigationOpen} importantForAccessibility={navigationOpen ? 'auto' : 'no-hide-descendants'} style={styles.layer}>
      {navigation(backdropStyle)}
    </View>
    <View testID="profile-layer" pointerEvents={navigationOpen ? 'box-none' : 'none'}
      accessibilityElementsHidden={!navigationOpen} importantForAccessibility={navigationOpen ? 'auto' : 'no-hide-descendants'} style={[styles.layer, styles.profile]}>{profile}</View>
    {hasChat && <Animated.View testID="chat-layer" pointerEvents={navigationOpen ? 'none' : 'auto'}
      accessibilityElementsHidden={navigationOpen} importantForAccessibility={navigationOpen ? 'no-hide-descendants' : 'auto'} style={[styles.layer, styles.chat, { backgroundColor: surfaceColor, borderColor: edgeColor }, chatStyle]}>
      <View style={styles.chatClip}>{conversation}</View>
    </Animated.View>}
  </View></GestureDetector>;
}
const styles = StyleSheet.create({ root: { flex: 1, marginHorizontal: -geometry.inset, overflow: 'hidden' }, layer: { ...StyleSheet.absoluteFillObject, left: geometry.inset, right: geometry.inset },
  profile: { zIndex: 1 },
  chat: { zIndex: 2, borderRadius: geometry.radius, borderWidth: geometry.borderWidth, shadowColor: '#000000', shadowOpacity: 0.55, shadowRadius: 18, shadowOffset: { width: -8, height: 0 }, elevation: 12 },
  // The inset curve is concentric with the common outer radius.
  chatClip: { flex: 1, borderRadius: geometry.radius - geometry.borderWidth, overflow: 'hidden' } });
