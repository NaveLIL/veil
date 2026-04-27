import React, { useEffect, useRef } from "react";
import { Animated, Easing, StyleSheet, View } from "react-native";
import { LinearGradient } from "expo-linear-gradient";

/**
 * Two soft purple glow blobs that pulse in and out of phase, mirroring
 * the desktop onboarding background.
 */
export const GlowBlobs: React.FC = () => {
  return (
    <View pointerEvents="none" style={StyleSheet.absoluteFill}>
      <Blob
        size={500}
        top="12%"
        left="20%"
        opacity={0.18}
        delay={0}
        duration={6000}
      />
      <Blob
        size={420}
        top="55%"
        left="40%"
        opacity={0.12}
        delay={2000}
        duration={8000}
      />
    </View>
  );
};

const Blob: React.FC<{
  size: number;
  top: string;
  left: string;
  opacity: number;
  delay: number;
  duration: number;
}> = ({ size, top, left, opacity, delay, duration }) => {
  const v = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    const loop = Animated.loop(
      Animated.sequence([
        Animated.timing(v, {
          toValue: 1,
          duration: duration / 2,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
          delay,
        }),
        Animated.timing(v, {
          toValue: 0,
          duration: duration / 2,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
        }),
      ]),
    );
    loop.start();
    return () => loop.stop();
  }, [v, duration, delay]);

  const scale = v.interpolate({ inputRange: [0, 1], outputRange: [1, 1.06] });
  const op = v.interpolate({
    inputRange: [0, 1],
    outputRange: [opacity * 0.6, opacity],
  });

  return (
    <Animated.View
      style={{
        position: "absolute",
        width: size,
        height: size,
        // @ts-expect-error: percentage strings are valid for absolute positioning.
        top,
        // @ts-expect-error: percentage strings are valid for absolute positioning.
        left,
        opacity: op,
        transform: [{ scale }, { translateX: -size / 2 }, { translateY: -size / 2 }],
      }}
    >
      <LinearGradient
        colors={["rgba(124,107,245,0.55)", "rgba(124,107,245,0)"]}
        start={{ x: 0.5, y: 0.5 }}
        end={{ x: 1, y: 1 }}
        style={{ flex: 1, borderRadius: size / 2 }}
      />
    </Animated.View>
  );
};
