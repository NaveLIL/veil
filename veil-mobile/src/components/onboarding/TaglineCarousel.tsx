import React, { useEffect, useRef, useState } from "react";
import { Animated, Easing, StyleSheet, Text, View } from "react-native";
import { colors, motion } from "../../lib/theme";

const TAGLINES = [
  { text: "Zero-knowledge encryption", sub: "Your keys never leave this device" },
  { text: "No phone number required", sub: "True anonymity by design" },
  { text: "Open protocol", sub: "Transparent and auditable" },
  { text: "Forward secrecy", sub: "Every message has a unique key" },
  { text: "Decentralized identity", sub: "You own your cryptographic identity" },
];

export const TaglineCarousel: React.FC = () => {
  const [idx, setIdx] = useState(0);
  const fade = useRef(new Animated.Value(1)).current;
  const slide = useRef(new Animated.Value(0)).current;
  const progress = useRef(new Animated.Value((1 / TAGLINES.length) * 100)).current;

  useEffect(() => {
    const id = setInterval(() => {
      Animated.parallel([
        Animated.timing(fade, {
          toValue: 0,
          duration: motion.taglineFadeMs,
          easing: Easing.out(Easing.ease),
          useNativeDriver: true,
        }),
        Animated.timing(slide, {
          toValue: -6,
          duration: motion.taglineFadeMs,
          easing: Easing.out(Easing.ease),
          useNativeDriver: true,
        }),
      ]).start(() => {
        setIdx((i) => {
          const next = (i + 1) % TAGLINES.length;
          Animated.timing(progress, {
            toValue: ((next + 1) / TAGLINES.length) * 100,
            duration: 600,
            easing: Easing.out(Easing.ease),
            useNativeDriver: false,
          }).start();
          return next;
        });
        slide.setValue(6);
        Animated.parallel([
          Animated.timing(fade, {
            toValue: 1,
            duration: motion.taglineFadeMs,
            easing: Easing.out(Easing.ease),
            useNativeDriver: true,
          }),
          Animated.timing(slide, {
            toValue: 0,
            duration: motion.taglineFadeMs,
            easing: Easing.out(Easing.ease),
            useNativeDriver: true,
          }),
        ]).start();
      });
    }, motion.taglineIntervalMs);
    return () => clearInterval(id);
  }, [fade, slide, progress]);

  const tag = TAGLINES[idx];
  const barWidth = progress.interpolate({
    inputRange: [0, 100],
    outputRange: ["0%", "100%"],
  });

  return (
    <View style={styles.wrap}>
      <Animated.View style={{ opacity: fade, transform: [{ translateY: slide }] }}>
        <Text style={styles.text}>{tag.text}</Text>
        <Text style={styles.sub}>{tag.sub}</Text>
      </Animated.View>

      <View style={styles.track}>
        <Animated.View style={[styles.bar, { width: barWidth }]} />
      </View>

      <View style={styles.dots}>
        {TAGLINES.map((_, i) => (
          <View
            key={i}
            style={[
              styles.dot,
              i === idx ? styles.dotActive : null,
            ]}
          />
        ))}
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  wrap: { gap: 14 },
  text: {
    fontSize: 17,
    fontWeight: "600",
    color: colors.textHi,
    textAlign: "center",
  },
  sub: {
    fontSize: 13,
    color: colors.textLo,
    textAlign: "center",
    marginTop: 6,
  },
  track: {
    height: 3,
    borderRadius: 2,
    backgroundColor: "rgba(255,255,255,0.04)",
    overflow: "hidden",
  },
  bar: {
    height: 3,
    backgroundColor: colors.primary,
    borderRadius: 2,
  },
  dots: {
    flexDirection: "row",
    justifyContent: "center",
    gap: 6,
  },
  dot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: "rgba(255,255,255,0.08)",
  },
  dotActive: {
    backgroundColor: colors.primary,
  },
});
