import React, { useEffect, useMemo, useRef } from "react";
import { Animated, Dimensions, Easing, StyleSheet, Text, View } from "react-native";

const HEBREW_WORDS = [
  "שמירה", "מגן", "סוד", "חומה",
  "מפתח", "הצפנה", "ביטחון", "חותם",
  "שלום", "אמת", "חוזק", "מסתור",
  "מחסה", "צופן", "משמר", "סודי",
  "נאמן", "חופש", "פרטי", "זהות",
  "אמון", "מבצר", "שריון", "עוגן",
  "מגדל", "רשת", "ענן", "חיבור",
  "קשר", "דלת", "נעילה", "פתיחה",
];

interface Drop {
  word: string;
  xPct: number;
  delay: number;
  duration: number;
  size: number;
  opacity: number;
}

interface Props {
  count?: number;
  height: number;
}

export const HebrewRain: React.FC<Props> = ({ count = 36, height }) => {
  const drops = useMemo<Drop[]>(
    () =>
      Array.from({ length: count }, () => ({
        word: HEBREW_WORDS[Math.floor(Math.random() * HEBREW_WORDS.length)],
        xPct: Math.random() * 100,
        delay: Math.random() * 12000,
        duration: 8000 + Math.random() * 14000,
        size: 12 + Math.random() * 6,
        opacity: 0.05 + Math.random() * 0.1,
      })),
    [count],
  );

  return (
    <View pointerEvents="none" style={StyleSheet.absoluteFill}>
      {drops.map((d, i) => (
        <RainDrop key={i} drop={d} viewportH={height} />
      ))}
    </View>
  );
};

const RainDrop: React.FC<{ drop: Drop; viewportH: number }> = ({ drop, viewportH }) => {
  const v = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    let cancelled = false;
    const start = () => {
      v.setValue(0);
      const anim = Animated.timing(v, {
        toValue: 1,
        duration: drop.duration,
        easing: Easing.linear,
        useNativeDriver: true,
      });
      anim.start(({ finished }) => {
        if (!cancelled && finished) start();
      });
    };
    const t = setTimeout(start, drop.delay);
    return () => {
      cancelled = true;
      clearTimeout(t);
      v.stopAnimation();
    };
  }, [v, drop.delay, drop.duration]);

  const translateY = v.interpolate({
    inputRange: [0, 1],
    outputRange: [-60, viewportH + 60],
  });
  const opacity = v.interpolate({
    inputRange: [0, 0.05, 0.9, 1],
    outputRange: [0, drop.opacity, drop.opacity, 0],
  });

  return (
    <Animated.View
      style={[
        styles.drop,
        {
          left: `${drop.xPct}%`,
          opacity,
          transform: [{ translateY }],
        },
      ]}
    >
      <Text
        style={{
          fontSize: drop.size,
          color: "#7c6bf5",
          // Stack glyphs vertically — RN has no writing-mode, so each
          // character on its own line gives the same visual.
        }}
      >
        {drop.word.split("").join("\n")}
      </Text>
    </Animated.View>
  );
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _w = Dimensions.get("window").width;

const styles = StyleSheet.create({
  drop: {
    position: "absolute",
    top: 0,
  },
});
