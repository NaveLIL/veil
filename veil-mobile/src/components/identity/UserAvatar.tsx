import React, { useMemo } from "react";
import { StyleSheet, View } from "react-native";
import Svg, { Circle, Rect } from "react-native-svg";

export interface AvatarIdentity {
  identityKey?: string | null;
  userId?: string | null;
  username?: string | null;
}

const palette = ["#7c6bf5", "#59c7d6", "#9b8afb", "#54d6a1", "#d96fb4"];

function seedFor(identity: AvatarIdentity): string {
  return identity.identityKey?.trim().toLowerCase()
    || identity.userId?.trim().toLowerCase()
    || identity.username?.trim().normalize("NFC").toLowerCase()
    || "veil-anonymous";
}

function hashSeed(seed: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < seed.length; i += 1) {
    hash ^= seed.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

export const UserAvatar: React.FC<AvatarIdentity & { size?: number; statusColor?: string }> = ({ size = 40, statusColor, ...identity }) => {
  const seed = seedFor(identity);
  const hash = useMemo(() => hashSeed(seed), [seed]);
  const cells = useMemo(() => Array.from({ length: 15 }, (_, index) => ((hash >>> (index % 24)) ^ Math.imul(index + 1, 2654435761)) & 1), [hash]);
  const primary = palette[hash % palette.length];
  const secondary = palette[(hash >>> 8) % palette.length];
  return (
    <View accessibilityRole="image" accessibilityLabel="Deterministic identity Phaseprint" style={{ width: size, height: size }}>
      <Svg width={size} height={size} viewBox="0 0 48 48">
        <Circle cx="24" cy="24" r="23" fill="#172536" stroke={primary} strokeOpacity={0.6} />
        {cells.map((active, index) => {
          if (!active) return null;
          const row = Math.floor(index / 3);
          const col = index % 3;
          const x = 7 + col * 7;
          const mirrorX = 48 - x - 6;
          return <React.Fragment key={index}>
            <Rect x={x} y={7 + row * 7} width="6" height="6" rx="1.5" fill={index % 2 ? primary : secondary} />
            {col < 2 && <Rect x={mirrorX} y={7 + row * 7} width="6" height="6" rx="1.5" fill={index % 2 ? primary : secondary} />}
          </React.Fragment>;
        })}
      </Svg>
      {statusColor ? <View style={[styles.status, { backgroundColor: statusColor }]} /> : null}
    </View>
  );
};

const styles = StyleSheet.create({ status: { position: "absolute", right: -1, bottom: -1, width: 12, height: 12, borderRadius: 6, borderWidth: 2, borderColor: "#2B2D31" } });
