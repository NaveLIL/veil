import React, { useMemo } from "react";
import { StyleSheet, View } from "react-native";
import Svg, { Circle, Defs, LinearGradient, Rect, Stop } from "react-native-svg";
import { createPhaseprintModel, type PhaseprintIdentity } from "./Phaseprint";

interface UserAvatarProps extends PhaseprintIdentity {
  size?: number;
  statusColor?: string;
  label?: string;
}

export const UserAvatar: React.FC<UserAvatarProps> = ({
  identityKey,
  canonicalServerOrigin,
  userId,
  technicalUsername,
  size = 40,
  statusColor,
  label,
}) => {
  const model = useMemo(
    () => createPhaseprintModel({ identityKey, canonicalServerOrigin, userId, technicalUsername }),
    [identityKey, canonicalServerOrigin, userId, technicalUsername],
  );
  return (
    <View
      accessible={Boolean(label)}
      accessibilityRole={label ? "image" : undefined}
      accessibilityLabel={label}
      importantForAccessibility={label ? "yes" : "no"}
      style={{ width: size, height: size }}
    >
      <Svg width={size} height={size} viewBox="0 0 64 64" aria-hidden={!label}>
        <Defs>
          <LinearGradient
            id="phaseprint-background"
            x1="0"
            y1="0"
            x2="1"
            y2="1"
            gradientTransform={`rotate(${model.angle - 135} 0.5 0.5)`}
          >
            <Stop offset="0" stopColor={model.background} />
            <Stop offset="1" stopColor={model.wash} />
          </LinearGradient>
        </Defs>
        <Circle cx="32" cy="32" r="32" fill="url(#phaseprint-background)" />
        <Circle cx={model.orbX} cy={model.orbY} r={model.orbRadius} fill={model.glow} opacity={0.16} />
        <Circle
          cx="32"
          cy="32"
          r={model.orbitRadius}
          fill="none"
          stroke={model.ink}
          strokeWidth="1.4"
          strokeDasharray={`${model.orbitDash} ${model.orbitGap}`}
          opacity={0.34}
          rotation={model.orbitRotation}
          origin="32, 32"
        />
        {model.cells.map((cell) => (
          <Rect key={`${cell.x}-${cell.y}`} x={cell.x} y={cell.y} width="8" height="8" rx="2.25" fill={cell.fill} opacity={cell.opacity} />
        ))}
      </Svg>
      {statusColor ? <View style={[styles.status, { backgroundColor: statusColor }]} /> : null}
    </View>
  );
};

const styles = StyleSheet.create({
  status: {
    position: "absolute",
    right: -1,
    bottom: -1,
    width: 12,
    height: 12,
    borderRadius: 6,
    borderWidth: 2,
    borderColor: "#2B2D31",
  },
});
