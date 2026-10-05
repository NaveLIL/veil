import React from 'react';
import Svg, {
  Defs,
  LinearGradient,
  Stop,
  Rect,
  Path,
  Circle,
} from 'react-native-svg';
/** Bundled vector fixture, no remote loads or full-size bitmap decoding. */
export function AttachmentVisual() {
  return (
    <Svg
      width="100%"
      height="100%"
      viewBox="0 0 960 640"
      accessibilityElementsHidden
      importantForAccessibility="no-hide-descendants"
    >
      <Defs>
        <LinearGradient id="sky" x1="0" y1="0" x2="0" y2="1">
          <Stop offset="0" stopColor="#303451" />
          <Stop offset="1" stopColor="#9D8A98" />
        </LinearGradient>
      </Defs>
      <Rect width="960" height="640" fill="url(#sky)" />
      <Circle cx="700" cy="170" r="60" fill="#D9C9B4" />
      <Path
        d="M0 410 L260 200 L430 390 L600 290 L960 410 L960 640 L0 640 Z"
        fill="#424C61"
      />
      <Path
        d="M0 490 L310 360 L630 470 L960 360 L960 640 L0 640 Z"
        fill="#242E43"
      />
      <Path d="M0 490 Q400 470 960 510 L960 640 L0 640 Z" fill="#66798A" />
      <Path d="M0 560 Q300 510 620 640 L0 640 Z" fill="#1F2636" />
    </Svg>
  );
}
