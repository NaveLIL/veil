import type { Component } from "solid-js";

interface Props {
  canonicalOrigin: string;
  spaceId: string;
  size?: number;
}

function seedBytes(value: string): Uint8Array {
  // Stable non-cryptographic expansion is intentional: Space marks are only
  // decorative and are never presented as identity proof or a trust signal.
  let a = 0x811c9dc5;
  let b = 0x9e3779b9;
  for (const character of new TextEncoder().encode(value)) {
    a = Math.imul(a ^ character, 0x01000193) >>> 0;
    b = Math.imul(b ^ (character + 0x9d), 0x85ebca6b) >>> 0;
  }
  const out = new Uint8Array(20);
  for (let index = 0; index < out.length; index += 1) {
    a ^= a << 13; a ^= a >>> 17; a ^= a << 5;
    b = Math.imul(b ^ (b >>> 16), 0x7feb352d) >>> 0;
    out[index] = (a ^ b) & 0xff;
  }
  return out;
}

export const SpaceMark: Component<Props> = (props) => {
  const bytes = () => seedBytes(`veil-space-mark-v1\0${props.canonicalOrigin}\0${props.spaceId}`);
  const hue = () => 188 + (bytes()[0] % 74);
  const cells = () => Array.from({ length: 15 }, (_, index) => ({
    row: Math.floor(index / 3),
    column: index % 3,
    enabled: (bytes()[index + 1] & 3) !== 0,
    tone: bytes()[index + 1] & 1,
  }));
  const size = () => props.size ?? 34;
  return (
    <svg width={size()} height={size()} viewBox="0 0 36 36" aria-hidden="true">
      <rect width="36" height="36" rx="12" fill={`hsl(${hue()} 48% 16%)`} />
      {cells().flatMap((cell) => {
        if (!cell.enabled) return [];
        const x = 6 + cell.column * 5;
        const mirrorX = 26 - cell.column * 5;
        const y = 6 + cell.row * 5;
        const color = `hsl(${hue() + (cell.tone ? 34 : 0)} 76% ${cell.tone ? 72 : 62}%)`;
        return [
          <rect x={x} y={y} width="4" height="4" rx="1.2" fill={color} />,
          ...(mirrorX === x ? [] : [<rect x={mirrorX} y={y} width="4" height="4" rx="1.2" fill={color} />]),
        ];
      })}
    </svg>
  );
};
