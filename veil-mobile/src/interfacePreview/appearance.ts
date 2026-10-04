/** One rounded-rectangle standard across islands, panels and controls. */
export const geometry = { radius: 20, borderWidth: 1 } as const;

/** Presentation-only presets matching the desktop names; no account storage. */
export const palettes = {
  Veil: { bg: '#2B2D31', surface: '#36373D', raised: '#383A40', line: '#45464C', text: '#EEEEEF', muted: '#C0C0C8', accent: '#7C6BF5', tint: '#39324B' },
  Midnight: { bg: '#191E2C', surface: '#252B3D', raised: '#2A3145', line: '#394158', text: '#EEEEEF', muted: '#C0C0C8', accent: '#8B7CFF', tint: '#302B49' },
  Ocean: { bg: '#142536', surface: '#20384C', raised: '#223D53', line: '#355268', text: '#EEEEEF', muted: '#C0C0C8', accent: '#4AA8FF', tint: '#204461' },
  Forest: { bg: '#172720', surface: '#243A31', raised: '#294238', line: '#3A574B', text: '#EEEEEF', muted: '#C0C0C8', accent: '#4FD1A1', tint: '#264B3D' },
  OLED: { bg: '#101010', surface: '#1C1C1C', raised: '#202020', line: '#303030', text: '#EEEEEF', muted: '#C0C0C8', accent: '#A78BFA', tint: '#2B223A' },
};
export type ThemeName = keyof typeof palettes;
export type Palette = typeof palettes.Veil;
