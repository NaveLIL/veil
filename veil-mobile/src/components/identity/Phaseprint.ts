export interface PhaseprintIdentity {
  identityKey?: string | null;
  canonicalServerOrigin?: string | null;
  userId?: string | null;
  technicalUsername?: string | null;
}

export type PhaseprintSeedKind = "identity-key" | "user-id" | "username" | "anonymous";

export interface ResolvedPhaseprintSeed {
  kind: PhaseprintSeedKind;
  canonical: string;
}

export interface PhaseprintCell {
  x: number;
  y: number;
  fill: string;
  opacity: number;
}

export interface PhaseprintModel {
  seedKind: PhaseprintSeedKind;
  renderVector: string;
  background: string;
  wash: string;
  ink: string;
  glow: string;
  angle: number;
  orbitRadius: number;
  orbitRotation: number;
  orbitDash: number;
  orbitGap: number;
  orbX: number;
  orbY: number;
  orbRadius: number;
  cells: PhaseprintCell[];
}

interface PhaseprintPalette {
  base: string;
  wash: string;
  ink: string;
  glow: string;
}

interface ParsedOriginUrl {
  protocol: string;
  username: string;
  password: string;
  pathname: string;
  search: string;
  hash: string;
  port: string;
  hostname: string;
}

const PHASEPRINT_DOMAIN = "veil-phaseprint-v1";
const IDENTITY_KEY_RE = /^[0-9a-f]{64}$/i;
const USER_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NIL_USER_ID = "00000000-0000-0000-0000-000000000000";

const PALETTES: readonly PhaseprintPalette[] = [
  { base: "#10243f", wash: "#1d5b79", ink: "#86f4d6", glow: "#56a8ff" },
  { base: "#17233f", wash: "#443b78", ink: "#b8a7ff", glow: "#6fe4ff" },
  { base: "#102f38", wash: "#1e6a5c", ink: "#8cf0b6", glow: "#58c6e8" },
  { base: "#2d2037", wash: "#75405f", ink: "#ffc1dd", glow: "#a99bff" },
  { base: "#30291d", wash: "#79613a", ink: "#ffe0a3", glow: "#78ddc6" },
  { base: "#172d47", wash: "#245f88", ink: "#a8dcff", glow: "#76f0d0" },
  { base: "#25213d", wash: "#5b477c", ink: "#d7bdff", glow: "#7ed7ff" },
  { base: "#163137", wash: "#356b6e", ink: "#a4efe1", glow: "#8db7ff" },
];

function normalizedText(value: string | null | undefined, maxUtf8Bytes: number): string | null {
  if (!value || value.length > maxUtf8Bytes) return null;
  const normalized = value.trim().normalize("NFC");
  if (!normalized || normalized.length > maxUtf8Bytes || utf8Bytes(normalized).length > maxUtf8Bytes) return null;
  return normalized;
}

export function canonicalPhaseprintOrigin(value: string | null | undefined): string | null {
  const candidate = normalizedText(value, 512);
  if (!candidate) return null;
  try {
    const parsed = new URL(candidate) as unknown as ParsedOriginUrl;
    if (
      (parsed.protocol !== "https:" && parsed.protocol !== "http:")
      || parsed.username
      || parsed.password
      || parsed.pathname !== "/"
      || parsed.search
      || parsed.hash
    ) return null;
    const port = parsed.port || (parsed.protocol === "https:" ? "443" : "80");
    return `${parsed.protocol}//${parsed.hostname.toLowerCase()}:${port}`;
  } catch {
    return null;
  }
}

export function canonicalPhaseprintUserId(value: string | null | undefined): string | null {
  const userId = normalizedText(value, 36)?.toLowerCase() ?? null;
  return userId && USER_ID_RE.test(userId) && userId !== NIL_USER_ID ? userId : null;
}

export function canonicalPhaseprintIdentityKey(value: string | null | undefined): string | null {
  const identityKey = normalizedText(value, 64);
  return identityKey && IDENTITY_KEY_RE.test(identityKey) && !/^0{64}$/i.test(identityKey)
    ? identityKey.toLowerCase()
    : null;
}

export function resolvePhaseprintSeed(identity: PhaseprintIdentity): ResolvedPhaseprintSeed {
  const identityKey = canonicalPhaseprintIdentityKey(identity.identityKey);
  if (identityKey) {
    return { kind: "identity-key", canonical: `${PHASEPRINT_DOMAIN}\0identity-key\0${identityKey}` };
  }
  const origin = canonicalPhaseprintOrigin(identity.canonicalServerOrigin);
  if (!origin) {
    return { kind: "anonymous", canonical: `${PHASEPRINT_DOMAIN}\0anonymous\0origin-unavailable` };
  }
  const userId = canonicalPhaseprintUserId(identity.userId);
  if (userId) {
    return { kind: "user-id", canonical: `${PHASEPRINT_DOMAIN}\0origin-user-id\0${origin}\0${userId}` };
  }
  const technicalUsername = normalizedText(identity.technicalUsername, 256);
  if (technicalUsername) {
    return { kind: "username", canonical: `${PHASEPRINT_DOMAIN}\0origin-username\0${origin}\0${technicalUsername}` };
  }
  return { kind: "anonymous", canonical: `${PHASEPRINT_DOMAIN}\0anonymous\0${origin}` };
}

function utf8Bytes(value: string): Uint8Array {
  const output: number[] = [];
  for (const character of value) {
    const codePoint = character.codePointAt(0)!;
    // Match TextEncoder exactly: an unpaired UTF-16 surrogate is replaced by
    // U+FFFD rather than encoded as an invalid UTF-8 scalar.
    if (codePoint >= 0xd800 && codePoint <= 0xdfff) output.push(0xef, 0xbf, 0xbd);
    else if (codePoint <= 0x7f) output.push(codePoint);
    else if (codePoint <= 0x7ff) output.push(0xc0 | (codePoint >> 6), 0x80 | (codePoint & 0x3f));
    else if (codePoint <= 0xffff) output.push(0xe0 | (codePoint >> 12), 0x80 | ((codePoint >> 6) & 0x3f), 0x80 | (codePoint & 0x3f));
    else output.push(0xf0 | (codePoint >> 18), 0x80 | ((codePoint >> 12) & 0x3f), 0x80 | ((codePoint >> 6) & 0x3f), 0x80 | (codePoint & 0x3f));
  }
  return Uint8Array.from(output);
}

function mix32(value: number): number {
  let mixed = value >>> 0;
  mixed ^= mixed >>> 16;
  mixed = Math.imul(mixed, 0x7feb352d) >>> 0;
  mixed ^= mixed >>> 15;
  mixed = Math.imul(mixed, 0x846ca68b) >>> 0;
  mixed ^= mixed >>> 16;
  return mixed >>> 0;
}

function hash32(value: Uint8Array, salt: number): number {
  let hash = (0x811c9dc5 ^ salt) >>> 0;
  for (const byte of value) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return mix32(hash ^ salt);
}

function createWordStream(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x9e3779b9) >>> 0;
    return mix32(state);
  };
}

export function createPhaseprintModel(identity: PhaseprintIdentity): PhaseprintModel {
  const seed = resolvePhaseprintSeed(identity);
  const seedBytes = utf8Bytes(seed.canonical);
  const words = [
    hash32(seedBytes, 0x243f6a88),
    hash32(seedBytes, 0x85a308d3),
    hash32(seedBytes, 0x13198a2e),
    hash32(seedBytes, 0x03707344),
  ];
  const palette = PALETTES[words[0] % PALETTES.length];
  const nextWord = createWordStream(words[2] ^ words[3]);
  const cells: PhaseprintCell[] = [];
  for (let row = 0; row < 5; row += 1) {
    for (let leftColumn = 0; leftColumn < 3; leftColumn += 1) {
      const word = nextWord();
      const enabled = (row === 2 && leftColumn === 2) || (word & 0b11) !== 0;
      if (!enabled) continue;
      const columns = leftColumn === 2 ? [2] : [leftColumn, 4 - leftColumn];
      const fill = (word & 0b100) === 0 ? palette.ink : palette.glow;
      const opacity = 0.5 + ((word >>> 8) % 4) * 0.12;
      for (const column of columns) cells.push({ x: 7 + column * 10, y: 7 + row * 10, fill, opacity });
    }
  }
  return {
    seedKind: seed.kind,
    renderVector: words.map((word) => word.toString(16).padStart(8, "0")).join(""),
    background: palette.base,
    wash: palette.wash,
    ink: palette.ink,
    glow: palette.glow,
    angle: 115 + (words[0] % 131),
    orbitRadius: 18 + (words[1] % 8),
    orbitRotation: words[2] % 180,
    orbitDash: 3 + (words[2] % 6),
    orbitGap: 4 + (words[3] % 7),
    orbX: 15 + (words[1] % 35),
    orbY: 15 + (words[2] % 35),
    orbRadius: 5 + (words[3] % 7),
    cells,
  };
}
