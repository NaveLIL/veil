import type { PhaseprintIdentity } from "@/components/identity/Phaseprint";

export type IdentityContextKind =
  | "self"
  | "direct-message"
  | "message-author"
  | "friend"
  | "friend-request"
  | "user-search"
  | "group-member"
  | "server-member";

export interface IdentityContextRole {
  name: string;
  color?: string;
}

export interface IdentityIslandProfile extends PhaseprintIdentity {
  displayName: string;
  nickname?: string | null;
  signingKey?: string | null;
  profileVersion?: number | null;
  profileOrigin?: string | null;
  contextKind: IdentityContextKind;
  contextLabel: string;
  contextDetail?: string | null;
  joinedAt?: string | null;
  roles?: readonly IdentityContextRole[];
  rolesTruncated?: boolean;
  isOwner?: boolean;
  selfIdentity?: PhaseprintIdentity | null;
}

export type IdentityProofState = "self" | "not-compared" | "unavailable";

const USER_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IDENTITY_KEY_RE = /^[0-9a-f]{64}$/i;
const NIL_USER_ID = "00000000-0000-0000-0000-000000000000";

// Role state remains complete in the store/native authorization paths. This
// budget only bounds untrusted presentation work in profile chips and menus.
export const IDENTITY_ROLE_PRESENTATION_BUDGET = 64;

export function boundedIdentityRoles<T>(roles: readonly T[]): readonly T[] {
  return roles.length > IDENTITY_ROLE_PRESENTATION_BUDGET
    ? roles.slice(0, IDENTITY_ROLE_PRESENTATION_BUDGET)
    : roles;
}

export function boundedIdentityText(
  value: string | null | undefined,
  fallback: string,
  maxCodePoints = 256,
): string {
  const normalized = value?.trim().normalize("NFC");
  if (!normalized) return fallback;
  return Array.from(normalized).slice(0, maxCodePoints).join("");
}

export function canonicalIdentityOrigin(value: string | null | undefined): string | null {
  if (!value || value.length > 512) return null;
  try {
    const parsed = new URL(value);
    if (
      (parsed.protocol !== "https:" && parsed.protocol !== "http:")
      || parsed.username
      || parsed.password
      || parsed.pathname !== "/"
      || parsed.search
      || parsed.hash
    ) return null;
    const hostname = parsed.hostname.replace(/^\[/, "").replace(/\]$/, "").toLowerCase();
    const loopback = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
    if (parsed.protocol === "http:" && !loopback) return null;
    const port = parsed.port || (parsed.protocol === "https:" ? "443" : "80");
    const authority = hostname.includes(":") ? `[${hostname}]` : hostname;
    return `${parsed.protocol}//${authority}:${port}`;
  } catch {
    return null;
  }
}

export function canonicalIdentityUserId(value: string | null | undefined): string | null {
  const candidate = value?.trim().toLowerCase();
  if (!candidate || candidate === NIL_USER_ID || !USER_ID_RE.test(candidate)) return null;
  return candidate;
}

export function canonicalIdentityKey(value: string | null | undefined): string | null {
  const candidate = value?.trim().toLowerCase();
  if (!candidate || /^0{64}$/.test(candidate) || !IDENTITY_KEY_RE.test(candidate)) return null;
  return candidate;
}

export function identityAllowsKeylessDmResolution(profile: IdentityIslandProfile): boolean {
  return profile.identityKey == null
    && (profile.contextKind === "friend" || profile.contextKind === "friend-request");
}

export function isSameCanonicalIdentity(
  left: PhaseprintIdentity,
  right: PhaseprintIdentity,
): boolean {
  const leftOrigin = canonicalIdentityOrigin(left.canonicalServerOrigin);
  const leftUserId = canonicalIdentityUserId(left.userId);
  const leftIdentityKey = canonicalIdentityKey(left.identityKey);
  const rightOrigin = canonicalIdentityOrigin(right.canonicalServerOrigin);
  const rightUserId = canonicalIdentityUserId(right.userId);
  const rightIdentityKey = canonicalIdentityKey(right.identityKey);

  return !!leftOrigin
    && !!leftUserId
    && !!leftIdentityKey
    && leftOrigin === rightOrigin
    && leftUserId === rightUserId
    && leftIdentityKey === rightIdentityKey;
}

export function identityProofState(profile: IdentityIslandProfile): IdentityProofState {
  const hasCompleteLocator = !!canonicalIdentityOrigin(profile.canonicalServerOrigin)
    && !!canonicalIdentityUserId(profile.userId)
    && !!canonicalIdentityKey(profile.identityKey);
  if (!hasCompleteLocator) return "unavailable";
  return profile.selfIdentity && isSameCanonicalIdentity(profile, profile.selfIdentity)
    ? "self"
    : "not-compared";
}

export function canMessageIdentity(
  profile: IdentityIslandProfile,
  currentCanonicalOrigin: string | null | undefined,
  currentUserId: string | null | undefined,
): boolean {
  const profileOrigin = canonicalIdentityOrigin(profile.canonicalServerOrigin);
  const currentOrigin = canonicalIdentityOrigin(currentCanonicalOrigin);
  const targetUserId = canonicalIdentityUserId(profile.userId);
  const selfUserId = canonicalIdentityUserId(currentUserId);
  return !!profileOrigin
    && profileOrigin === currentOrigin
    && !!targetUserId
    && targetUserId !== selfUserId;
}

export function identityProfileKey(profile: IdentityIslandProfile): string {
  return [
    canonicalIdentityOrigin(profile.canonicalServerOrigin) ?? "origin-unavailable",
    canonicalIdentityUserId(profile.userId) ?? "user-unavailable",
    canonicalIdentityKey(profile.identityKey) ?? "key-unavailable",
    profile.contextKind,
  ].join("\0");
}
