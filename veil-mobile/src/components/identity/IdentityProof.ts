import {
  canonicalPhaseprintIdentityKey,
  canonicalPhaseprintUserId,
  type PhaseprintIdentity,
} from "./Phaseprint";

export type IdentityAuthority = "authenticated-directory" | "unavailable";

export interface IdentityProofCandidate extends PhaseprintIdentity {
  identityAuthority: IdentityAuthority;
}

export interface ExactIdentityLocator {
  canonicalServerOrigin: string;
  userId: string;
  identityKey: string;
}

interface ParsedIdentityOrigin {
  protocol: string;
  username: string;
  password: string;
  pathname: string;
  search: string;
  hash: string;
  port: string;
  hostname: string;
}

// Security/trust UI deliberately uses a stricter origin contract than the
// presentation-only Phaseprint. Plain HTTP is accepted only for local
// development loopback, matching the desktop/native REST boundary.
export function canonicalIdentityOrigin(value: string | null | undefined): string | null {
  if (!value || value.length > 512) return null;
  try {
    const parsed = new URL(value) as unknown as ParsedIdentityOrigin;
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

// Syntax is insufficient for a trust statement. A caller must explicitly
// carry provenance from an authenticated directory; prototype/mock rows stay
// unavailable until Phase 5 wires that native observation.
export function authoritativeIdentityLocator(
  candidate: IdentityProofCandidate,
): ExactIdentityLocator | null {
  if (candidate.identityAuthority !== "authenticated-directory") return null;
  const canonicalServerOrigin = canonicalIdentityOrigin(candidate.canonicalServerOrigin);
  const userId = canonicalPhaseprintUserId(candidate.userId);
  const identityKey = canonicalPhaseprintIdentityKey(candidate.identityKey);
  return canonicalServerOrigin && userId && identityKey
    ? { canonicalServerOrigin, userId, identityKey }
    : null;
}
