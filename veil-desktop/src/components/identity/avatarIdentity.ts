import type { PhaseprintIdentity } from "@/components/identity/Phaseprint";

export interface FriendRequestAvatarSource {
  fromUserId: string;
  fromUsername: string;
  outgoing: boolean;
}

/**
 * The current gateway labels an outgoing request with the local account in
 * `fromUserId`; using it would draw our own Phaseprint beside the recipient.
 * Until the DTO carries `counterpartUserId`, outgoing rows deliberately use
 * the origin-scoped technical username fallback instead.
 */
export function phaseprintIdentityForFriendRequest(
  request: FriendRequestAvatarSource,
  canonicalServerOrigin: string,
): PhaseprintIdentity {
  return {
    canonicalServerOrigin,
    userId: request.outgoing ? undefined : request.fromUserId,
    technicalUsername: request.fromUsername,
  };
}
