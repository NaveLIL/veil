import type { VeilMobileRuntimeSnapshot } from '../native/runtime';
import type { PublicFailureCodeV1 } from '../contracts/publicFailureCodesV1';
import { canRenderChat, type RuntimeGatePhase } from '../stores/runtime';

export type AccountStartupState = 'loading' | 'locked' | 'unavailable' | 'recoverable-error' | 'configuration-error' | 'ready';
/** Presentation classification of existing facts, never an authorization decision. */
export function accountStartupState(phase: RuntimeGatePhase, snapshot: VeilMobileRuntimeSnapshot | null,
  requiresExplicitReopen: boolean, failure: PublicFailureCodeV1 | null): AccountStartupState {
  if (failure === 'VEIL-NODE-004') return 'configuration-error';
  if (phase === 'privacy' || requiresExplicitReopen || snapshot?.sessionState === 'locked') return 'locked';
  if (phase === 'error' || failure) return 'recoverable-error';
  if (phase === 'bootstrapping' || !snapshot || ['opening','closing'].includes(snapshot.sessionState)
    || snapshot.connectionState === 'connecting' || (snapshot.connectionState === 'connected' && !snapshot.directoryReady)) return 'loading';
  return canRenderChat(snapshot, requiresExplicitReopen, failure) ? 'ready' : 'unavailable';
}
