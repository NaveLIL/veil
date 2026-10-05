import { beforeEach, expect, jest, test } from '@jest/globals';
import {
  directDraftScope,
  resetChatStoreForTests,
  useChatStore,
} from '../../stores/chat';
jest.mock('../../native/runtime', () => ({
  __esModule: true,
  isExactAuthenticatedBinding: () => true,
  default: {},
}));
const a = '22222222-2222-4222-8222-222222222222';
const b = '33333333-3333-4333-8333-333333333333';
beforeEach(() => {
  resetChatStoreForTests();
  useChatStore.setState({
    runtimeBinding: {
      canonicalServerOrigin: 'https://veil.example:443',
      userId: '11111111-1111-4111-8111-111111111111',
    },
    directGeneration: 1,
    selectedDmId: a,
    dms: [a, b].map((id) => ({
      id,
      name: id,
      isGroup: false,
      color: '#FFFFFF',
      peerUserId: id,
      peerUsername: id,
      avatarIdentity: {
        canonicalServerOrigin: 'https://veil.example:443',
        userId: id,
        username: id,
      },
    })),
  });
});
test('A -> B -> A retains separate drafts; late input cannot write into B', () => {
  const scopeA = directDraftScope(useChatStore.getState())!;
  useChatStore.getState().setDirectDraft(scopeA, 'draft A');
  useChatStore.getState().selectDm(b);
  const scopeB = directDraftScope(useChatStore.getState())!;
  useChatStore.getState().setDirectDraft(scopeB, 'draft B');
  useChatStore.getState().setDirectDraft(scopeA, 'stale A callback');
  useChatStore.getState().selectDm(a);
  expect(useChatStore.getState().directDrafts).toEqual({
    [scopeA]: 'draft A',
    [scopeB]: 'draft B',
  });
});
test('a send result clears only its unchanged draft under the same authority', () => {
  const scope = directDraftScope(useChatStore.getState())!;
  useChatStore.getState().setDirectDraft(scope, 'sent');
  useChatStore.getState().setDirectDraft(scope, 'newer text');
  useChatStore.getState().consumeDirectDraft(scope, 'sent');
  expect(useChatStore.getState().directDrafts[scope]).toBe('newer text');
  useChatStore.getState().consumeDirectDraft(scope, 'newer text');
  expect(useChatStore.getState().directDrafts[scope]).toBeUndefined();
});
test('privacy clear removes drafts and rejects stale callbacks', () => {
  const scope = directDraftScope(useChatStore.getState())!;
  useChatStore.getState().setDirectDraft(scope, 'private draft');
  useChatStore.getState().clearRenderableChat();
  useChatStore.getState().setDirectDraft(scope, 'late text');
  expect(useChatStore.getState().directDrafts).toEqual({});
});
test('stable message anchors survive A -> B -> A and reject another chat callback', () => {
  const scopeA = directDraftScope(useChatStore.getState())!;
  useChatStore.getState().setDirectViewport(scopeA, a, false);
  useChatStore.getState().selectDm(b);
  const scopeB = directDraftScope(useChatStore.getState())!;
  useChatStore.getState().setDirectViewport(scopeB, b, true);
  useChatStore.getState().setDirectViewport(scopeA, b, true);
  useChatStore.getState().selectDm(a);
  expect(useChatStore.getState().directViewports).toEqual({
    [scopeA]: { anchorId: a, following: false },
    [scopeB]: { anchorId: b, following: true },
  });
  useChatStore.getState().clearRenderableChat();
  useChatStore.getState().setDirectViewport(scopeA, a, false);
  expect(useChatStore.getState().directViewports).toEqual({});
});
