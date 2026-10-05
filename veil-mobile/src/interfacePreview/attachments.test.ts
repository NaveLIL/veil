import { expect, test } from '@jest/globals';
import {
  chooseAttachment,
  sendAttachment,
  advanceTransfer,
  retryTransfer,
  cancelTransfer,
  designAttachments,
} from './attachments';
import { createDemoSession, setDraft } from './model';
const id = 'demo-anna';
const last = (s: ReturnType<typeof createDemoSession>) =>
  s.chats[0].messages[s.chats[0].messages.length - 1];
test('unknown result neither advances nor retries; offline waits for an explicit same-ID retry', () => {
  const send = (scenario: 'unknown' | 'offline') =>
    sendAttachment(
      chooseAttachment(
        { ...createDemoSession(), scenario },
        id,
        designAttachments[1],
      ),
      id,
      '16:00',
    );
  const unknown = send('unknown');
  expect(last(unknown).delivery).toBe('unknown');
  expect(last(unknown).transfer?.phase).toBe('unknown');
  expect(advanceTransfer(unknown, id, last(unknown).id, 1)).toBe(unknown);
  const online = { ...unknown, scenario: 'normal' as const };
  expect(last(retryTransfer(online, id, last(online).id))).toEqual(
    last(unknown),
  );
  const waiting = send('offline');
  expect(last(waiting).transfer?.phase).toBe('waiting');
  expect(last(waiting).delivery).toBe('queued');
  expect(advanceTransfer(waiting, id, last(waiting).id, 1)).toBe(waiting);
  expect(retryTransfer(waiting, id, last(waiting).id)).toBe(waiting);
  const retry = retryTransfer(
    { ...waiting, scenario: 'normal' },
    id,
    last(waiting).id,
  );
  expect(last(retry).id).toBe(last(waiting).id);
  expect(last(retry).transfer?.phase).toBe('sending');
  expect(retry.chats[0].messages).toHaveLength(
    waiting.chats[0].messages.length,
  );
});
test('choose/cancel retains per-chat text and quotes; attachment sends without a caption', () => {
  let s = setDraft(createDemoSession(), id, 'подпись');
  s = { ...s, replies: { [id]: 'fixture-a2' } };
  s = chooseAttachment(s, id, designAttachments[0]);
  expect(s.attachments?.['demo-max']).toBeUndefined();
  s = chooseAttachment(s, id);
  expect(s.drafts[id]).toBe('подпись');
  expect(s.replies?.[id]).toBe('fixture-a2');
  s = sendAttachment(
    chooseAttachment(setDraft(s, id, ''), id, designAttachments[0]),
    id,
    '16:00',
  );
  expect(last(s).attachment).toEqual(designAttachments[0]);
  expect(last(s).replyTo).toBe('fixture-a2');
  expect(s.attachments?.[id]).toBeUndefined();
});
test('failure and retry retain one stable message with caption and ignore stale attempts', () => {
  let s = setDraft(createDemoSession(), id, 'подпись');
  s.scenario = 'failure';
  s = sendAttachment(
    chooseAttachment(s, id, designAttachments[1]),
    id,
    '16:00',
  );
  const messageId = last(s).id,
    count = s.chats[0].messages.length;
  s = advanceTransfer(advanceTransfer(s, id, messageId, 1), id, messageId, 1);
  expect(last(s).transfer?.phase).toBe('failed');
  s = retryTransfer({ ...s, scenario: 'normal' }, id, messageId);
  expect(advanceTransfer(s, id, messageId, 1)).toBe(s);
  for (let i = 0; i < 4; i++) s = advanceTransfer(s, id, messageId, 2);
  expect(last(s).transfer?.phase).toBe('complete');
  expect(last(s).text).toBe('подпись');
  expect(s.chats[0].messages).toHaveLength(count);
});
test('cancel and deletion defeat callbacks, identity change blocks retry/send', () => {
  let s = sendAttachment(
    chooseAttachment(createDemoSession(), id, designAttachments[0]),
    id,
    '16:00',
  );
  const messageId = last(s).id;
  s = cancelTransfer(s, id, messageId);
  expect(advanceTransfer(s, id, messageId, 1)).toBe(s);
  expect(last(s).transfer?.phase).toBe('cancelled');
  const blocked = { ...s, scenario: 'identityChanged' as const };
  expect(retryTransfer(blocked, id, messageId)).toBe(blocked);
  expect(
    sendAttachment(
      chooseAttachment(blocked, id, designAttachments[0]),
      id,
      '16:01',
    ).nextId,
  ).toBe(blocked.nextId);
});
