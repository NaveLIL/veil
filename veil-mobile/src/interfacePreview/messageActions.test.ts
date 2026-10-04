import { expect, test } from '@jest/globals';
import { createDemoSession, sendDemo, setDraft } from './model';
import {
  availableActions,
  cancelComposition,
  changeComposition,
  deleteMessage,
  findMessage,
  startEdit,
  startReply,
  submitComposition,
} from './messageActions';

test('reply is chat scoped, preserves text on cancellation and is attached once to the sent message', () => {
  let s = setDraft(createDemoSession(), 'demo-anna', 'мой ответ');
  s = startReply(s, 'demo-anna', 'fixture-a1');
  s = setDraft(s, 'demo-max', 'другой черновик');
  expect(s.replies?.['demo-max']).toBeUndefined();
  const cancelled = cancelComposition(s, 'demo-anna');
  expect(cancelled.drafts['demo-anna']).toBe('мой ответ');
  expect(cancelled.replies?.['demo-anna']).toBeUndefined();
  s = sendDemo(s, 'demo-anna', '15:00');
  expect(s.chats[0].messages[s.chats[0].messages.length - 1]?.replyTo).toBe(
    'fixture-a1',
  );
  expect(s.replies?.['demo-anna']).toBeUndefined();
  expect(s.drafts['demo-max']).toBe('другой черновик');
});
test('edit preserves stable identity and delivery and restores the ordinary draft and reply on save or cancel', () => {
  let s = startReply(
    setDraft(createDemoSession(), 'demo-anna', 'не потерять'),
    'demo-anna',
    'fixture-a1',
  );
  const before = findMessage(s, 'demo-anna', 'fixture-a2')!;
  const count = s.chats[0].messages.length;
  s = changeComposition(
    startEdit(s, 'demo-anna', before.id),
    'demo-anna',
    'изменённый текст',
  );
  expect(cancelComposition(s, 'demo-anna').drafts['demo-anna']).toBe(
    'не потерять',
  );
  s = submitComposition(s, 'demo-anna', '20:00');
  expect(findMessage(s, 'demo-anna', before.id)).toEqual({
    ...before,
    text: 'изменённый текст',
    edited: true,
  });
  expect(s.chats[0].messages).toHaveLength(count);
  expect(s.drafts['demo-anna']).toBe('не потерять');
  expect(s.replies?.['demo-anna']).toBe('fixture-a1');
  expect(s.edits?.['demo-anna']).toBeUndefined();
});
test('ownership, unknown delivery, missing IDs and identity block prevent invalid mutations', () => {
  const s = createDemoSession();
  expect(startEdit(s, 'demo-anna', 'fixture-a1')).toBe(s);
  expect(deleteMessage(s, 'demo-anna', 'fixture-a1')).toBe(s);
  expect(startReply(s, 'demo-max', 'fixture-a1')).toBe(s);
  expect(
    availableActions({
      id: 'x',
      text: 'a',
      own: true,
      delivery: 'unknown',
      time: '12:00',
    }),
  ).toEqual(['reply', 'copy']);
  const editing = changeComposition(
    startEdit(s, 'demo-anna', 'fixture-a2'),
    'demo-anna',
    '   ',
  );
  expect(submitComposition(editing, 'demo-anna', '15:00')).toBe(editing);
  const blocked = { ...editing, scenario: 'identityChanged' as const };
  expect(submitComposition(blocked, 'demo-anna', '15:00')).toBe(blocked);
});
test('deletion removes plaintext but retains quote IDs, anchors and unrelated drafts', () => {
  let s = startReply(
    setDraft(createDemoSession(), 'demo-anna', 'ответ'),
    'demo-anna',
    'fixture-a2',
  );
  s = sendDemo(s, 'demo-anna', '15:00');
  s = startEdit(s, 'demo-anna', 'fixture-a2');
  s = deleteMessage(s, 'demo-anna', 'fixture-a2');
  const original = findMessage(s, 'demo-anna', 'fixture-a2')!;
  expect(original.deleted).toBe(true);
  expect(original.text).toBe('');
  expect(availableActions(original)).toEqual([]);
  expect(s.edits?.['demo-anna']).toBeUndefined();
  expect(s.chats[0].messages[s.chats[0].messages.length - 1]?.replyTo).toBe(
    original.id,
  );
  expect(deleteMessage(s, 'demo-anna', original.id)).toBe(s);
});
test('failed reply retry keeps the same ID and reference', () => {
  const s = {
    ...startReply(
      setDraft(createDemoSession(), 'demo-anna', 'ответ'),
      'demo-anna',
      'fixture-a1',
    ),
    scenario: 'failure' as const,
  };
  const sent = submitComposition(s, 'demo-anna', '15:00');
  expect(
    sent.chats[0].messages[sent.chats[0].messages.length - 1],
  ).toMatchObject({
    id: 'demo-local-1',
    replyTo: 'fixture-a1',
    delivery: 'failed',
  });
});
