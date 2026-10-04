import { expect, test } from '@jest/globals';
import {
  canGroup,
  createDemoSession,
  DemoSession,
  openChat,
  receiveDemo,
  retryDemo,
  sendDemo,
  setDraft,
  visibleChats,
} from './model';

test('drafts survive navigation, are isolated by chat, and clear only on local acceptance', () => {
  let s = setDraft(createDemoSession(), 'demo-anna', '  Привет  ');
  s = setDraft(s, 'demo-max', 'Завтра');
  s = openChat(s, 'demo-max');
  expect(s.drafts['demo-anna']).toBe('  Привет  ');
  s = sendDemo(s, 'demo-anna', '15:00');
  expect(s.drafts['demo-anna']).toBe('');
  expect(s.drafts['demo-max']).toBe('Завтра');
  expect(s.chats[0].messages[s.chats[0].messages.length - 1]?.text).toBe(
    '  Привет  ',
  );
  expect(createDemoSession().chats[0].messages).toHaveLength(320);
});

test('long histories have stable unique IDs and grouping stops at a date boundary', () => {
  const session = createDemoSession();
  const anna = session.chats[0].messages;
  expect(session.chats[1].messages).toHaveLength(160);
  expect(new Set(anna.map((message) => message.id)).size).toBe(320);
  expect(new Set(anna.map((message) => message.day)).size).toBeGreaterThan(6);
  const first = {
    id: 'a',
    own: false,
    text: 'a',
    time: '09:00',
    day: '2026-10-03',
  };
  expect(
    canGroup(first, { ...first, id: 'b', time: '09:01', day: '2026-10-04' }),
  ).toBe(false);
  expect(canGroup(first, { ...first, id: 'b', time: '09:01' })).toBe(true);
});
test('incoming fixture bursts append stable messages without changing the draft or another chat', () => {
  const before = setDraft(
    createDemoSession(),
    'demo-anna',
    'Многострочный\nчерновик',
  );
  const after = receiveDemo(before, 'demo-anna', 3, '15:00');
  expect(after.chats[0].messages.slice(0, 320)).toEqual(
    before.chats[0].messages,
  );
  expect(
    after.chats[0].messages
      .slice(-3)
      .every((message) => !message.own && !message.delivery),
  ).toBe(true);
  expect(after.chats[0].unread).toBe(before.chats[0].unread + 3);
  expect(after.drafts).toBe(before.drafts);
  expect(after.chats[1]).toBe(before.chats[1]);
  expect(receiveDemo(before, 'real-account-id', 3, '15:00')).toBe(before);
  expect(receiveDemo(before, 'demo-anna', 500, '15:00')).toBe(before);
});
test('identity change blocks sending without losing a draft or adding a message', () => {
  const s = {
    ...setDraft(createDemoSession(), 'demo-anna', 'Не терять'),
    scenario: 'identityChanged' as const,
  };
  expect(sendDemo(s, 'demo-anna', '15:00')).toBe(s);
  expect(retryDemo(s, 'demo-anna', 'unknown')).toBe(s);
});
test('offline and failure states do not invent delivery or read receipts; retry does not duplicate', () => {
  let s: DemoSession = {
    ...setDraft(createDemoSession(), 'demo-new', 'Тест'),
    scenario: 'failure',
  };
  s = sendDemo(s, 'demo-new', '15:00');
  const id = s.chats[5].messages[0].id;
  expect(s.chats[5].messages[0].delivery).toBe('failed');
  s = { ...s, scenario: 'offline' };
  s = retryDemo(s, 'demo-new', id);
  expect(s.chats[5].messages).toHaveLength(1);
  expect(s.chats[5].messages[0].delivery).toBe('queued');
});
test('search/unread/open and unknown IDs respect the fixture boundary', () => {
  const s = createDemoSession();
  expect(visibleChats(s, '  АННА ', false)).toHaveLength(1);
  expect(visibleChats(s, 'nikita.demo', false)[0].messages).toHaveLength(0);
  expect(
    visibleChats(openChat(s, 'demo-anna'), '', true).map((c) => c.id),
  ).toEqual(['demo-sofia', 'demo-group']);
  expect(setDraft(s, 'real-account-id', 'x')).toBe(s);
  expect(
    sendDemo(setDraft(s, 'demo-new', '   '), 'demo-new', '15:00').nextId,
  ).toBe(1);
});
test('unknown confirmation cannot be retried; mixed Unicode and newlines remain unchanged', () => {
  const text = 'Привет 👋\nمرحبا\n' + 'длинный текст '.repeat(40);
  let s = sendDemo(
    { ...setDraft(createDemoSession(), 'demo-new', text), scenario: 'unknown' },
    'demo-new',
    '15:00',
  );
  expect(s.chats[5].messages[0].delivery).toBe('unknown');
  s = retryDemo(
    { ...s, scenario: 'normal' },
    'demo-new',
    s.chats[5].messages[0].id,
  );
  expect(s.chats[5].messages).toHaveLength(1);
  expect(s.chats[5].messages[0].delivery).toBe('unknown');
  expect(s.chats[5].messages[0].text).toBe(text);
});
