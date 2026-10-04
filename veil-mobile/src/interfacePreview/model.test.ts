import { expect, test } from '@jest/globals';
import { createDemoSession, DemoSession, openChat, retryDemo, sendDemo, setDraft, visibleChats } from './model';

test('drafts survive navigation, are isolated by chat, and clear only on local acceptance', () => {
  let s = setDraft(createDemoSession(), 'demo-anna', '  Привет  ');
  s = setDraft(s, 'demo-max', 'Завтра');
  s = openChat(s, 'demo-max');
  expect(s.drafts['demo-anna']).toBe('  Привет  ');
  s = sendDemo(s, 'demo-anna', '15:00');
  expect(s.drafts['demo-anna']).toBe('');
  expect(s.drafts['demo-max']).toBe('Завтра');
  expect(s.chats[0].messages[s.chats[0].messages.length - 1]?.text).toBe('  Привет  ');
  expect(createDemoSession().chats[0].messages).toHaveLength(4);
});
test('identity change blocks sending without losing a draft or adding a message', () => {
  const s = { ...setDraft(createDemoSession(), 'demo-anna', 'Не терять'), scenario: 'identityChanged' as const };
  expect(sendDemo(s, 'demo-anna', '15:00')).toBe(s);
  expect(retryDemo(s, 'demo-anna', 'unknown')).toBe(s);
});
test('offline and failure states do not invent delivery or read receipts; retry does not duplicate', () => {
  let s: DemoSession = { ...setDraft(createDemoSession(), 'demo-new', 'Тест'), scenario: 'failure' };
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
  expect(visibleChats(openChat(s, 'demo-anna'), '', true).map(c => c.id)).toEqual(['demo-sofia']);
  expect(setDraft(s, 'real-account-id', 'x')).toBe(s);
  expect(sendDemo(setDraft(s, 'demo-new', '   '), 'demo-new', '15:00').nextId).toBe(1);
});
test('unknown confirmation cannot be retried; mixed Unicode and newlines remain unchanged', () => {
  const text = 'Привет 👋\nمرحبا\n' + 'длинный текст '.repeat(40);
  let s = sendDemo({ ...setDraft(createDemoSession(), 'demo-new', text), scenario: 'unknown' }, 'demo-new', '15:00');
  expect(s.chats[5].messages[0].delivery).toBe('unknown');
  s = retryDemo({ ...s, scenario: 'normal' }, 'demo-new', s.chats[5].messages[0].id);
  expect(s.chats[5].messages).toHaveLength(1);
  expect(s.chats[5].messages[0].delivery).toBe('unknown');
  expect(s.chats[5].messages[0].text).toBe(text);
});
