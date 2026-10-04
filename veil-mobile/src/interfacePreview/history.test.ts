import { expect, test } from '@jest/globals';
import { dayLabel, incomingAfter, isAtLatest } from './history';
import {
  createDemoSession,
  receiveDemo,
  retryDemo,
  sendDemo,
  setDraft,
} from './model';

test('reading position distinguishes the tail, old history, short content and overscroll', () => {
  expect(isAtLatest(800, 1300, 500)).toBe(true);
  expect(isAtLatest(752, 1300, 500)).toBe(true);
  expect(isAtLatest(700, 1300, 500)).toBe(false);
  expect(isAtLatest(800, 1300, 300)).toBe(false);
  expect(isAtLatest(-10, 200, 500)).toBe(true);
});
test('new-message count ignores old fixtures, own sends, duplicate delivery updates and unrelated IDs', () => {
  const session = createDemoSession();
  const messages = session.chats[0].messages;
  const lastId = messages[messages.length - 1].id;
  const received = receiveDemo(session, 'demo-anna', 3, '15:00');
  expect(incomingAfter(received.chats[0].messages, lastId)).toHaveLength(3);
  expect(incomingAfter(messages, lastId)).toHaveLength(0);
  expect(incomingAfter(messages, undefined)).toHaveLength(0);
  expect(incomingAfter(messages, 'unrelated')).toHaveLength(0);
  const sent = sendDemo(
    { ...setDraft(session, 'demo-anna', 'test'), scenario: 'failure' },
    'demo-anna',
    '15:00',
  );
  expect(incomingAfter(sent.chats[0].messages, lastId)).toHaveLength(0);
  const sentId = sent.chats[0].messages[sent.chats[0].messages.length - 1].id;
  expect(
    incomingAfter(
      retryDemo({ ...sent, scenario: 'normal' }, 'demo-anna', sentId).chats[0]
        .messages,
      sentId,
    ),
  ).toHaveLength(0);
});
test('date labels follow fixture dates rather than treating all history as today', () => {
  expect(dayLabel(undefined)).toBe('Сегодня');
  expect(dayLabel('2026-10-03')).toBe('Вчера');
  expect(dayLabel('2026-09-27')).toBe('27 сентября');
});
