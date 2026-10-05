import { expect, test } from '@jest/globals';
import {
  directDesignProjection,
  directTimelineRow,
} from '../directDesignAdapter';
import type { DirectMessageView } from '../../native/runtime';
const message: DirectMessageView = {
  stableUiId: 'client-one',
  messageId: 'server-one',
  serverMessageId: 'server-one',
  clientMessageId: 'client-one',
  text: 'native fact',
  timestampMs: null,
  direction: 'outgoing',
  delivery: 'unknown',
};
test('native adapter preserves stable identity and unknown; no invented receipts/timestamps/attachments', () => {
  expect(directTimelineRow(message)).toEqual({
    id: 'client-one',
    text: 'native fact',
    own: true,
    time: '—',
    day: undefined,
    delivery: 'unknown',
  });
  expect(directTimelineRow({ ...message, delivery: 'sent' }).delivery).toBe(
    'accepted',
  );
  expect(directTimelineRow({ ...message, delivery: 'sending' }).delivery).toBe(
    'queued',
  );
  expect(
    directTimelineRow({ ...message, direction: 'incoming', delivery: 'sent' })
      .delivery,
  ).toBeUndefined();
});
test('unavailable native projection never falls back to demo; missing operations remain unsupported', () => {
  const result = directDesignProjection({
    availability: 'unavailable',
    messages: [message],
  });
  expect(result.messages).toEqual([]);
  expect(result.source).toBe('native');
  expect(result.capabilities.copy).toBe(true); // Explicit frontend clipboard; no transport operation.
  expect(Object.entries(result.capabilities).filter(([name]) => name !== 'copy').every(([, value]) => !value)).toBe(
    true,
  );
});
