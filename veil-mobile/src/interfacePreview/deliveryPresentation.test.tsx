import React from 'react';
import { expect, test, jest } from '@jest/globals';
import { render } from '@testing-library/react-native';
import { showDelivery } from './deliveryPresentation';
import { DemoMessage, createDemoSession } from './model';
import { MessageRow } from './MessageRow';
import { palettes } from './appearance';
const own: DemoMessage = {
  id: 'one',
  own: true,
  text: 'Коротко',
  time: '10:00',
  delivery: 'accepted',
};
const next = { ...own, id: 'two', time: '10:01' };
test('only the last accepted status in the same author/time sequence is visual', () => {
  expect(showDelivery(own, next)).toBe(false);
  expect(showDelivery(next)).toBe(true);
  for (const delivery of ['queued', 'failed', 'unknown'] as const) {
    expect(showDelivery({ ...own, delivery }, { ...next, delivery })).toBe(
      true,
    );
    expect(showDelivery(own, { ...next, delivery })).toBe(true);
  }
});
test('dates, author, time gap, deletion and missing facts break status collapsing', () => {
  for (const delta of [
    { own: false },
    { author: 'Другой' },
    { time: '10:06' },
    { day: '2026-10-03' },
    { deleted: true },
    { delivery: undefined },
  ])
    expect(showDelivery(own, { ...next, ...delta })).toBe(true);
  expect(showDelivery({ ...own, deleted: true }, next)).toBe(false);
  expect(showDelivery({ ...own, own: false }, next)).toBe(false);
});
test('visually collapsed status remains available on the individual accessible message', () => {
  const ui = render(
    <MessageRow
      item={own}
      chat={createDemoSession().chats[0]}
      grouped
      showStatus={false}
      c={palettes.OLED}
      onMessage={jest.fn()}
      onRetry={jest.fn()}
    />,
  );
  expect(ui.queryByTestId('delivery-one')).toBeNull();
  expect(ui.getByLabelText('Вы: Коротко. 10:00. Отправлено')).toBeTruthy();
});
