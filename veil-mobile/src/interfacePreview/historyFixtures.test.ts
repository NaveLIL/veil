import { expect, test } from '@jest/globals';
import { olderHistory } from './historyFixtures';
import { canGroup } from './messageGrouping';
import { showDelivery } from './deliveryPresentation';
test('deterministic long history contains author boundaries, twenty short replies, attention and media cases', () => {
  const history = olderHistory('stress', 716),
    cases = history.slice(-40);
  expect(history).toEqual(olderHistory('stress', 716));
  expect(new Set(history.map((row) => row.id)).size).toBe(716);
  expect(
    cases.slice(0, 7).map((row, index) => canGroup(cases[index - 1], row)),
  ).toEqual([false, true, true, true, false, true, false]);
  const short = cases.slice(7, 27);
  expect(short).toHaveLength(20);
  expect(
    short.filter((row, index) => showDelivery(row, short[index + 1])),
  ).toHaveLength(1);
  expect(canGroup(cases[6], cases[7])).toBe(false);
  for (const index of [27, 28, 29])
    expect(showDelivery(cases[index], cases[index + 1])).toBe(true);
  expect(cases[30].author!.length).toBeGreaterThan(40);
  expect(cases[31].text.length).toBeGreaterThan(4000);
  expect(cases[34]).toMatchObject({
    replyTo: cases[32].id,
    attachment: { kind: 'image' },
  });
  expect(cases[35]).toMatchObject({
    replyTo: cases[32].id,
    attachment: { kind: 'file' },
  });
});
