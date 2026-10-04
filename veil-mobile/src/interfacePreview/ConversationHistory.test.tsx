import React from 'react';
import { afterEach, beforeEach, expect, jest, test } from '@jest/globals';
import { act, cleanup, fireEvent, render } from '@testing-library/react-native';
import { FlatList } from 'react-native';
import { ConversationHistory } from './ConversationHistory';
import { palettes } from './appearance';
import { createDemoSession, receiveDemo, sendDemo, setDraft } from './model';

beforeEach(() => {
  jest.useFakeTimers();
});
afterEach(() => {
  cleanup();
  jest.restoreAllMocks();
  jest.useRealTimers();
});
const callbacks = () => ({
  onMessage: jest.fn(),
  onRetry: jest.fn(),
  onRead: jest.fn(),
});
const readingEvent = {
  nativeEvent: {
    contentOffset: { x: 0, y: 500 },
    contentSize: { width: 360, height: 10000 },
    layoutMeasurement: { width: 360, height: 500 },
  },
};
test('incoming messages while reading keep the position and offer a counted explicit jump', async () => {
  const scroll = jest
    .spyOn(FlatList.prototype, 'scrollToEnd')
    .mockImplementation(() => {});
  let session = createDemoSession();
  const actions = callbacks();
  const props = {
    chatId: 'demo-anna',
    visible: true,
    c: palettes.OLED,
    reduceMotion: true,
    ...actions,
  };
  const ui = render(<ConversationHistory chats={session.chats} {...props} />);
  await act(async () => {
    jest.runOnlyPendingTimers();
  });
  scroll.mockClear();
  actions.onRead.mockClear();
  const list = ui.getByTestId('history-list-demo-anna');
  fireEvent(list, 'scrollBeginDrag', readingEvent);
  fireEvent.scroll(list, readingEvent);
  fireEvent(list, 'scrollEndDrag', readingEvent);
  session = receiveDemo(session, 'demo-anna', 3, '15:00');
  ui.rerender(<ConversationHistory chats={session.chats} {...props} />);
  await act(async () => {
    jest.runOnlyPendingTimers();
  });
  expect(scroll).not.toHaveBeenCalled();
  expect(actions.onRead).not.toHaveBeenCalled();
  expect(
    ui.getByLabelText('Новые сообщения: 3. К последним сообщениям'),
  ).toBeTruthy();
  expect(ui.getByTestId('history-list-demo-anna')).toBe(list);
  fireEvent.press(ui.getByTestId('jump-latest'));
  await act(async () => {
    jest.runOnlyPendingTimers();
  });
  expect(scroll).toHaveBeenCalledWith({ animated: false });
});
test('switching chats retains the previous native list and its reading state; own sending follows the tail', async () => {
  const scroll = jest
    .spyOn(FlatList.prototype, 'scrollToEnd')
    .mockImplementation(() => {});
  let session = createDemoSession();
  const props = {
    visible: true,
    c: palettes.OLED,
    reduceMotion: true,
    ...callbacks(),
  };
  const ui = render(
    <ConversationHistory chats={session.chats} chatId="demo-anna" {...props} />,
  );
  await act(async () => {
    jest.runOnlyPendingTimers();
  });
  const list = ui.getByTestId('history-list-demo-anna');
  fireEvent(list, 'scrollBeginDrag', readingEvent);
  fireEvent.scroll(list, readingEvent);
  fireEvent(list, 'scrollEndDrag', readingEvent);
  ui.rerender(
    <ConversationHistory chats={session.chats} chatId="demo-max" {...props} />,
  );
  expect(
    ui.getByTestId('history-list-demo-anna', { includeHiddenElements: true }),
  ).toBe(list);
  ui.rerender(
    <ConversationHistory chats={session.chats} chatId="demo-anna" {...props} />,
  );
  expect(ui.getByTestId('history-list-demo-anna')).toBe(list);
  expect(ui.getByLabelText('К последним сообщениям')).toBeTruthy();
  scroll.mockClear();
  session = sendDemo(
    setDraft(session, 'demo-anna', 'свой ответ'),
    'demo-anna',
    '15:00',
  );
  ui.rerender(
    <ConversationHistory chats={session.chats} chatId="demo-anna" {...props} />,
  );
  await act(async () => {
    jest.runOnlyPendingTimers();
  });
  expect(scroll).toHaveBeenCalled();
  expect(ui.queryByTestId('jump-latest')).toBeNull();
});
test('prepending a page preserves the loaded anchor and receiving does not trim the head', async () => {
  jest.spyOn(FlatList.prototype, 'scrollToEnd').mockImplementation(() => {});
  let session = createDemoSession();
  const props = {
    chatId: 'demo-anna',
    visible: true,
    c: palettes.OLED,
    reduceMotion: true,
    ...callbacks(),
  };
  const ui = render(<ConversationHistory chats={session.chats} {...props} />);
  await act(async () => {
    jest.runOnlyPendingTimers();
  });
  const data = () =>
    ui
      .UNSAFE_getAllByType(FlatList)
      .find((list) => list.props.testID === 'history-list-demo-anna')!.props
      .data;
  const anchor = data()[0].id;
  expect(data()).toHaveLength(40);
  fireEvent.press(ui.getByLabelText('Показать более ранние сообщения'));
  expect(data()).toHaveLength(80);
  expect(data()[40].id).toBe(anchor);
  const firstLoaded = data()[0].id;
  session = receiveDemo(session, 'demo-anna', 3, '15:00');
  ui.rerender(<ConversationHistory chats={session.chats} {...props} />);
  expect(data()).toHaveLength(83);
  expect(data()[0].id).toBe(firstLoaded);
  expect(data()[40].id).toBe(anchor);
});
test('quote jump loads an earlier original by ID and highlights only after visibility is confirmed', async () => {
  const seek = jest
    .spyOn(FlatList.prototype, 'scrollToIndex')
    .mockImplementation(() => {});
  jest.spyOn(FlatList.prototype, 'scrollToEnd').mockImplementation(() => {});
  const session = createDemoSession();
  const props = {
    chatId: 'demo-anna',
    visible: true,
    c: palettes.OLED,
    reduceMotion: true,
    ...callbacks(),
  };
  const ui = render(<ConversationHistory chats={session.chats} {...props} />);
  await act(async () => {
    jest.runOnlyPendingTimers();
  });
  const target = session.chats[0].messages[20];
  ui.rerender(
    <ConversationHistory
      chats={session.chats}
      {...props}
      jump={{ chatId: 'demo-anna', messageId: target.id, sequence: 1 }}
    />,
  );
  await act(async () => {
    jest.advanceTimersByTime(180);
  });
  const list = ui
    .UNSAFE_getAllByType(FlatList)
    .find((node) => node.props.testID === 'history-list-demo-anna')!;
  expect(list.props.data.some((m: { id: string }) => m.id === target.id)).toBe(
    true,
  );
  expect(seek).toHaveBeenCalledWith({
    index: 10,
    viewPosition: 0.35,
    animated: false,
  });
  expect(list.props.extraData).not.toContain(target.id);
  act(() =>
    list.props.onViewableItemsChanged({
      viewableItems: [
        { item: target, isViewable: true, index: 10, key: target.id },
      ],
    }),
  );
  expect(
    ui
      .UNSAFE_getAllByType(FlatList)
      .find((node) => node.props.testID === 'history-list-demo-anna')!.props
      .extraData,
  ).toContain(target.id);
  await act(async () => {
    jest.advanceTimersByTime(1900);
  });
  expect(
    ui
      .UNSAFE_getAllByType(FlatList)
      .find((node) => node.props.testID === 'history-list-demo-anna')!.props
      .extraData,
  ).not.toContain(target.id);
});
test('unresolved quote seeks are bounded and cancelled by a reading gesture', async () => {
  const seek = jest
    .spyOn(FlatList.prototype, 'scrollToIndex')
    .mockImplementation(() => {});
  jest.spyOn(FlatList.prototype, 'scrollToEnd').mockImplementation(() => {});
  const session = createDemoSession();
  const onNotice = jest.fn();
  const props = {
    chatId: 'demo-anna',
    visible: true,
    c: palettes.OLED,
    reduceMotion: true,
    onNotice,
    ...callbacks(),
  };
  const ui = render(
    <ConversationHistory
      chats={session.chats}
      {...props}
      jump={{ chatId: 'demo-anna', messageId: 'fixture-a1', sequence: 1 }}
    />,
  );
  for (let i = 0; i < 14; i++)
    await act(async () => {
      jest.advanceTimersByTime(200);
    });
  expect(seek.mock.calls.length).toBeLessThanOrEqual(12);
  expect(onNotice).toHaveBeenCalledWith(
    'Не удалось показать оригинал. Попробуйте ещё раз.',
  );
  onNotice.mockClear();
  ui.rerender(
    <ConversationHistory
      chats={session.chats}
      {...props}
      jump={{ chatId: 'demo-anna', messageId: 'fixture-a1', sequence: 2 }}
    />,
  );
  fireEvent(
    ui.getByTestId('history-list-demo-anna'),
    'scrollBeginDrag',
    readingEvent,
  );
  for (let i = 0; i < 14; i++)
    await act(async () => {
      jest.advanceTimersByTime(200);
    });
  expect(onNotice).not.toHaveBeenCalled();
});
