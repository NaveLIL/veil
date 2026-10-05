import React from 'react';
import { afterEach, beforeEach, expect, jest, test } from '@jest/globals';
import { act, cleanup, fireEvent, render } from '@testing-library/react-native';
import { FlatList } from 'react-native';
import { DesignApp } from './DesignApp';
import { canGroup, createDemoSession, visibleChats } from './model';
import { ConversationHistory } from './ConversationHistory';
import { ChatDeck } from './ChatDeck';
import { copyDemoText } from './clipboardBridge';
jest.mock('./preferencesBridge', () => {
  const actual = jest.requireActual<typeof import('./preferencesBridge')>(
    './preferencesBridge',
  );
  return {
    ...actual,
    loadPreferences: jest
      .fn<() => Promise<typeof actual.defaultPreferences>>()
      .mockResolvedValue(actual.defaultPreferences),
    savePreferences: jest.fn<() => Promise<null>>().mockResolvedValue(null),
  };
});
jest.mock('./clipboardBridge', () => ({
  copyDemoText: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
}));
jest.mock('react-native-reanimated', () =>
  jest.requireActual('react-native-reanimated/mock'),
);
jest.mock('react-native-gesture-handler', () => {
  const { View } =
    jest.requireActual<typeof import('react-native')>('react-native');
  const ReactModule = jest.requireActual<typeof import('react')>('react');
  return {
    GestureHandlerRootView: View,
    GestureDetector: ({ children }: { children: React.ReactNode }) =>
      ReactModule.createElement(ReactModule.Fragment, null, children),
    Gesture: {
      Pan: () => {
        const builder: Record<string, (...args: unknown[]) => unknown> = {};
        for (const key of [
          'enabled',
          'maxPointers',
          'activeOffsetX',
          'failOffsetY',
          'onStart',
          'onUpdate',
          'onEnd',
          'onFinalize',
        ])
          builder[key] = () => builder;
        return builder;
      },
    },
  };
});
jest.mock('react-native-safe-area-context', () => {
  const ReactModule = jest.requireActual<typeof import('react')>('react');
  const { View } =
    jest.requireActual<typeof import('react-native')>('react-native');
  return {
    SafeAreaProvider: ({ children }: { children: React.ReactNode }) => children,
    SafeAreaView: ({ children, ...props }: { children: React.ReactNode }) =>
      ReactModule.createElement(View, props, children),
  };
});
beforeEach(() => {
  jest.useFakeTimers();
});
afterEach(async () => {
  await act(async () => {
    jest.runOnlyPendingTimers();
  });
  cleanup();
  jest.useRealTimers();
});
async function mount() {
  const ui = render(<DesignApp />);
  await act(async () => {});
  return ui;
}
async function finishSheetTransition() {
  await act(async () => { jest.advanceTimersByTime(240); });
}
test('messages and spaces keep the dock, every conversation opens full screen and returns to its source', async () => {
  const ui = await mount();
  expect(ui.getByTestId('navigation-dock')).toBeTruthy();
  fireEvent.press(
    ui.getByRole('button', { name: /Дизайн Veil, непрочитанных/ }),
  );
  expect(ui.queryByTestId('navigation-dock')).toBeNull();
  expect(ui.getByText('Групповой чат · демо')).toBeTruthy();
  fireEvent.press(ui.getByLabelText('Назад к списку'));
  fireEvent.press(ui.getByRole('tab', { name: 'Пространство Студия' }));
  fireEvent.press(ui.getByLabelText('Открыть канал общий'));
  expect(ui.queryByTestId('navigation-dock')).toBeNull();
  expect(ui.getByText('# общий')).toBeTruthy();
  fireEvent.press(ui.getByLabelText('Назад к списку'));
  expect(
    ui.getByLabelText('Пространство Студия').props.accessibilityState.selected,
  ).toBe(true);
  expect(ui.getByLabelText('Открыть канал общий')).toBeTruthy();
  expect(
    visibleChats(createDemoSession(), '', false).some(
      (c) => c.kind === 'channel',
    ),
  ).toBe(false);
});
test('collapsed search, draft and return preserve conversation state', async () => {
  const ui = await mount();
  expect(
    ui.queryByLabelText('Найти демо-чат по имени или username'),
  ).toBeNull();
  fireEvent.press(ui.getByLabelText('Поиск чатов'));
  fireEvent.changeText(
    ui.getByLabelText('Найти демо-чат по имени или username'),
    'Анна',
  );
  fireEvent.press(
    ui.getByRole('button', { name: /Анна Морозова, непрочитанных/ }),
  );
  fireEvent.changeText(
    ui.getByLabelText('Текст демо-сообщения'),
    'проверка связи',
  );
  fireEvent.press(ui.getByLabelText('Назад к списку'));
  expect(
    ui.getByLabelText('Найти демо-чат по имени или username').props.value,
  ).toBe('Анна');
  expect(ui.getByText('Черновик: проверка связи')).toBeTruthy();
  fireEvent.press(
    ui.getByRole('button', { name: /Анна Морозова, есть черновик/ }),
  );
  fireEvent.press(ui.getByLabelText('Отправить демо-сообщение'));
  await act(async () => {
    jest.runOnlyPendingTimers();
  });
  const history = ui
    .UNSAFE_getAllByType(FlatList)
    .find((list) => list.props.testID === 'history-list-demo-anna');
  expect(history?.props.data[history.props.data.length - 1].text).toBe(
    'проверка связи',
  );
  expect(ui.getByLabelText('Текст демо-сообщения').props.value).toBe('');
});
test('identity change blocks composer while retaining the draft', async () => {
  const ui = await mount();
  fireEvent.press(
    ui.getByRole('button', { name: /Анна Морозова, непрочитанных/ }),
  );
  fireEvent.changeText(ui.getByLabelText('Текст демо-сообщения'), 'сохранить');
  fireEvent.press(ui.getByLabelText('Состояния и настройки макета'));
  fireEvent.press(ui.getByRole('radio', { name: 'Ключ изменился' }));
  fireEvent.press(ui.getByLabelText('Закрыть'));
  await finishSheetTransition();
  expect(ui.getByLabelText('Текст демо-сообщения').props.editable).toBe(false);
  expect(ui.getByLabelText('Текст демо-сообщения').props.value).toBe(
    'сохранить',
  );
  expect(
    ui.getByLabelText('Отправить демо-сообщение').props.accessibilityState
      .disabled,
  ).toBe(true);
});
test('desktop theme presets survive navigation and the lock preview needs no credentials', async () => {
  const ui = await mount();
  fireEvent.press(ui.getByLabelText('Раскрыть свой профиль'));
  fireEvent.press(ui.getByRole('tab', { name: 'Настройки' }));
  fireEvent.press(ui.getByRole('button', { name: 'Внешний вид' }));
  for (const theme of ['Veil', 'Midnight', 'Ocean', 'Forest', 'OLED'])
    expect(ui.getByLabelText(`Тема ${theme}`)).toBeTruthy();
  fireEvent.press(ui.getByLabelText('Тема Ocean'));
  fireEvent.press(ui.getByLabelText('Закрыть свой профиль'));
  await finishSheetTransition();
  fireEvent.press(ui.getByLabelText('Раскрыть свой профиль'));
  expect(ui.getByLabelText('Тема Ocean').props.accessibilityState.checked).toBe(
    true,
  );
  fireEvent.press(
    ui.getByRole('button', { name: 'Посмотреть экран блокировки' }),
  );
  expect(ui.getByText('Демо · PIN не требуется')).toBeTruthy();
  fireEvent.press(ui.getByText('Вернуться в макет'));
  expect(ui.getByTestId('navigation-dock')).toBeTruthy();
});
test('revealing navigation and browsing a space retains the active chat, draft and hidden profile', async () => {
  const ui = await mount();
  const floatingProfile = ui.getByTestId('floating-profile');
  fireEvent.press(
    ui.getByRole('button', { name: /Анна Морозова, непрочитанных/ }),
  );
  fireEvent.changeText(
    ui.getByLabelText('Текст демо-сообщения'),
    'остаться в этом чате',
  );
  expect(ui.queryByLabelText('Раскрыть свой профиль')).toBeNull();
  expect(
    ui.getByTestId('floating-profile', { includeHiddenElements: true }),
  ).toBe(floatingProfile);
  fireEvent.press(ui.getByLabelText('Назад к списку'));
  fireEvent.press(ui.getByLabelText('Пространство Студия'));
  expect(ui.getByLabelText('Раскрыть свой профиль')).toBeTruthy();
  expect(ui.queryByLabelText('Вернуться в последний чат')).toBeNull();
  // Swiping the existing deck closed resumes the retained conversation.
  act(() => ui.UNSAFE_getByType(ChatDeck).props.onNavigationChange(false));
  expect(ui.getByText('Личный чат · демо')).toBeTruthy();
  expect(ui.getByLabelText('Текст демо-сообщения').props.value).toBe(
    'остаться в этом чате',
  );
  expect(ui.queryByLabelText('Раскрыть свой профиль')).toBeNull();
  fireEvent.press(ui.getByLabelText('Назад к списку'));
  expect(
    ui.getByLabelText('Пространство Студия').props.accessibilityState.selected,
  ).toBe(true);
});
test('floating profile editing updates its card and exposes settings inside the profile', async () => {
  const ui = await mount();
  fireEvent.press(ui.getByLabelText('Раскрыть свой профиль'));
  fireEvent.press(ui.getByLabelText('Редактировать демо-профиль'));
  fireEvent.changeText(ui.getByLabelText('Имя демо-профиля'), 'Мой Veil');
  fireEvent.press(ui.getByLabelText('Готово'));
  fireEvent.press(ui.getByLabelText('Закрыть свой профиль'));
  await finishSheetTransition();
  expect(ui.getByText('Мой Veil')).toBeTruthy();
  fireEvent.press(ui.getByLabelText('Раскрыть свой профиль'));
  fireEvent.press(ui.getByRole('tab', { name: 'Настройки' }));
  for (const name of ['Внешний вид', 'Безопасность', 'Уведомления', 'Сеть'])
    expect(ui.getByRole('button', { name })).toBeTruthy();
});
test('timeline groups only the same author within five forward minutes', () => {
  const first = {
    id: '1',
    own: false,
    author: 'Анна',
    time: '14:00',
    text: 'a',
  };
  expect(canGroup(first, { ...first, id: '2', time: '14:05' })).toBe(true);
  expect(canGroup(first, { ...first, author: 'Максим' })).toBe(false);
  expect(canGroup(first, { ...first, own: true })).toBe(false);
  expect(canGroup(first, { ...first, time: '13:59' })).toBe(false);
  expect(canGroup(first, { ...first, time: '14:06' })).toBe(false);
});
test('message actions retain per-chat reply/draft state and edit cancellation restores the ordinary composer', async () => {
  const ui = await mount();
  fireEvent.press(
    ui.getByRole('button', { name: /Анна Морозова, непрочитанных/ }),
  );
  fireEvent.changeText(ui.getByLabelText('Текст демо-сообщения'), 'черновик');
  const select = (id: string) =>
    act(() => {
      const message = createDemoSession().chats[0].messages.find(
        (m) => m.id === id,
      )!;
      ui.UNSAFE_getByType(ConversationHistory).props.onMessage(message);
    });
  select('fixture-a1');
  fireEvent.press(ui.getByRole('button', { name: 'Ответить' }));
  expect(ui.getByLabelText('Отменить ответ')).toBeTruthy();
  fireEvent.press(ui.getByLabelText('Назад к списку'));
  fireEvent.press(ui.getByRole('button', { name: /^Максим/ }));
  expect(ui.queryByLabelText('Отменить ответ')).toBeNull();
  fireEvent.press(ui.getByLabelText('Назад к списку'));
  fireEvent.press(
    ui.getByRole('button', { name: /Анна Морозова, есть черновик/ }),
  );
  expect(ui.getByLabelText('Отменить ответ')).toBeTruthy();
  select('fixture-a2');
  fireEvent.press(ui.getByRole('button', { name: 'Редактировать' }));
  fireEvent.changeText(
    ui.getByLabelText('Текст демо-сообщения'),
    'редактирование',
  );
  fireEvent.press(ui.getByLabelText('Отменить редактирование'));
  expect(ui.getByLabelText('Текст демо-сообщения').props.value).toBe(
    'черновик',
  );
  expect(ui.getByLabelText('Отменить ответ')).toBeTruthy();
  select('fixture-a2');
  fireEvent.press(ui.getByRole('button', { name: 'Копировать' }));
  await act(async () => {});
  expect(copyDemoText).toHaveBeenCalledWith(
    'Согласен. Сначала доведём личные чаты до мелочей.',
  );
  expect(ui.getByText('Текст скопирован')).toBeTruthy();
  jest.mocked(copyDemoText).mockRejectedValueOnce(new Error('Unavailable'));
  select('fixture-a1');
  fireEvent.press(ui.getByRole('button', { name: 'Копировать' }));
  await act(async () => {});
  expect(ui.getByText('Не удалось скопировать текст')).toBeTruthy();
});
test('attachment cancellation retains caption; viewer and retry keep the same native history/message', async () => {
  const ui = await mount();
  fireEvent.press(ui.getByRole('button', { name: /^Анна Морозова, / }));
  fireEvent.changeText(ui.getByLabelText('Текст демо-сообщения'), 'подпись');
  fireEvent.press(ui.getByLabelText('Добавить вложение'));
  fireEvent.press(ui.getByRole('button', { name: 'Демо-изображение' }));
  fireEvent.press(ui.getByLabelText('Убрать вложение'));
  expect(ui.getByLabelText('Текст демо-сообщения').props.value).toBe('подпись');
  fireEvent.press(ui.getByLabelText('Состояния и настройки макета'));
  fireEvent.press(ui.getByRole('radio', { name: 'Ошибка отправки' }));
  fireEvent.press(ui.getByLabelText('Закрыть'));
  await finishSheetTransition();
  fireEvent.press(ui.getByLabelText('Добавить вложение'));
  fireEvent.press(ui.getByRole('button', { name: 'Демо-изображение' }));
  fireEvent.press(ui.getByLabelText('Отправить демо-сообщение'));
  for (let i = 0; i < 2; i++)
    await act(async () => {
      jest.advanceTimersByTime(650);
    });
  const list = ui.getByTestId('history-list-demo-anna');
  const data = () =>
    ui
      .UNSAFE_getAllByType(FlatList)
      .find((v) => v.props.testID === 'history-list-demo-anna')!.props.data;
  const count = data().length;
  expect(data()[count - 1].transfer.phase).toBe('failed');
  act(() =>
    ui
      .UNSAFE_getByType(ConversationHistory)
      .props.onAttachment(data()[count - 1].attachment),
  );
  fireEvent.press(ui.getByLabelText('Закрыть изображение'));
  await finishSheetTransition();
  expect(ui.getByTestId('history-list-demo-anna')).toBe(list);
  fireEvent.press(ui.getByLabelText('Состояния и настройки макета'));
  fireEvent.press(ui.getByRole('radio', { name: 'Обычный чат' }));
  fireEvent.press(ui.getByLabelText('Закрыть'));
  await finishSheetTransition();
  act(() =>
    ui
      .UNSAFE_getByType(ConversationHistory)
      .props.onRetry('demo-anna', data()[count - 1].id),
  );
  for (let i = 0; i < 4; i++)
    await act(async () => {
      jest.advanceTimersByTime(650);
    });
  expect(data()).toHaveLength(count);
  expect(data()[count - 1].transfer.phase).toBe('complete');
  expect(data()[count - 1].text).toBe('подпись');
});

test('short viewport combines reply and attachment without losing either cancel action or the draft', async () => {
  const ui = await mount();
  fireEvent.press(ui.getByRole('button', { name: /^Анна Морозова, / }));
  act(() =>
    ui
      .UNSAFE_getByType(ConversationHistory)
      .props.onMessage(
        createDemoSession().chats[0].messages.find(
          (m) => m.id === 'fixture-a2',
        ),
      ),
  );
  fireEvent.press(ui.getByRole('button', { name: 'Ответить' }));
  fireEvent.changeText(ui.getByLabelText('Текст демо-сообщения'), 'подпись');
  fireEvent.press(ui.getByLabelText('Добавить вложение'));
  fireEvent.press(ui.getByRole('button', { name: 'Демо-изображение' }));
  fireEvent(ui.getByTestId('conversation-island'), 'layout', {
    nativeEvent: { layout: { width: 390, height: 340 } },
  });
  expect(ui.getByTestId('compact-composition-context')).toBeTruthy();
  expect(ui.getByLabelText('Отменить ответ')).toBeTruthy();
  expect(ui.getByLabelText('Убрать вложение')).toBeTruthy();
  fireEvent(ui.getByTestId('conversation-island'), 'layout', {
    nativeEvent: { layout: { width: 390, height: 740 } },
  });
  expect(ui.queryByTestId('compact-composition-context')).toBeNull();
  fireEvent.press(ui.getByLabelText('Убрать вложение'));
  expect(ui.getByLabelText('Отменить ответ')).toBeTruthy();
  expect(ui.getByLabelText('Текст демо-сообщения').props.value).toBe('подпись');
  fireEvent.press(ui.getByLabelText('Отменить ответ'));
  expect(ui.getByLabelText('Текст демо-сообщения').props.value).toBe('подпись');
});
