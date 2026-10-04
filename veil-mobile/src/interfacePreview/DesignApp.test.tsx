import React from 'react';
import { afterEach, beforeEach, expect, jest, test } from '@jest/globals';
import { act, cleanup, fireEvent, render } from '@testing-library/react-native';
import { FlatList } from 'react-native';
import { DesignApp } from './DesignApp';
import { canGroup, createDemoSession, visibleChats } from './model';
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
  fireEvent.press(ui.getByLabelText('Вернуться в последний чат'));
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
