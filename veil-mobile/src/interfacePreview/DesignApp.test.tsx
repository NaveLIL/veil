import React from 'react';
import { expect, jest, test } from '@jest/globals';
import { act, fireEvent, render } from '@testing-library/react-native';
import { DesignApp } from './DesignApp';
import { canGroup, createDemoSession, visibleChats } from './model';
jest.mock('react-native-safe-area-context', () => {
  const ReactModule = jest.requireActual<typeof import('react')>('react');
  const { View } = jest.requireActual<typeof import('react-native')>('react-native');
  return { SafeAreaProvider: ({ children }: { children: React.ReactNode }) => children,
    SafeAreaView: ({ children, ...props }: { children: React.ReactNode }) => ReactModule.createElement(View, props, children) };
});
async function mount() {
  const ui = render(<DesignApp />);
  await act(async () => {});
  return ui;
}
test('messages and spaces keep the dock, every conversation opens full screen and returns to its source', async () => {
  const ui = await mount();
  expect(ui.getByTestId('navigation-dock')).toBeTruthy();
  fireEvent.press(ui.getByRole('button', { name: /Дизайн Veil, непрочитанных/ }));
  expect(ui.queryByTestId('navigation-dock')).toBeNull();
  expect(ui.getByText('Групповой чат · демо')).toBeTruthy();
  fireEvent.press(ui.getByLabelText('Назад к списку'));
  fireEvent.press(ui.getByRole('tab', { name: 'Пространство Студия' }));
  fireEvent.press(ui.getByLabelText('Открыть канал общий'));
  expect(ui.queryByTestId('navigation-dock')).toBeNull();
  expect(ui.getByText('# общий')).toBeTruthy();
  fireEvent.press(ui.getByLabelText('Назад к списку'));
  expect(ui.getByLabelText('Пространство Студия').props.accessibilityState.selected).toBe(true);
  expect(ui.getByLabelText('Открыть канал общий')).toBeTruthy();
  expect(visibleChats(createDemoSession(), '', false).some(c => c.kind === 'channel')).toBe(false);
});
test('collapsed search, draft and return preserve conversation state', async () => {
  const ui = await mount();
  expect(ui.queryByLabelText('Найти демо-чат по имени или username')).toBeNull();
  fireEvent.press(ui.getByLabelText('Поиск чатов'));
  fireEvent.changeText(ui.getByLabelText('Найти демо-чат по имени или username'), 'Анна');
  fireEvent.press(ui.getByRole('button', { name: /Анна Морозова, непрочитанных/ }));
  fireEvent.changeText(ui.getByLabelText('Текст демо-сообщения'), 'проверка связи');
  fireEvent.press(ui.getByLabelText('Назад к списку'));
  expect(ui.getByLabelText('Найти демо-чат по имени или username').props.value).toBe('Анна');
  expect(ui.getByText('Черновик: проверка связи')).toBeTruthy();
  fireEvent.press(ui.getByRole('button', { name: /Анна Морозова, есть черновик/ }));
  fireEvent.press(ui.getByLabelText('Отправить демо-сообщение'));
  expect(ui.getByText('проверка связи')).toBeTruthy();
  expect(ui.getByLabelText('Текст демо-сообщения').props.value).toBe('');
});
test('identity change blocks composer while retaining the draft', async () => {
  const ui = await mount();
  fireEvent.press(ui.getByRole('button', { name: /Анна Морозова, непрочитанных/ }));
  fireEvent.changeText(ui.getByLabelText('Текст демо-сообщения'), 'сохранить');
  fireEvent.press(ui.getByLabelText('Состояния и настройки макета'));
  fireEvent.press(ui.getByRole('radio', { name: 'Ключ изменился' }));
  fireEvent.press(ui.getByLabelText('Закрыть'));
  expect(ui.getByLabelText('Текст демо-сообщения').props.editable).toBe(false);
  expect(ui.getByLabelText('Текст демо-сообщения').props.value).toBe('сохранить');
  expect(ui.getByLabelText('Отправить демо-сообщение').props.accessibilityState.disabled).toBe(true);
});
test('desktop theme presets survive navigation and the lock preview needs no credentials', async () => {
  const ui = await mount();
  fireEvent.press(ui.getByRole('tab', { name: 'Внешний вид' }));
  for (const theme of ['Veil', 'Midnight', 'Ocean', 'Forest', 'OLED']) expect(ui.getByLabelText(`Тема ${theme}`)).toBeTruthy();
  fireEvent.press(ui.getByLabelText('Тема Ocean'));
  fireEvent.press(ui.getByRole('tab', { name: 'Сообщения' }));
  fireEvent.press(ui.getByRole('tab', { name: 'Внешний вид' }));
  expect(ui.getByLabelText('Тема Ocean').props.accessibilityState.checked).toBe(true);
  fireEvent.press(ui.getByRole('tab', { name: 'Предпросмотр блокировки' }));
  expect(ui.getByText('Демо · PIN не требуется')).toBeTruthy();
  fireEvent.press(ui.getByText('Вернуться в макет'));
  expect(ui.getByTestId('navigation-dock')).toBeTruthy();
});
test('timeline groups only the same author within five forward minutes', () => {
  const first = { id: '1', own: false, author: 'Анна', time: '14:00', text: 'a' };
  expect(canGroup(first, { ...first, id: '2', time: '14:05' })).toBe(true);
  expect(canGroup(first, { ...first, author: 'Максим' })).toBe(false);
  expect(canGroup(first, { ...first, own: true })).toBe(false);
  expect(canGroup(first, { ...first, time: '13:59' })).toBe(false);
  expect(canGroup(first, { ...first, time: '14:06' })).toBe(false);
});
