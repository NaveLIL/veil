import React from 'react';
import { expect, jest, test } from '@jest/globals';
import { fireEvent, render } from '@testing-library/react-native';
import { DesignApp } from './DesignApp';

jest.mock('react-native-safe-area-context', () => {
  const ReactModule = jest.requireActual<typeof import('react')>('react');
  const { View } = jest.requireActual<typeof import('react-native')>('react-native');
  return { SafeAreaProvider: ({ children }: { children: React.ReactNode }) => children,
    SafeAreaView: ({ children, ...props }: { children: React.ReactNode }) => ReactModule.createElement(View, props, children) };
});

test('starts without enrollment and navigates reserved groups/spaces', () => {
  const ui = render(<DesignApp />);
  expect(ui.getByText('Личные чаты')).toBeTruthy();
  fireEvent.press(ui.getByRole('tab', { name: 'Группы' }));
  expect(ui.getByText('Место уже предусмотрено')).toBeTruthy();
  fireEvent.press(ui.getByRole('tab', { name: 'Пространства' }));
  expect(ui.getByText('Список пространств')).toBeTruthy();
  fireEvent.press(ui.getByRole('tab', { name: 'Чаты' }));
  expect(ui.getByText('Личные чаты')).toBeTruthy();
});
test('search, open, draft, back and reopen keep only local conversation state', () => {
  const ui = render(<DesignApp />);
  fireEvent.changeText(ui.getByLabelText('Найти демо-чат по имени или username'), 'Анна');
  fireEvent.press(ui.getByRole('button', { name: /Анна Морозова, непрочитанных/ }));
  fireEvent.changeText(ui.getByLabelText('Текст демо-сообщения'), 'Черновик теста');
  fireEvent.press(ui.getByLabelText('Назад к чатам'));
  expect(ui.getByText('Черновик: Черновик теста')).toBeTruthy();
  fireEvent.press(ui.getByRole('button', { name: /Анна Морозова, есть черновик/ }));
  fireEvent.press(ui.getByLabelText('Добавить демо-сообщение'));
  expect(ui.getByText('Черновик теста')).toBeTruthy();
  expect(ui.getByLabelText('Текст демо-сообщения').props.value).toBe('');
});
test('identity-changed scenario blocks composer, survives sheet close, preserves draft', () => {
  const ui = render(<DesignApp />);
  fireEvent.press(ui.getByRole('button', { name: /Анна Морозова, непрочитанных/ }));
  fireEvent.changeText(ui.getByLabelText('Текст демо-сообщения'), 'Сохранить');
  fireEvent.press(ui.getByLabelText('Состояния и настройки макета'));
  fireEvent.press(ui.getByRole('radio', { name: 'Ключ изменился' }));
  fireEvent.press(ui.getByLabelText('Закрыть'));
  expect(ui.getByLabelText('Текст демо-сообщения').props.editable).toBe(false);
  expect(ui.getByLabelText('Текст демо-сообщения').props.value).toBe('Сохранить');
  expect(ui.getByLabelText('Добавить демо-сообщение').props.accessibilityState.disabled).toBe(true);
});
