import React from 'react';
import { afterEach, expect, jest, test } from '@jest/globals';
import { cleanup, fireEvent, render } from '@testing-library/react-native';
import { MessageActionsPanel } from './MessageActionsPanel';
import { MessageQuote } from './MessageQuote';
import { palettes } from './appearance';
import { createDemoSession } from './model';
afterEach(cleanup);
test('peer menu has reply/copy only; own deletion needs an explicit confirmation', () => {
  const props = {
    c: palettes.OLED,
    reduceMotion: true,
    onClose: jest.fn(),
    onAction: jest.fn(),
  };
  const message = { id: 'x', own: false, text: 'сообщение', time: '12:00' };
  const ui = render(<MessageActionsPanel message={message} {...props} />);
  expect(ui.getByRole('button', { name: 'Ответить' })).toBeTruthy();
  expect(ui.queryByRole('button', { name: 'Редактировать' })).toBeNull();
  ui.rerender(
    <MessageActionsPanel
      message={{ ...message, own: true, delivery: 'accepted' }}
      {...props}
    />,
  );
  fireEvent.press(ui.getByRole('button', { name: 'Удалить' }));
  expect(props.onAction).not.toHaveBeenCalled();
  fireEvent.press(ui.getByRole('button', { name: 'Отмена' }));
  fireEvent.press(ui.getByRole('button', { name: 'Удалить' }));
  fireEvent.press(ui.getByRole('button', { name: 'Подтвердить удаление' }));
  expect(props.onAction).toHaveBeenCalledWith('delete');
});
test('quotes distinguish unavailable and deleted originals without showing deleted plaintext', () => {
  const chat = createDemoSession().chats[0];
  const props = { c: palettes.OLED, onPress: jest.fn() };
  const ui = render(<MessageQuote chat={chat} id="missing" {...props} />);
  expect(ui.getByText('Оригинал недоступен')).toBeTruthy();
  ui.rerender(
    <MessageQuote
      chat={{
        ...chat,
        messages: [
          { id: 'gone', own: true, time: '12:00', text: '', deleted: true },
        ],
      }}
      id="gone"
      {...props}
    />,
  );
  expect(ui.getByText('Сообщение удалено')).toBeTruthy();
});
test('quote cancellation and original navigation are independent touch actions', () => {
  const onPress = jest.fn(),
    onDismiss = jest.fn();
  const ui = render(
    <MessageQuote
      chat={createDemoSession().chats[0]}
      id="fixture-a1"
      c={palettes.OLED}
      onPress={onPress}
      onDismiss={onDismiss}
    />,
  );
  fireEvent.press(ui.getByLabelText('Отменить ответ'));
  expect(onDismiss).toHaveBeenCalledTimes(1);
  expect(onPress).not.toHaveBeenCalled();
  fireEvent.press(ui.getByLabelText(/Перейти к оригиналу:/));
  expect(onPress).toHaveBeenCalledTimes(1);
});
