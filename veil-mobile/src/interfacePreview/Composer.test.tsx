import React from 'react';
import { afterEach, expect, jest, test } from '@jest/globals';
import { cleanup, fireEvent, render } from '@testing-library/react-native';
import { Dimensions, StyleSheet } from 'react-native';
import { Composer } from './Composer';
import { palettes } from './appearance';

afterEach(cleanup);
test('multiline drafts are preserved; a long field is capped and clearing restores its height', () => {
  const onChange = jest.fn();
  const onSend = jest.fn();
  const props = {
    value: 'Первая\nВторая',
    onChange,
    onSend,
    blocked: false,
    placeholder: 'Написать',
    c: palettes.OLED,
  };
  const scale = Dimensions.get('window').fontScale;
  const ui = render(<Composer {...props} />);
  fireEvent.changeText(
    ui.getByTestId('preview-composer'),
    'Первая\nВторая\nТретья',
  );
  expect(onChange).toHaveBeenCalledWith('Первая\nВторая\nТретья');
  fireEvent(ui.getByTestId('preview-composer'), 'contentSizeChange', {
    nativeEvent: { contentSize: { width: 300, height: 500 } },
  });
  expect(
    StyleSheet.flatten(ui.getByTestId('preview-composer').props.style).height,
  ).toBe(Math.ceil(22 * scale * 5 + 24));
  expect(ui.getByTestId('preview-composer').props.scrollEnabled).toBe(true);
  fireEvent.press(ui.getByLabelText('Отправить демо-сообщение'));
  expect(onSend).toHaveBeenCalledTimes(1);
  ui.rerender(<Composer {...props} value="" />);
  expect(
    StyleSheet.flatten(ui.getByTestId('preview-composer').props.style).height,
  ).toBe(Math.max(48, Math.ceil(22 * scale + 24)));
});
test('whitespace and identity change block sending without discarding the draft', () => {
  const onSend = jest.fn();
  const props = {
    value: ' \n ',
    onChange: jest.fn(),
    onSend,
    blocked: false,
    placeholder: 'Написать',
    c: palettes.OLED,
  };
  const ui = render(<Composer {...props} />);
  fireEvent.press(ui.getByLabelText('Отправить демо-сообщение'));
  ui.rerender(<Composer {...props} value="Сохранить черновик" blocked />);
  expect(ui.getByTestId('preview-composer').props.value).toBe(
    'Сохранить черновик',
  );
  expect(ui.getByTestId('preview-composer').props.editable).toBe(false);
  fireEvent.press(ui.getByLabelText('Отправить демо-сообщение'));
  expect(onSend).not.toHaveBeenCalled();
});
