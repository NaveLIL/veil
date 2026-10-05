import React from 'react';
import { expect, jest, test } from '@jest/globals';
import { render, fireEvent } from '@testing-library/react-native';
import { AttachmentCard } from './AttachmentCard';
import { designAttachments } from './attachments';
import { palettes } from './appearance';
test('unknown result exposes its uncertainty without offering a duplicate send', () => {
  const ui = render(
    <AttachmentCard
      asset={designAttachments[1]}
      c={palettes.OLED}
      onRetry={jest.fn()}
      transfer={{ phase: 'unknown', progress: 0, attempt: 1, fail: false }}
    />,
  );
  expect(ui.getByText('Демо: результат отправки неизвестен')).toBeTruthy();
  expect(
    ui.queryByRole('button', { name: 'Повторить отправку вложения' }),
  ).toBeNull();
  expect(ui.queryByRole('progressbar')).toBeNull();
});
test('image opens its viewer, failed operation retries only on action; preview removal is independent', () => {
  const onOpen = jest.fn(),
    onRetry = jest.fn(),
    onRemove = jest.fn();
  const ui = render(
    <AttachmentCard
      asset={designAttachments[0]}
      c={palettes.OLED}
      onOpen={onOpen}
      onRetry={onRetry}
      transfer={{ phase: 'failed', progress: 50, attempt: 1, fail: true }}
    />,
  );
  fireEvent.press(
    ui.getByLabelText('Открыть изображение: Тихий берег · иллюстрация'),
  );
  expect(onOpen).toHaveBeenCalledTimes(1);
  expect(onRetry).not.toHaveBeenCalled();
  fireEvent.press(
    ui.getByRole('button', { name: 'Повторить отправку вложения' }),
  );
  expect(onRetry).toHaveBeenCalledTimes(1);
  ui.rerender(
    <AttachmentCard
      asset={designAttachments[1]}
      c={palettes.OLED}
      compact
      onRemove={onRemove}
    />,
  );
  fireEvent.press(ui.getByLabelText('Убрать вложение'));
  expect(onRemove).toHaveBeenCalledTimes(1);
  expect(ui.queryByRole('imagebutton')).toBeNull();
});
