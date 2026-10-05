import React from 'react';
import { act, fireEvent, render } from '@testing-library/react-native';
import { AccessibilityInfo, Pressable } from 'react-native';
import { afterEach, beforeEach, expect, jest, test } from '@jest/globals';
import {
  AccessibilityFocusBoundary,
  useAccessibilityFocus,
} from './AccessibilityFocusBoundary';

function Probe() {
  const focus = useAccessibilityFocus();
  return (
    <>
      <Pressable testID="restore" onPress={() => focus.restore(733)} />
      <Pressable testID="new-modal" onPress={focus.cancel} />
    </>
  );
}
beforeEach(() => {
  jest.useFakeTimers();
});
afterEach(() => {
  jest.restoreAllMocks();
  jest.useRealTimers();
});
test('restores after Android dismissal; a reopened modal cancels the old target', () => {
  const native = jest
    .spyOn(AccessibilityInfo, 'setAccessibilityFocus')
    .mockImplementation(() => {});
  const view = render(
    <AccessibilityFocusBoundary>
      <Probe />
    </AccessibilityFocusBoundary>,
  );
  fireEvent.press(view.getByTestId('restore'));
  expect(native).not.toHaveBeenCalled();
  act(() => jest.advanceTimersByTime(350));
  expect(native).toHaveBeenCalledWith(733);
  native.mockClear();
  fireEvent.press(view.getByTestId('restore'));
  fireEvent.press(view.getByTestId('new-modal'));
  act(() => jest.advanceTimersByTime(1000));
  expect(native).not.toHaveBeenCalled();
});
test('no orphan focus request survives the workbench unmount', () => {
  const native = jest
    .spyOn(AccessibilityInfo, 'setAccessibilityFocus')
    .mockImplementation(() => {});
  const view = render(
    <AccessibilityFocusBoundary>
      <Probe />
    </AccessibilityFocusBoundary>,
  );
  fireEvent.press(view.getByTestId('restore'));
  view.unmount();
  act(() => jest.advanceTimersByTime(1000));
  expect(native).not.toHaveBeenCalled();
});
