import React from 'react';
import { act, fireEvent, render } from '@testing-library/react-native';
import { Animated, Modal, PanResponder, PanResponderCallbacks, Text } from 'react-native';
import { afterEach, expect, jest, test } from '@jest/globals';
import { VeilSheet } from './VeilSheet';
import { palettes } from './appearance';

afterEach(() => { jest.restoreAllMocks(); });
test('the dismiss grip is accessible, contains no cross, and Back cannot dismiss twice', () => {
  const close = jest.fn();
  const ui = render(<VeilSheet c={palettes.OLED} reduceMotion onClose={close}><Text>Content</Text></VeilSheet>);
  const grip = ui.getByRole('button', { name: 'Закрыть панель' });
  expect(grip.props.accessibilityActions).toEqual([{name:'dismiss',label:'Закрыть панель'}]);
  fireEvent.press(grip);
  fireEvent(ui.UNSAFE_getByType(Modal), 'requestClose');
  expect(close).toHaveBeenCalledTimes(1);
});
test('swipe dismissal finishes once if Reduce Motion interrupts its native animation', () => {
  let completion: ((result: { finished: boolean }) => void) | undefined;
  let pan: PanResponderCallbacks | undefined;
  jest.spyOn(PanResponder, 'create').mockImplementation(config => { pan = config; return {panHandlers:{}}; });
  jest.spyOn(Animated, 'timing').mockReturnValue({ start: jest.fn((callback?: (result: { finished: boolean }) => void) => { completion = callback; }), stop: jest.fn(), reset: jest.fn() });
  const close = jest.fn(), content = (reduceMotion: boolean) => <VeilSheet c={palettes.OLED} reduceMotion={reduceMotion} onClose={close}><Text>Content</Text></VeilSheet>;
  const ui = render(content(false));
  act(() => pan?.onPanResponderRelease?.({} as never, {dy:90,vy:1} as never));
  expect(close).not.toHaveBeenCalled();
  ui.rerender(content(true));
  expect(close).toHaveBeenCalledTimes(1);
  act(() => completion?.({finished:false}));
  expect(close).toHaveBeenCalledTimes(1);
});
test('a destroyed sheet cannot deliver its old animation callback', () => {
  let completion: ((result: { finished: boolean }) => void) | undefined;
  jest.spyOn(Animated, 'timing').mockReturnValue({ start: jest.fn((callback?: (result: { finished: boolean }) => void) => { completion = callback; }), stop: jest.fn(), reset: jest.fn() });
  const close = jest.fn();
  const ui = render(<VeilSheet c={palettes.OLED} reduceMotion={false} onClose={close}><Text>Content</Text></VeilSheet>);
  act(() => ui.UNSAFE_getByType(Modal).props.onShow());
  ui.unmount();
  act(() => completion?.({finished:true}));
  expect(close).not.toHaveBeenCalled();
});
