import React from 'react';
import { act, fireEvent, render } from '@testing-library/react-native';
import { Animated, Modal, PanResponder, PanResponderCallbacks, StyleSheet, Text, useWindowDimensions } from 'react-native';
import { afterEach, expect, jest, test } from '@jest/globals';
import { VeilSheet } from './VeilSheet';
import { palettes } from './appearance';
import { ModalBlurBoundary } from './LiveBlur';

afterEach(() => { jest.restoreAllMocks(); });
test('the first modal frame is offscreen and repeated native onShow does not restart entry', () => {
  const timing = jest.spyOn(Animated, 'timing').mockReturnValue({start:jest.fn(),stop:jest.fn(),reset:jest.fn()});
  let height = 0;
  function Content() { height = useWindowDimensions().height; return <Text>Content</Text>; }
  const ui = render(<VeilSheet c={palettes.OLED} reduceMotion={false} onClose={jest.fn()}><Content /></VeilSheet>);
  const panel = ui.UNSAFE_getByType(Animated.View);
  const translate = StyleSheet.flatten(panel.props.style).transform[0].translateY;
  expect(translate.__getValue()).toBe(height);
  expect(timing).not.toHaveBeenCalled();
  act(() => ui.UNSAFE_getByType(Modal).props.onShow());
  act(() => ui.UNSAFE_getByType(Modal).props.onShow());
  expect(timing).toHaveBeenCalledTimes(1);
  expect(timing.mock.calls[0][1]).toMatchObject({toValue:0,useNativeDriver:true});
});
test('an initially hidden sheet does not start an invisible exit animation', () => {
  const timing = jest.spyOn(Animated, 'timing');
  const ui = render(<VeilSheet visible={false} c={palettes.OLED} reduceMotion={false} onClose={jest.fn()}><Text>Content</Text></VeilSheet>);
  expect(ui.UNSAFE_getByType(Modal).props.visible).toBe(false);
  expect(timing).not.toHaveBeenCalled();
});
test('underlay blur starts clearing during exit, and reopening rejects the old exit', () => {
  const completions: ((r:{finished:boolean})=>void)[]=[];
  jest.spyOn(Animated,'timing').mockReturnValue({start:jest.fn((cb?: (r:{finished:boolean})=>void)=>{if(cb)completions.push(cb);}),stop:jest.fn(),reset:jest.fn()});
  const close=jest.fn(),tree=(visible:boolean)=><ModalBlurBoundary><VeilSheet visible={visible} c={palettes.OLED} reduceMotion={false} onClose={close}><Text>Content</Text></VeilSheet></ModalBlurBoundary>;
  const ui=render(tree(true));
  expect(ui.getByTestId('modal-blur-background', {includeHiddenElements:true}).props.blurRadius).toBe(12);
  ui.rerender(tree(false));
  expect(ui.UNSAFE_getByType(Modal).props.visible).toBe(true);
  expect(ui.getByTestId('modal-blur-background', {includeHiddenElements:true}).props.blurRadius).toBe(0);
  ui.rerender(tree(true));
  act(()=>completions[0]({finished:true}));
  expect(ui.UNSAFE_getByType(Modal).props.visible).toBe(true);
  expect(ui.getByTestId('modal-blur-background', {includeHiddenElements:true}).props.blurRadius).toBe(12);
  expect(close).not.toHaveBeenCalled();
});
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

test.each(['grip', 'back', 'outside', 'accessibility'] as const)('%s dismissal shares the animated exit and completes once', source => {
  let completion: ((result: {finished:boolean}) => void) | undefined;
  const timing = jest.spyOn(Animated, 'timing').mockReturnValue({start: jest.fn((cb?: (r:{finished:boolean})=>void) => {completion=cb;}), stop:jest.fn(), reset:jest.fn()});
  const close=jest.fn();
  const ui=render(<VeilSheet c={palettes.OLED} reduceMotion={false} onClose={close}><Text>Content</Text></VeilSheet>);
  if(source==='back')fireEvent(ui.UNSAFE_getByType(Modal),'requestClose');
  else if(source==='outside')fireEvent.press(ui.getByTestId('veil-sheet-outside', {includeHiddenElements:true}));
  else if(source==='accessibility')fireEvent(ui.getByLabelText('Закрыть панель'),'accessibilityAction',{nativeEvent:{actionName:'dismiss'}});
  else fireEvent.press(ui.getByLabelText('Закрыть панель'));
  expect(timing).toHaveBeenCalledTimes(1);expect(close).not.toHaveBeenCalled();
  act(()=>completion?.({finished:true}));
  act(()=>completion?.({finished:true}));
  expect(close).toHaveBeenCalledTimes(1);
});
test('Reduce Motion short gesture cancellation does not run a decorative spring', () => {
  let pan: PanResponderCallbacks | undefined;
  jest.spyOn(PanResponder,'create').mockImplementation(config=>{pan=config;return{panHandlers:{}};});
  const spring=jest.spyOn(Animated,'spring'),close=jest.fn();
  const ui=render(<VeilSheet c={palettes.OLED} reduceMotion onClose={close}><Text>Content</Text></VeilSheet>);
  act(()=>pan?.onPanResponderRelease?.({} as never,{dy:20,vy:0} as never));
  act(()=>pan?.onPanResponderTerminate?.({} as never,{} as never));
  expect(spring).not.toHaveBeenCalled();expect(close).not.toHaveBeenCalled();
  expect(ui.UNSAFE_getByType(Modal).props.visible).toBe(true);
});
test('a programmatic close stays mounted until its exit; reopening rejects its stale completion', () => {
  const completions: ((r:{finished:boolean})=>void)[]=[];
  jest.spyOn(Animated,'timing').mockReturnValue({start:jest.fn((cb?: (r:{finished:boolean})=>void)=>{if(cb)completions.push(cb);}),stop:jest.fn(),reset:jest.fn()});
  const close=jest.fn(),content=(visible:boolean)=><VeilSheet visible={visible} c={palettes.OLED} reduceMotion={false} onClose={close}><Text>Content</Text></VeilSheet>;
  const ui=render(content(true));ui.rerender(content(false));
  expect(ui.UNSAFE_getByType(Modal).props.visible).toBe(true);
  ui.rerender(content(true));
  act(()=>completions[0]({finished:true}));
  expect(ui.UNSAFE_getByType(Modal).props.visible).toBe(true);expect(close).not.toHaveBeenCalled();
});
test('nested Back returns one level without dismissing the parent modal', () => {
  const back=jest.fn(),close=jest.fn();
  const ui=render(<VeilSheet c={palettes.OLED} reduceMotion onBack={back} onClose={close}><Text>Child</Text></VeilSheet>);
  fireEvent(ui.UNSAFE_getByType(Modal),'requestClose');
  expect(back).toHaveBeenCalledTimes(1);expect(close).not.toHaveBeenCalled();
});
test('reversing a long drag upwards cancels rather than completing dismissal', () => {
  let pan: PanResponderCallbacks | undefined;
  jest.spyOn(PanResponder,'create').mockImplementation(config=>{pan=config;return{panHandlers:{}};});
  const close=jest.fn(), spring=jest.spyOn(Animated,'spring');
  render(<VeilSheet c={palettes.OLED} reduceMotion onClose={close}><Text>Content</Text></VeilSheet>);
  act(()=>pan?.onPanResponderRelease?.({} as never,{dy:90,vy:-1} as never));
  expect(close).not.toHaveBeenCalled(); expect(spring).not.toHaveBeenCalled();
});
