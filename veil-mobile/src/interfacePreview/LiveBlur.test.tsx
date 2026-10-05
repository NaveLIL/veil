import React from 'react';
import { test, expect } from '@jest/globals';
import { Text } from 'react-native';
import { act, render } from '@testing-library/react-native';
import { ModalBlurBoundary, useModalBackdrop } from './LiveBlur';
import { motion } from './appearance';

function Owner({ active, name, engaged = active, reduceMotion = false }: {active:boolean;name:string;engaged?:boolean;reduceMotion?:boolean}) {
  const radius = useModalBackdrop(active, engaged, reduceMotion);
  return <Text testID={name}>{radius}</Text>;
}
test('nested windows retain live underlay blur until the final owner closes', () => {
  const tree = (a:boolean,b:boolean) => <ModalBlurBoundary><Owner active={a} name="a" /><Owner active={b} name="b" /></ModalBlurBoundary>;
  const ui=render(tree(true,false));
  expect(ui.getByTestId('modal-blur-background').props.blurRadius).toBe(12);
  act(() => ui.rerender(tree(true,true)));
  expect(ui.getByTestId('a').props.children).toBe(12);
  expect(ui.getByTestId('b').props.children).toBe(0);
  act(() => ui.rerender(tree(true,false)));
  expect(ui.getByTestId('a').props.children).toBe(0);
  expect(ui.getByTestId('modal-blur-background').props.blurRadius).toBe(12);
  act(() => ui.rerender(tree(false,false)));
  expect(ui.getByTestId('modal-blur-background').props.blurRadius).toBe(0);
});
test('closing the top sheet clears only its lower underlay, not a still-open root owner', () => {
  const tree=(engaged:boolean)=><ModalBlurBoundary><Owner active name="a" /><Owner active engaged={engaged} name="b" /></ModalBlurBoundary>;
  const ui=render(tree(true));
  expect(ui.getByTestId('a').props.children).toBe(12);
  ui.rerender(tree(false));
  expect(ui.getByTestId('a').props.children).toBe(0);
  expect(ui.getByTestId('b').props.children).toBe(0);
  expect(ui.getByTestId('modal-blur-background').props.blurRadius).toBe(12);
  ui.rerender(tree(true));
  expect(ui.getByTestId('a').props.children).toBe(12);
  expect(ui.getByTestId('b').props.children).toBe(0);
});
test('Reduce Motion skips native blur interpolation even while the owner exits', () => {
  const tree=(engaged:boolean,reduceMotion:boolean)=><ModalBlurBoundary><Owner active engaged={engaged} reduceMotion={reduceMotion} name="a" /></ModalBlurBoundary>;
  const ui=render(tree(true,false));
  expect(ui.getByTestId('modal-blur-background').props.blurTransitionMs).toBe(motion.transitionDuration);
  ui.rerender(tree(true,true));
  expect(ui.getByTestId('modal-blur-background').props.blurTransitionMs).toBe(0);
  ui.rerender(tree(false,true));
  expect(ui.getByTestId('modal-blur-background').props.blurRadius).toBe(0);
  expect(ui.getByTestId('modal-blur-background').props.blurTransitionMs).toBe(0);
});
test('immediately unmounting the final Reduce Motion owner does not animate its unblur', () => {
  const tree=(open:boolean)=><ModalBlurBoundary>{open && <Owner active reduceMotion name="a" />}</ModalBlurBoundary>;
  const ui=render(tree(true));
  expect(ui.getByTestId('modal-blur-background').props.blurRadius).toBe(12);
  ui.rerender(tree(false));
  expect(ui.getByTestId('modal-blur-background').props.blurRadius).toBe(0);
  expect(ui.getByTestId('modal-blur-background').props.blurTransitionMs).toBe(0);
  ui.rerender(<ModalBlurBoundary><Owner active name="a" /></ModalBlurBoundary>);
  expect(ui.getByTestId('modal-blur-background').props.blurTransitionMs).toBe(motion.transitionDuration);
});
