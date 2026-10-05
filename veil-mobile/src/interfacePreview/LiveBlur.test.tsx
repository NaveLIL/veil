import React from 'react';
import { test, expect } from '@jest/globals';
import { Text } from 'react-native';
import { act, render } from '@testing-library/react-native';
import { ModalBlurBoundary, useModalBackdrop } from './LiveBlur';

function Owner({ active, name }: {active:boolean;name:string}) {
  const radius = useModalBackdrop(active);
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
