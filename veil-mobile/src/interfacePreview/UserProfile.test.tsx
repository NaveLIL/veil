import React from 'react';
import { fireEvent, render } from '@testing-library/react-native';
import { expect, jest, test } from '@jest/globals';
import { Text } from 'react-native';
import { ProfilePanel } from './UserProfile';
import { palettes } from './appearance';

function profile() {
  const changed=jest.fn();
  const props={open:true,onClose:jest.fn(),c:palettes.OLED,reduceMotion:true,
    profile:{name:'Original',bio:'Original bio'},onProfileChange:changed,
    appearance:<Text>Appearance</Text>,onLock:jest.fn(),onAbout:jest.fn(),onScenarios:jest.fn()};
  return{changed,props,ui:render(<ProfilePanel {...props}/>)};
}
test('demo profile input remains a draft and Cancel discards it',()=>{
  const{changed,ui}=profile();
  fireEvent.press(ui.getByLabelText('Редактировать демо-профиль'));
  fireEvent.changeText(ui.getByLabelText('Имя демо-профиля'),'Changed');
  expect(changed).not.toHaveBeenCalled();
  fireEvent.press(ui.getByLabelText('Отмена'));
  expect(ui.getByText('Original')).toBeTruthy();expect(changed).not.toHaveBeenCalled();
  fireEvent.press(ui.getByLabelText('Редактировать демо-профиль'));
  expect(ui.getByLabelText('Имя демо-профиля').props.value).toBe('Original');
});
test('demo Save commits both fields once and keeps its local-only ownership visible',()=>{
  const{changed,ui}=profile();
  fireEvent.press(ui.getByLabelText('Редактировать демо-профиль'));
  fireEvent.changeText(ui.getByLabelText('Имя демо-профиля'),'Changed');
  fireEvent.changeText(ui.getByLabelText('Описание демо-профиля'),'New bio');
  fireEvent.press(ui.getByLabelText('Готово'));
  expect(changed).toHaveBeenCalledTimes(1);expect(changed).toHaveBeenCalledWith({name:'Changed',bio:'New bio'});
  expect(ui.getByText(/без публикации на/)).toBeTruthy();
});
test('an external panel close discards an unfinished edit before reopening', () => {
  const { changed, props, ui } = profile();
  fireEvent.press(ui.getByLabelText('Редактировать демо-профиль'));
  fireEvent.changeText(ui.getByLabelText('Имя демо-профиля'), 'Unfinished');
  ui.rerender(<ProfilePanel {...props} open={false} />);
  ui.rerender(<ProfilePanel {...props} />);
  expect(ui.queryByLabelText('Имя демо-профиля')).toBeNull();
  fireEvent.press(ui.getByLabelText('Редактировать демо-профиль'));
  expect(ui.getByLabelText('Имя демо-профиля').props.value).toBe('Original');
  expect(changed).not.toHaveBeenCalled();
});
