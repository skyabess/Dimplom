import { TypedUseSelectorHook, useDispatch, useSelector } from 'react-redux';
import type { Dispatch, UnknownAction } from 'redux';

type AppDispatch = Dispatch<UnknownAction>;
type RootState = Record<string, unknown>;

export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;

export const showNotification = (message?: string) => {
  if (message) {
    console.info(message);
  }
};
