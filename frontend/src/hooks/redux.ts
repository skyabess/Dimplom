import { useDispatch, useSelector, TypedUseSelectorHook } from 'react-redux';

export const useAppDispatch = () => useDispatch();
export const useAppSelector: TypedUseSelectorHook<any> = useSelector;