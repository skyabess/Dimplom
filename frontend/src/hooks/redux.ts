import { useDispatch, useSelector } from 'react-redux';

export const useAppDispatch: any = () => useDispatch();
export const useAppSelector: any = useSelector;
export const showNotification = () => {};