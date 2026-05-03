import { ContractStatus, DocumentItem, TaskPriority } from '../types/contract';

export const contractStatusMeta: Record<
  ContractStatus,
  { label: string; tone: 'neutral' | 'info' | 'warning' | 'success' | 'danger'; progress: number }
> = {
  draft: { label: 'Черновик', tone: 'neutral', progress: 15 },
  pending_approval: { label: 'На согласовании', tone: 'info', progress: 45 },
  pending_signature: { label: 'На подписании', tone: 'warning', progress: 72 },
  signed: { label: 'Подписан', tone: 'success', progress: 84 },
  active: { label: 'Активен', tone: 'success', progress: 91 },
  completed: { label: 'Завершен', tone: 'success', progress: 100 },
  cancelled: { label: 'Отменен', tone: 'danger', progress: 0 },
  terminated: { label: 'Расторгнут', tone: 'danger', progress: 0 },
};

export const priorityMeta: Record<TaskPriority, { label: string; tone: string }> = {
  low: { label: 'Низкий', tone: 'neutral' },
  medium: { label: 'Средний', tone: 'info' },
  high: { label: 'Высокий', tone: 'danger' },
};

export const documentStatusMeta: Record<DocumentItem['status'], { label: string; tone: string }> = {
  uploaded: { label: 'Загружен', tone: 'neutral' },
  review: { label: 'На проверке', tone: 'warning' },
  approved: { label: 'Принят', tone: 'success' },
};

export const documentTypeLabel: Record<DocumentItem['documentType'], string> = {
  contract: 'Договор',
  egrn: 'ЕГРН',
  payment: 'Оплата',
  identity: 'Личность',
  other: 'Другое',
};
