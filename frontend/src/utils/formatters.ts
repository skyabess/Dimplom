import { CurrencyCode } from '../types/contract';

const currencyFormatter = (currency: CurrencyCode) =>
  new Intl.NumberFormat('ru-RU', {
    style: 'currency',
    currency,
    maximumFractionDigits: 0,
  });

export const formatCurrency = (amount: number, currency: CurrencyCode = 'RUB') =>
  currencyFormatter(currency).format(Number.isFinite(amount) ? amount : 0);

export const formatNumber = (value: number) =>
  new Intl.NumberFormat('ru-RU').format(Number.isFinite(value) ? value : 0);

export const formatArea = (area: number) => {
  if (area >= 10000) {
    return `${formatNumber(Number((area / 10000).toFixed(2)))} га`;
  }

  return `${formatNumber(area)} м²`;
};

export const formatDate = (value?: string) => {
  if (!value) {
    return 'Не указана';
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return 'Не указана';
  }

  return new Intl.DateTimeFormat('ru-RU', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  }).format(date);
};

export const formatFileSize = (bytes: number) => {
  if (!bytes) {
    return '0 Б';
  }

  const units = ['Б', 'КБ', 'МБ', 'ГБ'];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** index;

  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`;
};

export const pluralRu = (count: number, one: string, few: string, many: string) => {
  const abs = Math.abs(count) % 100;
  const last = abs % 10;

  if (abs > 10 && abs < 20) {
    return many;
  }

  if (last > 1 && last < 5) {
    return few;
  }

  if (last === 1) {
    return one;
  }

  return many;
};
