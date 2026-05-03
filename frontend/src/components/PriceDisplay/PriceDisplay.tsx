import { CurrencyCode } from '../../types/contract';
import { formatCurrency } from '../../utils/formatters';

interface PriceDisplayProps {
  amount: number;
  currency?: CurrencyCode;
  additionalFees?: number;
  size?: 'small' | 'medium' | 'large';
}

const PriceDisplay = ({
  amount,
  currency = 'RUB',
  additionalFees = 0,
  size = 'medium',
}: PriceDisplayProps) => {
  const total = amount + additionalFees;

  return (
    <span className={`price-display ${size}`}>
      <strong>{formatCurrency(total, currency)}</strong>
      {additionalFees > 0 && <small>включая сборы</small>}
    </span>
  );
};

export { PriceDisplay };
export default PriceDisplay;
