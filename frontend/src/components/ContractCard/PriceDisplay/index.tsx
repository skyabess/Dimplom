import { Typography } from '@mui/material';

interface PriceDisplayProps {
  price: number;
}

export const PriceDisplay = ({ price }: PriceDisplayProps) => (
  <Typography variant="h6">₽{price.toLocaleString()}</Typography>
);