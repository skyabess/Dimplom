import { Chip } from '@mui/material';

interface StatusBadgeProps {
  status: string;
}

export const StatusBadge = ({ status }: StatusBadgeProps) => (
  <Chip label={status} color="primary" size="small" />
);