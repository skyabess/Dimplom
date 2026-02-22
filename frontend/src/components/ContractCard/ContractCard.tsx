import React, { memo, useCallback, useMemo } from 'react';
import {
  Card,
  CardContent,
  CardActions,
  Typography,
  Box,
  Chip,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Edit as EditIcon,
  Visibility as ViewIcon,
  Delete as DeleteIcon,
  Signatures as SignIcon,
  Description as DocumentIcon,
} from '@mui/icons-material';
import { format } from 'date-fns';
import { ru } from 'date-fns/locale';

import { Contract } from '../../types/contract';
import { useAppDispatch } from '../../hooks/redux';
import { showNotification } from '../../store/slices/uiSlice';
import PriceDisplay from '../PriceDisplay/PriceDisplay';
import StatusBadge from '../StatusBadge/StatusBadge';

interface ContractCardProps {
  contract: Contract;
  onView: (id: string) => void;
  onEdit: (id: string) => void;
  onDelete: (id: string) => void;
  onSign: (id: string) => void;
  onDocumentView: (id: string) => void;
  actions?: ('view' | 'edit' | 'delete' | 'sign' | 'document')[];
  compact?: boolean;
}

const ContractCard: React.FC<ContractCardProps> = ({
  contract,
  onView,
  onEdit,
  onDelete,
  onSign,
  onDocumentView,
  actions = ['view', 'edit', 'delete', 'sign', 'document'],
  compact = false,
}) => {
  const dispatch = useAppDispatch();

  // Memoized handlers to prevent unnecessary re-renders
  const handleView = useCallback(() => {
    onView(contract.id);
  }, [contract.id, onView]);

  const handleEdit = useCallback(() => {
    onEdit(contract.id);
  }, [contract.id, onEdit]);

  const handleDelete = useCallback(() => {
    dispatch(showNotification({
      type: 'warning',
      message: 'Вы уверены, что хотите удалить договор?',
      action: {
        label: 'Удалить',
        callback: () => onDelete(contract.id),
      },
    }));
  }, [contract.id, onDelete, dispatch]);

  const handleSign = useCallback(() => {
    onSign(contract.id);
  }, [contract.id, onSign]);

  const handleDocumentView = useCallback(() => {
    onDocumentView(contract.id);
  }, [contract.id, onDocumentView]);

  // Memoized formatted values
  const formattedPrice = useMemo(() => {
    return {
      amount: contract.price,
      currency: contract.currency,
    };
  }, [contract.price, contract.currency]);

  const formattedDate = useMemo(() => {
    return format(new Date(contract.created_at), 'dd MMMM yyyy', { locale: ru });
  }, [contract.created_at]);

  const canSign = useMemo(() => {
    return contract.status === 'pending_signature';
  }, [contract.status]);

  const canEdit = useMemo(() => {
    return contract.status === 'draft';
  }, [contract.status]);

  const canDelete = useMemo(() => {
    return ['draft', 'cancelled'].includes(contract.status);
  }, [contract.status]);

  return (
    <Card
      sx={{
        height: compact ? 'auto' : '100%',
        display: 'flex',
        flexDirection: 'column',
        transition: 'all 0.3s ease',
        '&:hover': {
          transform: 'translateY(-2px)',
          boxShadow: 4,
        },
      }}
    >
      <CardContent sx={{ flexGrow: 1, pb: 1 }}>
        {/* Header with title and status */}
        <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={2}>
          <Typography variant="h6" component="h2" noWrap>
            {contract.title}
          </Typography>
          <StatusBadge status={contract.status} />
        </Box>

        {/* Contract details */}
        {!compact && (
          <Box mb={2}>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              {contract.description}
            </Typography>
          </Box>
        )}

        {/* Land plot information */}
        <Box mb={2}>
          <Typography variant="body2" color="text.secondary">
            Кадастровый номер: {contract.land_plot?.cadastral_number || 'Не указан'}
          </Typography>
          {contract.land_plot?.area && (
            <Typography variant="body2" color="text.secondary">
              Площадь: {contract.land_plot.area} га
            </Typography>
          )}
          {contract.land_plot?.address && (
            <Typography variant="body2" color="text.secondary">
              Адрес: {contract.land_plot.address}
            </Typography>
          )}
        </Box>

        {/* Parties information */}
        <Box mb={2}>
          <Typography variant="body2" color="text.secondary">
            Продавец: {contract.seller?.full_name || 'Не указан'}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Покупатель: {contract.buyer?.full_name || 'Не указан'}
          </Typography>
        </Box>

        {/* Financial information */}
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <PriceDisplay price={formattedPrice} size={compact ? 'small' : 'medium'} />
          <Typography variant="caption" color="text.secondary">
            {formattedDate}
          </Typography>
        </Box>

        {/* Tags and additional info */}
        {contract.tags && contract.tags.length > 0 && (
          <Box mb={2}>
            {contract.tags.map((tag, index) => (
              <Chip
                key={index}
                label={tag}
                size="small"
                variant="outlined"
                sx={{ mr: 0.5, mb: 0.5 }}
              />
            ))}
          </Box>
        )}
      </CardContent>

      {/* Actions */}
      <CardActions sx={{ justifyContent: 'flex', pt: 0 }}>
        {actions.includes('view') && (
          <Tooltip title="Просмотр">
            <IconButton onClick={handleView} size="small">
              <ViewIcon />
            </IconButton>
          </Tooltip>
        )}

        {actions.includes('document') && (
          <Tooltip title="Документы">
            <IconButton onClick={handleDocumentView} size="small">
              <DocumentIcon />
            </IconButton>
          </Tooltip>
        )}

        {actions.includes('edit') && canEdit && (
          <Tooltip title="Редактировать">
            <IconButton onClick={handleEdit} size="small" color="primary">
              <EditIcon />
            </IconButton>
          </Tooltip>
        )}

        {actions.includes('sign') && canSign && (
          <Tooltip title="Подписать">
            <IconButton onClick={handleSign} size="small" color="success">
              <SignIcon />
            </IconButton>
          </Tooltip>
        )}

        {actions.includes('delete') && canDelete && (
          <Tooltip title="Удалить">
            <IconButton onClick={handleDelete} size="small" color="error">
              <DeleteIcon />
            </IconButton>
          </Tooltip>
        )}
      </CardActions>
    </Card>
  );
};

export default memo(ContractCard);