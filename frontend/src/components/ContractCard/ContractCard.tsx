import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import DeleteIcon from '@mui/icons-material/Delete';
import DescriptionIcon from '@mui/icons-material/Description';
import EditIcon from '@mui/icons-material/Edit';
import VisibilityIcon from '@mui/icons-material/Visibility';
import { memo } from 'react';
import { Contract } from '../../types/contract';
import { formatArea, formatDate } from '../../utils/formatters';
import PriceDisplay from '../PriceDisplay/PriceDisplay';
import StatusBadge from '../StatusBadge/StatusBadge';

interface ContractCardProps {
  contract: Contract;
  compact?: boolean;
  onView: (id: string) => void;
  onEdit: (id: string) => void;
  onDelete: (id: string) => void;
  onSign: (id: string) => void;
  onDocumentView: (id: string) => void;
}

const ContractCard = ({
  contract,
  compact = false,
  onView,
  onEdit,
  onDelete,
  onSign,
  onDocumentView,
}: ContractCardProps) => {
  const canSign = contract.status === 'pending_signature';
  const canEdit = ['draft', 'pending_approval'].includes(contract.status);
  const canDelete = ['draft', 'cancelled'].includes(contract.status);

  return (
    <article className={`contract-card ${compact ? 'compact' : ''}`}>
      <header className="contract-card-header">
        <div>
          <span className="contract-number">{contract.number}</span>
          <h3>{contract.title}</h3>
        </div>
        <StatusBadge status={contract.status} />
      </header>

      {!compact && <p className="contract-description">{contract.description}</p>}

      <dl className="contract-facts">
        <div>
          <dt>Участок</dt>
          <dd>{contract.land_plot.cadastral_number}</dd>
        </div>
        <div>
          <dt>Площадь</dt>
          <dd>{formatArea(contract.land_plot.area)}</dd>
        </div>
        <div>
          <dt>Покупатель</dt>
          <dd>{contract.buyer.full_name}</dd>
        </div>
        <div>
          <dt>Срок</dt>
          <dd>{formatDate(contract.end_date)}</dd>
        </div>
      </dl>

      <div className="progress-line" aria-label={`Готовность ${contract.progress}%`}>
        <span style={{ width: `${contract.progress}%` }} />
      </div>

      <footer className="contract-card-footer">
        <PriceDisplay
          additionalFees={contract.additional_fees}
          amount={contract.price}
          currency={contract.currency}
          size={compact ? 'small' : 'medium'}
        />

        <div className="row-actions">
          <button
            aria-label="Открыть договор"
            className="icon-action"
            onClick={() => onView(contract.id)}
            title="Открыть"
            type="button"
          >
            <VisibilityIcon fontSize="small" />
          </button>
          <button
            aria-label="Документы договора"
            className="icon-action"
            onClick={() => onDocumentView(contract.id)}
            title="Документы"
            type="button"
          >
            <DescriptionIcon fontSize="small" />
          </button>
          <button
            aria-label="Редактировать договор"
            className="icon-action"
            disabled={!canEdit}
            onClick={() => onEdit(contract.id)}
            title="Редактировать"
            type="button"
          >
            <EditIcon fontSize="small" />
          </button>
          <button
            aria-label="Подписать договор"
            className="icon-action success"
            disabled={!canSign}
            onClick={() => onSign(contract.id)}
            title="Подписать"
            type="button"
          >
            <CheckCircleIcon fontSize="small" />
          </button>
          <button
            aria-label="Удалить договор"
            className="icon-action danger"
            disabled={!canDelete}
            onClick={() => onDelete(contract.id)}
            title="Удалить"
            type="button"
          >
            <DeleteIcon fontSize="small" />
          </button>
        </div>
      </footer>
    </article>
  );
};

export default memo(ContractCard);
