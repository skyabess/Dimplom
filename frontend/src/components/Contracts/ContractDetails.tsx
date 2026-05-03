import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import DescriptionIcon from '@mui/icons-material/Description';
import EditIcon from '@mui/icons-material/Edit';
import { Contract, DocumentItem } from '../../types/contract';
import { formatArea, formatCurrency, formatDate } from '../../utils/formatters';
import { documentStatusMeta } from '../../utils/status';
import StatusBadge from '../StatusBadge/StatusBadge';

interface ContractDetailsProps {
  contract?: Contract;
  documents: DocumentItem[];
  onEdit: (id: string) => void;
  onSign: (id: string) => void;
  onUploadDocument: (id: string) => void;
}

const ContractDetails = ({
  contract,
  documents,
  onEdit,
  onSign,
  onUploadDocument,
}: ContractDetailsProps) => {
  if (!contract) {
    return (
      <section className="panel side-panel">
        <div className="empty-state">Выберите договор, чтобы увидеть детали сделки</div>
      </section>
    );
  }

  const contractDocuments = documents.filter((document) => document.contractId === contract.id);
  const canSign = contract.status === 'pending_signature';

  return (
    <section className="panel side-panel">
      <div className="panel-header compact">
        <div>
          <h2>{contract.number}</h2>
          <p>{contract.title}</p>
        </div>
        <StatusBadge status={contract.status} />
      </div>

      <dl className="details-list">
        <div>
          <dt>Продавец</dt>
          <dd>{contract.seller.full_name}</dd>
        </div>
        <div>
          <dt>Покупатель</dt>
          <dd>{contract.buyer.full_name}</dd>
        </div>
        <div>
          <dt>Участок</dt>
          <dd>{contract.land_plot.cadastral_number}</dd>
        </div>
        <div>
          <dt>Адрес</dt>
          <dd>{contract.land_plot.address}</dd>
        </div>
        <div>
          <dt>Площадь</dt>
          <dd>{formatArea(contract.land_plot.area)}</dd>
        </div>
        <div>
          <dt>Сумма</dt>
          <dd>{formatCurrency(contract.total_amount, contract.currency)}</dd>
        </div>
        <div>
          <dt>Срок действия</dt>
          <dd>
            {formatDate(contract.start_date)} - {formatDate(contract.end_date)}
          </dd>
        </div>
      </dl>

      <div className="details-actions">
        <button className="icon-text-button" onClick={() => onEdit(contract.id)} type="button">
          <EditIcon fontSize="small" />
          <span>Редактировать</span>
        </button>
        <button
          className="icon-text-button"
          disabled={!canSign}
          onClick={() => onSign(contract.id)}
          type="button"
        >
          <CheckCircleIcon fontSize="small" />
          <span>Подписать</span>
        </button>
        <button className="icon-text-button" onClick={() => onUploadDocument(contract.id)} type="button">
          <DescriptionIcon fontSize="small" />
          <span>Документ</span>
        </button>
      </div>

      <div className="document-mini-list">
        <h3>Документы</h3>
        {contractDocuments.length > 0 ? (
          contractDocuments.map((document) => (
            <div className="document-mini-item" key={document.id}>
              <span>{document.title}</span>
              <small className={`status-pill ${documentStatusMeta[document.status].tone}`}>
                {documentStatusMeta[document.status].label}
              </small>
            </div>
          ))
        ) : (
          <div className="empty-state compact">Документы еще не загружены</div>
        )}
      </div>
    </section>
  );
};

export default ContractDetails;
