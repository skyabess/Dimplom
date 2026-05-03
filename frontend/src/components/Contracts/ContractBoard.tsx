import { Contract } from '../../types/contract';
import ContractCard from '../ContractCard/ContractCard';

interface ContractBoardProps {
  contracts: Contract[];
  title?: string;
  compact?: boolean;
  emptyText?: string;
  onView: (id: string) => void;
  onEdit: (id: string) => void;
  onDelete: (id: string) => void;
  onSign: (id: string) => void;
  onDocumentView: (id: string) => void;
}

const ContractBoard = ({
  contracts,
  title = 'Договоры',
  compact = false,
  emptyText = 'Договоры не найдены',
  onView,
  onEdit,
  onDelete,
  onSign,
  onDocumentView,
}: ContractBoardProps) => (
  <section className="panel contracts-panel">
    <div className="panel-header">
      <div>
        <h2>{title}</h2>
        <p>Статусы, суммы, участки и ближайшие действия по сделкам</p>
      </div>
    </div>

    {contracts.length > 0 ? (
      <div className={`contract-grid ${compact ? 'compact' : ''}`}>
        {contracts.map((contract) => (
          <ContractCard
            compact={compact}
            contract={contract}
            key={contract.id}
            onDelete={onDelete}
            onDocumentView={onDocumentView}
            onEdit={onEdit}
            onSign={onSign}
            onView={onView}
          />
        ))}
      </div>
    ) : (
      <div className="empty-state">{emptyText}</div>
    )}
  </section>
);

export default ContractBoard;
