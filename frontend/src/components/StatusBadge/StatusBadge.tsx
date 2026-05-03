import { ContractStatus } from '../../types/contract';
import { contractStatusMeta } from '../../utils/status';

interface StatusBadgeProps {
  status: ContractStatus;
}

const StatusBadge = ({ status }: StatusBadgeProps) => {
  const meta = contractStatusMeta[status] || contractStatusMeta.draft;

  return <span className={`status-pill ${meta.tone}`}>{meta.label}</span>;
};

export { StatusBadge };
export default StatusBadge;
