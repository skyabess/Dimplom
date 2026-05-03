import AssessmentIcon from '@mui/icons-material/Assessment';
import DescriptionIcon from '@mui/icons-material/Description';
import GppMaybeIcon from '@mui/icons-material/GppMaybe';
import TaskAltIcon from '@mui/icons-material/TaskAlt';
import { WorkspaceData } from '../../hooks/useWorkspaceData';
import { formatCurrency } from '../../utils/formatters';

interface MetricGridProps {
  metrics: WorkspaceData['metrics'];
}

const MetricGrid = ({ metrics }: MetricGridProps) => {
  const items = [
    {
      label: 'Договоры в работе',
      value: metrics.activeContracts,
      caption: `Всего договоров: ${metrics.totalContracts}`,
      icon: DescriptionIcon,
    },
    {
      label: 'Сумма сделок',
      value: formatCurrency(metrics.totalValue),
      caption: 'С учетом дополнительных сборов',
      icon: AssessmentIcon,
    },
    {
      label: 'Участки без проверки',
      value: metrics.unverifiedPlots,
      caption: 'Нужно запросить или подтвердить ЕГРН',
      icon: GppMaybeIcon,
    },
    {
      label: 'Открытые задачи',
      value: metrics.pendingTasks,
      caption: `${metrics.documentsOnReview} документа на проверке`,
      icon: TaskAltIcon,
    },
  ];

  return (
    <section className="metrics-grid" aria-label="Ключевые показатели">
      {items.map((item) => {
        const Icon = item.icon;

        return (
          <article className="metric-card" key={item.label}>
            <div className="metric-icon">
              <Icon fontSize="small" />
            </div>
            <span>{item.label}</span>
            <strong>{item.value}</strong>
            <small>{item.caption}</small>
          </article>
        );
      })}
    </section>
  );
};

export default MetricGrid;
