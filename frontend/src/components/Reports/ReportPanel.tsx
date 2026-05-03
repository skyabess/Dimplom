import DownloadIcon from '@mui/icons-material/Download';
import { Contract, DocumentItem, LandPlotSummary, TaskItem } from '../../types/contract';
import { formatCurrency, formatDate } from '../../utils/formatters';
import { contractStatusMeta } from '../../utils/status';

interface ReportPanelProps {
  contracts: Contract[];
  landPlots: LandPlotSummary[];
  tasks: TaskItem[];
  documents: DocumentItem[];
}

const buildCsv = (
  contracts: Contract[],
  landPlots: LandPlotSummary[],
  tasks: TaskItem[],
  documents: DocumentItem[],
) => {
  const rows = [
    ['Показатель', 'Значение'],
    ['Договоров', String(contracts.length)],
    ['Участков', String(landPlots.length)],
    ['Открытых задач', String(tasks.filter((task) => !task.completed).length)],
    ['Документов на проверке', String(documents.filter((doc) => doc.status === 'review').length)],
    [],
    ['Номер', 'Название', 'Статус', 'Сумма', 'Кадастровый номер'],
    ...contracts.map((contract) => [
      contract.number,
      contract.title,
      contractStatusMeta[contract.status].label,
      String(contract.total_amount),
      contract.land_plot.cadastral_number,
    ]),
  ];

  return rows
    .map((row) => row.map((cell) => `"${String(cell ?? '').replace(/"/g, '""')}"`).join(';'))
    .join('\n');
};

const downloadReport = (
  contracts: Contract[],
  landPlots: LandPlotSummary[],
  tasks: TaskItem[],
  documents: DocumentItem[],
) => {
  const blob = new Blob([buildCsv(contracts, landPlots, tasks, documents)], {
    type: 'text/csv;charset=utf-8',
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `land-contracts-report-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
};

const ReportPanel = ({ contracts, landPlots, tasks, documents }: ReportPanelProps) => {
  const totalValue = contracts.reduce((sum, contract) => sum + contract.total_amount, 0);
  const averageProgress =
    contracts.length > 0
      ? Math.round(contracts.reduce((sum, contract) => sum + contract.progress, 0) / contracts.length)
      : 0;
  const nextTasks = tasks
    .filter((task) => !task.completed)
    .sort((a, b) => new Date(a.dueDate).getTime() - new Date(b.dueDate).getTime())
    .slice(0, 4);

  return (
    <section className="panel reports-panel">
      <div className="panel-header">
        <div>
          <h2>Отчет по сделкам</h2>
          <p>Сводка по договорам, участкам, документам и открытым задачам</p>
        </div>
        <button
          className="icon-text-button"
          onClick={() => downloadReport(contracts, landPlots, tasks, documents)}
          type="button"
        >
          <DownloadIcon fontSize="small" />
          <span>CSV</span>
        </button>
      </div>

      <div className="report-grid">
        <article>
          <span>Общий портфель</span>
          <strong>{formatCurrency(totalValue)}</strong>
        </article>
        <article>
          <span>Средняя готовность</span>
          <strong>{averageProgress}%</strong>
        </article>
        <article>
          <span>Проверено участков</span>
          <strong>{landPlots.filter((plot) => plot.is_verified).length}</strong>
        </article>
        <article>
          <span>Документов принято</span>
          <strong>{documents.filter((doc) => doc.status === 'approved').length}</strong>
        </article>
      </div>

      <div className="report-columns">
        <div>
          <h3>Статусы договоров</h3>
          <div className="status-breakdown">
            {Object.entries(contractStatusMeta).map(([status, meta]) => {
              const count = contracts.filter((contract) => contract.status === status).length;

              if (!count) {
                return null;
              }

              return (
                <div key={status}>
                  <span className={`status-pill ${meta.tone}`}>{meta.label}</span>
                  <strong>{count}</strong>
                </div>
              );
            })}
          </div>
        </div>

        <div>
          <h3>Ближайшие задачи</h3>
          <div className="report-task-list">
            {nextTasks.length > 0 ? (
              nextTasks.map((task) => (
                <div key={task.id}>
                  <span>{task.title}</span>
                  <small>{formatDate(task.dueDate)}</small>
                </div>
              ))
            ) : (
              <div className="empty-state compact">Открытых задач нет</div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
};

export default ReportPanel;
