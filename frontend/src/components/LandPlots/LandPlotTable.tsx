import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import MapIcon from '@mui/icons-material/Map';
import { LandPlotSummary } from '../../types/contract';
import { formatArea } from '../../utils/formatters';

interface LandPlotTableProps {
  landPlots: LandPlotSummary[];
  title?: string;
  compact?: boolean;
  onCreate: () => void;
  onVerify: (id: string) => void;
}

const ownershipLabel: Record<LandPlotSummary['ownership_type'], string> = {
  state: 'Государственная',
  municipal: 'Муниципальная',
  private: 'Частная',
  shared: 'Долевая',
};

const LandPlotTable = ({
  landPlots,
  title = 'Земельные участки',
  compact = false,
  onCreate,
  onVerify,
}: LandPlotTableProps) => (
  <section className="panel">
    <div className="panel-header">
      <div>
        <h2>{title}</h2>
        <p>Кадастровые объекты, статусы проверки и назначение земли</p>
      </div>
      <button className="icon-text-button" onClick={onCreate} type="button">
        <MapIcon fontSize="small" />
        <span>Добавить</span>
      </button>
    </div>

    {landPlots.length > 0 ? (
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>Кадастр</th>
              <th>Регион</th>
              <th>Площадь</th>
              {!compact && <th>Назначение</th>}
              <th>Статус</th>
              <th aria-label="Действия" />
            </tr>
          </thead>
          <tbody>
            {landPlots.map((plot) => (
              <tr key={plot.id}>
                <td>
                  <strong>{plot.cadastral_number}</strong>
                  {!compact && <small>{plot.address}</small>}
                </td>
                <td>{plot.region_name}</td>
                <td>{formatArea(plot.area)}</td>
                {!compact && (
                  <td>
                    <span>{plot.purpose_name}</span>
                    <small>{ownershipLabel[plot.ownership_type]}</small>
                  </td>
                )}
                <td>
                  <span className={`status-pill ${plot.is_verified ? 'success' : 'warning'}`}>
                    {plot.is_verified ? 'Проверен' : 'Ожидает'}
                  </span>
                </td>
                <td>
                  <button
                    aria-label="Подтвердить участок"
                    className="icon-action"
                    disabled={plot.is_verified}
                    onClick={() => onVerify(plot.id)}
                    title="Подтвердить"
                    type="button"
                  >
                    <CheckCircleIcon fontSize="small" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : (
      <div className="empty-state">Участки не найдены</div>
    )}
  </section>
);

export default LandPlotTable;
