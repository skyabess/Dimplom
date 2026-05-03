import AddIcon from '@mui/icons-material/Add';
import AssessmentIcon from '@mui/icons-material/Assessment';
import ContentPasteSearchIcon from '@mui/icons-material/ContentPasteSearch';
import DashboardIcon from '@mui/icons-material/Dashboard';
import DescriptionIcon from '@mui/icons-material/Description';
import MapIcon from '@mui/icons-material/Map';
import SearchIcon from '@mui/icons-material/Search';
import UploadFileIcon from '@mui/icons-material/UploadFile';
import { ReactNode } from 'react';
import { ApiState } from '../../types/contract';

export type WorkspaceView = 'overview' | 'contracts' | 'plots' | 'documents' | 'reports';

interface AppLayoutProps {
  children: ReactNode;
  activeView: WorkspaceView;
  query: string;
  apiState: ApiState;
  pendingActions: number;
  onViewChange: (view: WorkspaceView) => void;
  onQueryChange: (value: string) => void;
  onNewContract: () => void;
  onImportLandPlot: () => void;
  onUploadDocument: () => void;
}

const navItems: Array<{
  view: WorkspaceView;
  label: string;
  icon: typeof DashboardIcon;
}> = [
  { view: 'overview', label: 'Обзор', icon: DashboardIcon },
  { view: 'contracts', label: 'Договоры', icon: ContentPasteSearchIcon },
  { view: 'plots', label: 'Участки', icon: MapIcon },
  { view: 'documents', label: 'Документы', icon: DescriptionIcon },
  { view: 'reports', label: 'Отчеты', icon: AssessmentIcon },
];

const apiTone = {
  checking: 'info',
  connected: 'success',
  offline: 'warning',
};

const AppLayout = ({
  children,
  activeView,
  query,
  apiState,
  pendingActions,
  onViewChange,
  onQueryChange,
  onNewContract,
  onImportLandPlot,
  onUploadDocument,
}: AppLayoutProps) => (
  <div className="app-shell">
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">LC</div>
        <div>
          <strong>Land Contracts</strong>
          <span>кабинет сделок</span>
        </div>
      </div>

      <nav className="nav-list" aria-label="Главная навигация">
        {navItems.map((item) => {
          const Icon = item.icon;

          return (
            <button
              className={`nav-item ${activeView === item.view ? 'active' : ''}`}
              key={item.view}
              onClick={() => onViewChange(item.view)}
              type="button"
            >
              <Icon fontSize="small" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="sidebar-note">
        <span>Сегодня</span>
        <strong>
          {pendingActions} {pendingActions === 1 ? 'действие требует' : 'действий требуют'} внимания
        </strong>
      </div>
    </aside>

    <main className="workspace">
      <header className="topbar">
        <div>
          <p className="eyebrow">Система управления земельными контрактами</p>
          <h1>Рабочий стол сделок</h1>
        </div>

        <div className="topbar-actions">
          <label className="search-control">
            <SearchIcon fontSize="small" />
            <input
              aria-label="Поиск"
              onChange={(event) => onQueryChange(event.target.value)}
              placeholder="Поиск"
              value={query}
            />
          </label>
          <button className="icon-text-button" onClick={onImportLandPlot} type="button">
            <MapIcon fontSize="small" />
            <span>ЕГРН</span>
          </button>
          <button className="icon-text-button" onClick={onUploadDocument} type="button">
            <UploadFileIcon fontSize="small" />
            <span>Документ</span>
          </button>
          <button className="primary-button" onClick={onNewContract} type="button">
            <AddIcon fontSize="small" />
            <span>Договор</span>
          </button>
        </div>
      </header>

      <div className={`api-banner ${apiTone[apiState.status]}`}>
        <span className="api-dot" />
        <span>{apiState.message}</span>
      </div>

      {children}
    </main>
  </div>
);

export default AppLayout;
