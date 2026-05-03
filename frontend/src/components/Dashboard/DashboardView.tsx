import { WorkspaceData } from '../../hooks/useWorkspaceData';
import { WorkspaceView } from '../Layout/AppLayout';
import ContractBoard from '../Contracts/ContractBoard';
import ContractDetails from '../Contracts/ContractDetails';
import DocumentPanel from '../Documents/DocumentPanel';
import LandPlotTable from '../LandPlots/LandPlotTable';
import ReportPanel from '../Reports/ReportPanel';
import TaskPanel from '../Tasks/TaskPanel';
import MetricGrid from './MetricGrid';

interface DashboardViewProps {
  view: WorkspaceView;
  workspace: WorkspaceData;
  selectedContractId?: string;
  contracts: WorkspaceData['contracts'];
  landPlots: WorkspaceData['landPlots'];
  documents: WorkspaceData['documents'];
  tasks: WorkspaceData['tasks'];
  onSelectContract: (id: string) => void;
  onEditContract: (id: string) => void;
  onDeleteContract: (id: string) => void;
  onSignContract: (id: string) => void;
  onOpenDocumentForm: (contractId?: string) => void;
  onOpenLandPlotForm: () => void;
}

const DashboardView = ({
  view,
  workspace,
  selectedContractId,
  contracts,
  landPlots,
  documents,
  tasks,
  onSelectContract,
  onEditContract,
  onDeleteContract,
  onSignContract,
  onOpenDocumentForm,
  onOpenLandPlotForm,
}: DashboardViewProps) => {
  const selectedContract =
    contracts.find((contract) => contract.id === selectedContractId) || contracts[0];

  if (view === 'contracts') {
    return (
      <section className="content-grid detail-layout">
        <ContractBoard
          contracts={contracts}
          onDelete={onDeleteContract}
          onDocumentView={onOpenDocumentForm}
          onEdit={onEditContract}
          onSign={onSignContract}
          onView={onSelectContract}
          title="Все договоры"
        />
        <ContractDetails
          contract={selectedContract}
          documents={documents}
          onEdit={onEditContract}
          onSign={onSignContract}
          onUploadDocument={onOpenDocumentForm}
        />
      </section>
    );
  }

  if (view === 'plots') {
    return (
      <LandPlotTable
        landPlots={landPlots}
        onCreate={onOpenLandPlotForm}
        onVerify={workspace.verifyLandPlot}
        title="Кадастровые участки"
      />
    );
  }

  if (view === 'documents') {
    return (
      <DocumentPanel
        contracts={workspace.contracts}
        documents={documents}
        onApprove={workspace.approveDocument}
        onUpload={() => onOpenDocumentForm()}
      />
    );
  }

  if (view === 'reports') {
    return (
      <ReportPanel
        contracts={contracts}
        documents={documents}
        landPlots={landPlots}
        tasks={tasks}
      />
    );
  }

  return (
    <>
      <MetricGrid metrics={workspace.metrics} />
      <section className="content-grid">
        <ContractBoard
          compact
          contracts={contracts.slice(0, 4)}
          onDelete={onDeleteContract}
          onDocumentView={onOpenDocumentForm}
          onEdit={onEditContract}
          onSign={onSignContract}
          onView={onSelectContract}
          title="Последние договоры"
        />
        <TaskPanel
          contracts={workspace.contracts}
          onAddTask={workspace.addTask}
          onToggleTask={workspace.toggleTask}
          tasks={tasks.slice(0, 5)}
        />
        <LandPlotTable
          compact
          landPlots={landPlots.slice(0, 5)}
          onCreate={onOpenLandPlotForm}
          onVerify={workspace.verifyLandPlot}
          title="Участки в работе"
        />
        <DocumentPanel
          contracts={workspace.contracts}
          documents={documents.slice(0, 4)}
          onApprove={workspace.approveDocument}
          onUpload={() => onOpenDocumentForm()}
        />
      </section>
    </>
  );
};

export default DashboardView;
