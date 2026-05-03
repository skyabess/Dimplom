import { useMemo, useState } from 'react';
import '../App.css';
import DashboardView from '../components/Dashboard/DashboardView';
import ContractForm from '../components/Forms/ContractForm';
import DocumentForm from '../components/Forms/DocumentForm';
import LandPlotForm from '../components/Forms/LandPlotForm';
import AppLayout, { WorkspaceView } from '../components/Layout/AppLayout';
import Modal from '../components/Modal/Modal';
import { useWorkspaceData } from '../hooks/useWorkspaceData';
import { Contract } from '../types/contract';

type ModalState =
  | { type: 'contract'; contract?: Contract }
  | { type: 'plot' }
  | { type: 'document'; contractId?: string }
  | null;

const matches = (value: string, query: string) =>
  value.toLocaleLowerCase('ru-RU').includes(query.toLocaleLowerCase('ru-RU'));

const DashboardApp = () => {
  const workspace = useWorkspaceData();
  const [activeView, setActiveView] = useState<WorkspaceView>('overview');
  const [query, setQuery] = useState('');
  const [selectedContractId, setSelectedContractId] = useState<string | undefined>(
    workspace.contracts[0]?.id,
  );
  const [modal, setModal] = useState<ModalState>(null);

  const normalizedQuery = query.trim();

  const filteredContracts = useMemo(() => {
    if (!normalizedQuery) {
      return workspace.contracts;
    }

    return workspace.contracts.filter((contract) =>
      [
        contract.number,
        contract.title,
        contract.buyer.full_name,
        contract.seller.full_name,
        contract.land_plot.cadastral_number,
      ].some((value) => matches(value, normalizedQuery)),
    );
  }, [normalizedQuery, workspace.contracts]);

  const filteredLandPlots = useMemo(() => {
    if (!normalizedQuery) {
      return workspace.landPlots;
    }

    return workspace.landPlots.filter((plot) =>
      [plot.cadastral_number, plot.region_name, plot.address, plot.purpose_name].some((value) =>
        matches(value, normalizedQuery),
      ),
    );
  }, [normalizedQuery, workspace.landPlots]);

  const filteredDocuments = useMemo(() => {
    if (!normalizedQuery) {
      return workspace.documents;
    }

    return workspace.documents.filter((document) =>
      [document.title, document.fileName].some((value) => matches(value, normalizedQuery)),
    );
  }, [normalizedQuery, workspace.documents]);

  const filteredTasks = useMemo(() => {
    if (!normalizedQuery) {
      return workspace.tasks;
    }

    return workspace.tasks.filter((task) => matches(task.title, normalizedQuery));
  }, [normalizedQuery, workspace.tasks]);

  const selectedContract =
    workspace.contracts.find((contract) => contract.id === selectedContractId) ||
    workspace.contracts[0];

  const closeModal = () => setModal(null);

  const handleSelectContract = (id: string) => {
    setSelectedContractId(id);
    setActiveView('contracts');
  };

  const handleEditContract = (id: string) => {
    const contract = workspace.contracts.find((item) => item.id === id);
    if (contract) {
      setModal({ type: 'contract', contract });
    }
  };

  return (
    <AppLayout
      activeView={activeView}
      apiState={workspace.apiState}
      onImportLandPlot={() => setModal({ type: 'plot' })}
      onNewContract={() => setModal({ type: 'contract' })}
      onQueryChange={setQuery}
      onUploadDocument={() => setModal({ type: 'document' })}
      onViewChange={setActiveView}
      pendingActions={workspace.metrics.pendingTasks + workspace.metrics.documentsOnReview}
      query={query}
    >
      <DashboardView
        contracts={filteredContracts}
        documents={filteredDocuments}
        landPlots={filteredLandPlots}
        onDeleteContract={workspace.deleteContract}
        onEditContract={handleEditContract}
        onOpenDocumentForm={(contractId) => setModal({ type: 'document', contractId })}
        onOpenLandPlotForm={() => setModal({ type: 'plot' })}
        onSelectContract={handleSelectContract}
        onSignContract={(id) => workspace.changeContractStatus(id, 'signed')}
        selectedContractId={selectedContract?.id}
        tasks={filteredTasks}
        view={activeView}
        workspace={workspace}
      />

      <Modal
        onClose={closeModal}
        open={modal?.type === 'contract'}
        title={modal?.type === 'contract' && modal.contract ? 'Редактировать договор' : 'Новый договор'}
        width="wide"
      >
        {modal?.type === 'contract' && (
          <ContractForm
            initialContract={modal.contract}
            landPlots={workspace.landPlots}
            onCancel={closeModal}
            onSubmit={(draft) => {
              if (modal.contract) {
                workspace.updateContract(modal.contract.id, draft);
              } else {
                workspace.createContract(draft);
              }
              closeModal();
            }}
          />
        )}
      </Modal>

      <Modal
        onClose={closeModal}
        open={modal?.type === 'plot'}
        title="Импорт участка из ЕГРН"
        width="wide"
      >
        {modal?.type === 'plot' && (
          <LandPlotForm
            mode="egrn"
            onCancel={closeModal}
            onSubmit={(draft) => {
              workspace.createLandPlot(draft);
              closeModal();
            }}
          />
        )}
      </Modal>

      <Modal
        onClose={closeModal}
        open={modal?.type === 'document'}
        title="Загрузить документ"
      >
        {modal?.type === 'document' && (
          <DocumentForm
            contracts={workspace.contracts}
            initialContractId={modal.contractId}
            landPlots={workspace.landPlots}
            onCancel={closeModal}
            onSubmit={(draft) => {
              workspace.addDocument(draft);
              closeModal();
            }}
          />
        )}
      </Modal>
    </AppLayout>
  );
};

export default DashboardApp;
