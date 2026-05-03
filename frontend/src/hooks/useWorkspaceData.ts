import { useCallback, useEffect, useMemo, useState } from 'react';
import { createDemoSnapshot } from '../data/fixtures';
import { loadApiSnapshot } from '../services/api';
import {
  ApiState,
  Contract,
  ContractDraft,
  ContractStatus,
  DocumentDraft,
  DocumentItem,
  LandPlotDraft,
  LandPlotSummary,
  TaskItem,
  TaskPriority,
  WorkspaceSnapshot,
} from '../types/contract';
import { contractStatusMeta } from '../utils/status';

const STORAGE_KEY = 'land-contracts.workspace.v2';

const todayIsoDate = () => new Date().toISOString().slice(0, 10);

const createId = (prefix: string) => `${prefix}-${crypto.randomUUID()}`;

const readSnapshot = (): WorkspaceSnapshot => {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      return JSON.parse(stored) as WorkspaceSnapshot;
    }
  } catch {
    localStorage.removeItem(STORAGE_KEY);
  }

  return createDemoSnapshot();
};

const persistSnapshot = (snapshot: WorkspaceSnapshot) => {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      ...snapshot,
      updatedAt: new Date().toISOString(),
    }),
  );
};

const buildContractNumber = (contracts: Contract[]) => {
  const year = new Date().getFullYear();
  const next = contracts.length + 1;
  return `DK-${year}-${String(next).padStart(3, '0')}`;
};

const buildParty = (name: string) => ({
  id: createId('party'),
  full_name: name.trim() || 'Не указан',
});

const createContractFromDraft = (
  draft: ContractDraft,
  landPlot: LandPlotSummary,
  contracts: Contract[],
): Contract => {
  const total = draft.price + draft.additionalFees;

  return {
    id: createId('contract'),
    number: buildContractNumber(contracts),
    title: draft.title.trim(),
    description: draft.description.trim(),
    seller: buildParty(draft.sellerName),
    buyer: buildParty(draft.buyerName),
    land_plot: landPlot,
    price: draft.price,
    currency: draft.currency,
    additional_fees: draft.additionalFees,
    total_amount: total,
    status: draft.status,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    start_date: draft.startDate,
    end_date: draft.endDate,
    payment_terms: draft.paymentTerms,
    special_conditions: draft.specialConditions,
    tags: draft.tags,
    document_ids: [],
    progress: contractStatusMeta[draft.status].progress,
  };
};

const updateContractFromDraft = (
  contract: Contract,
  draft: ContractDraft,
  landPlot: LandPlotSummary,
): Contract => ({
  ...contract,
  title: draft.title.trim(),
  description: draft.description.trim(),
  seller: { ...contract.seller, full_name: draft.sellerName.trim() || contract.seller.full_name },
  buyer: { ...contract.buyer, full_name: draft.buyerName.trim() || contract.buyer.full_name },
  land_plot: landPlot,
  price: draft.price,
  currency: draft.currency,
  additional_fees: draft.additionalFees,
  total_amount: draft.price + draft.additionalFees,
  status: draft.status,
  updated_at: new Date().toISOString(),
  start_date: draft.startDate,
  end_date: draft.endDate,
  payment_terms: draft.paymentTerms,
  special_conditions: draft.specialConditions,
  tags: draft.tags,
  progress: contractStatusMeta[draft.status].progress,
});

export const useWorkspaceData = () => {
  const [snapshot, setSnapshot] = useState<WorkspaceSnapshot>(() => readSnapshot());
  const [apiState, setApiState] = useState<ApiState>({
    status: 'checking',
    message: 'Проверяем подключение к API',
  });

  useEffect(() => {
    let isMounted = true;

    loadApiSnapshot()
      .then((apiSnapshot) => {
        if (!isMounted) {
          return;
        }

        const hasApiData =
          Boolean(apiSnapshot.contracts?.length) || Boolean(apiSnapshot.landPlots?.length);

        if (hasApiData) {
          setSnapshot((current) => ({
            ...current,
            contracts: apiSnapshot.contracts?.length ? apiSnapshot.contracts : current.contracts,
            landPlots: apiSnapshot.landPlots?.length ? apiSnapshot.landPlots : current.landPlots,
            updatedAt: apiSnapshot.updatedAt || new Date().toISOString(),
          }));
          setApiState({
            status: 'connected',
            message: 'Данные загружены из API',
          });
        } else {
          setApiState({
            status: 'connected',
            message: 'API доступен, но пока без данных. Используется рабочий локальный набор.',
          });
        }
      })
      .catch((error: Error) => {
        if (!isMounted) {
          return;
        }

        setApiState({
          status: 'offline',
          message: `${error.message}. Данные сохраняются локально в браузере.`,
        });
      });

    return () => {
      isMounted = false;
    };
  }, []);

  useEffect(() => {
    persistSnapshot(snapshot);
  }, [snapshot]);

  const metrics = useMemo(() => {
    const activeContracts = snapshot.contracts.filter((contract) =>
      ['active', 'signed', 'pending_signature'].includes(contract.status),
    );
    const pendingTasks = snapshot.tasks.filter((task) => !task.completed);
    const totalValue = snapshot.contracts.reduce(
      (sum, contract) => sum + contract.total_amount,
      0,
    );
    const unverifiedPlots = snapshot.landPlots.filter((plot) => !plot.is_verified);
    const documentsOnReview = snapshot.documents.filter((doc) => doc.status === 'review');

    return {
      totalContracts: snapshot.contracts.length,
      activeContracts: activeContracts.length,
      pendingTasks: pendingTasks.length,
      totalValue,
      unverifiedPlots: unverifiedPlots.length,
      documentsOnReview: documentsOnReview.length,
    };
  }, [snapshot]);

  const createContract = useCallback((draft: ContractDraft) => {
    setSnapshot((current) => {
      const landPlot =
        current.landPlots.find((plot) => plot.id === draft.landPlotId) || current.landPlots[0];
      const contract = createContractFromDraft(draft, landPlot, current.contracts);

      return {
        ...current,
        contracts: [contract, ...current.contracts],
      };
    });
  }, []);

  const updateContract = useCallback((id: string, draft: ContractDraft) => {
    setSnapshot((current) => {
      const landPlot =
        current.landPlots.find((plot) => plot.id === draft.landPlotId) || current.landPlots[0];

      return {
        ...current,
        contracts: current.contracts.map((contract) =>
          contract.id === id ? updateContractFromDraft(contract, draft, landPlot) : contract,
        ),
      };
    });
  }, []);

  const changeContractStatus = useCallback((id: string, status: ContractStatus) => {
    setSnapshot((current) => ({
      ...current,
      contracts: current.contracts.map((contract) =>
        contract.id === id
          ? {
              ...contract,
              status,
              progress: contractStatusMeta[status].progress,
              signing_date: status === 'signed' ? todayIsoDate() : contract.signing_date,
              updated_at: new Date().toISOString(),
            }
          : contract,
      ),
    }));
  }, []);

  const deleteContract = useCallback((id: string) => {
    setSnapshot((current) => ({
      ...current,
      contracts: current.contracts.filter((contract) => contract.id !== id),
      tasks: current.tasks.map((task) =>
        task.contractId === id ? { ...task, contractId: undefined } : task,
      ),
      documents: current.documents.map((document) =>
        document.contractId === id ? { ...document, contractId: undefined } : document,
      ),
    }));
  }, []);

  const createLandPlot = useCallback((draft: LandPlotDraft) => {
    setSnapshot((current) => {
      const plot: LandPlotSummary = {
        id: createId('plot'),
        cadastral_number: draft.cadastralNumber.trim(),
        region_name: draft.regionName.trim(),
        address: draft.address.trim(),
        area: draft.area,
        area_hectares: draft.area / 10000,
        category_name: draft.categoryName.trim(),
        purpose_name: draft.purposeName.trim(),
        ownership_type: draft.ownershipType,
        is_verified: draft.isVerified,
        is_active: true,
        notes: draft.notes.trim(),
        source: draft.source,
        created_at: new Date().toISOString(),
      };

      return {
        ...current,
        landPlots: [plot, ...current.landPlots],
      };
    });
  }, []);

  const verifyLandPlot = useCallback((id: string) => {
    setSnapshot((current) => ({
      ...current,
      landPlots: current.landPlots.map((plot) =>
        plot.id === id
          ? {
              ...plot,
              is_verified: true,
              source: plot.source || 'egrn',
            }
          : plot,
      ),
    }));
  }, []);

  const addTask = useCallback(
    (title: string, priority: TaskPriority = 'medium', contractId?: string) => {
      const task: TaskItem = {
        id: createId('task'),
        title: title.trim(),
        contractId,
        dueDate: todayIsoDate(),
        assignee: 'Команда сделки',
        priority,
        completed: false,
      };

      setSnapshot((current) => ({
        ...current,
        tasks: [task, ...current.tasks],
      }));
    },
    [],
  );

  const toggleTask = useCallback((id: string) => {
    setSnapshot((current) => ({
      ...current,
      tasks: current.tasks.map((task) =>
        task.id === id ? { ...task, completed: !task.completed } : task,
      ),
    }));
  }, []);

  const addDocument = useCallback((draft: DocumentDraft) => {
    setSnapshot((current) => {
      const document: DocumentItem = {
        id: createId('doc'),
        title: draft.title.trim(),
        contractId: draft.contractId,
        landPlotId: draft.landPlotId,
        documentType: draft.documentType,
        fileName: draft.fileName,
        fileSize: draft.fileSize,
        uploadedAt: new Date().toISOString(),
        status: 'review',
      };

      return {
        ...current,
        documents: [document, ...current.documents],
        contracts: current.contracts.map((contract) =>
          contract.id === draft.contractId
            ? {
                ...contract,
                document_ids: [...contract.document_ids, document.id],
                updated_at: new Date().toISOString(),
              }
            : contract,
        ),
      };
    });
  }, []);

  const approveDocument = useCallback((id: string) => {
    setSnapshot((current) => ({
      ...current,
      documents: current.documents.map((document) =>
        document.id === id ? { ...document, status: 'approved' } : document,
      ),
    }));
  }, []);

  const resetDemoData = useCallback(() => {
    setSnapshot(createDemoSnapshot());
  }, []);

  return {
    ...snapshot,
    apiState,
    metrics,
    createContract,
    updateContract,
    changeContractStatus,
    deleteContract,
    createLandPlot,
    verifyLandPlot,
    addTask,
    toggleTask,
    addDocument,
    approveDocument,
    resetDemoData,
  };
};

export type WorkspaceData = ReturnType<typeof useWorkspaceData>;
