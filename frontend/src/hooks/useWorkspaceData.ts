import { useCallback, useEffect, useMemo, useState } from 'react';
import { createDemoSnapshot } from '../data/fixtures';
import {
  ApiError,
  approveContractDocument,
  clearAuthSession,
  createContract as createContractApi,
  createLandPlot as createLandPlotApi,
  createTask as createTaskApi,
  deleteContract as deleteContractApi,
  getAccessToken,
  getProfile,
  getStoredUser,
  loadApiSnapshot,
  login as loginApi,
  logout as logoutApi,
  register as registerApi,
  signContract as signContractApi,
  toggleTask as toggleTaskApi,
  updateContract as updateContractApi,
  uploadContractDocument,
  verifyLandPlot as verifyLandPlotApi,
} from '../services/api';
import {
  ApiState,
  AuthUser,
  Contract,
  ContractDraft,
  ContractStatus,
  DocumentDraft,
  DocumentItem,
  LandPlotDraft,
  LandPlotSummary,
  LoginDraft,
  RegisterDraft,
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
  const [authUser, setAuthUser] = useState<AuthUser | undefined>(() => getStoredUser());
  const [apiState, setApiState] = useState<ApiState>({
    status: 'checking',
    message: 'Проверяем подключение к API',
  });

  const applyApiSnapshot = useCallback((apiSnapshot: Partial<WorkspaceSnapshot>) => {
    const hasApiSnapshot =
      apiSnapshot.contracts !== undefined ||
      apiSnapshot.landPlots !== undefined ||
      apiSnapshot.tasks !== undefined ||
      apiSnapshot.documents !== undefined;
    const hasServerRows =
      Boolean(apiSnapshot.contracts?.length) ||
      Boolean(apiSnapshot.landPlots?.length) ||
      Boolean(apiSnapshot.tasks?.length) ||
      Boolean(apiSnapshot.documents?.length);

    if (hasApiSnapshot) {
      setSnapshot((current) => ({
        ...current,
        contracts: apiSnapshot.contracts ?? current.contracts,
        landPlots: apiSnapshot.landPlots ?? current.landPlots,
        tasks: apiSnapshot.tasks ?? current.tasks,
        documents: apiSnapshot.documents ?? current.documents,
        updatedAt: apiSnapshot.updatedAt || new Date().toISOString(),
      }));
      setApiState({
        status: 'connected',
        message: hasServerRows
          ? 'Данные загружены из API'
          : 'API доступен, серверных данных пока нет.',
      });
    } else {
      setApiState({
        status: 'connected',
        message: 'API доступен, но пока без данных. Используется рабочий локальный набор.',
      });
    }
  }, []);

  const handleApiError = useCallback((error: unknown) => {
    if (error instanceof ApiError && error.status === 401) {
      clearAuthSession();
      setAuthUser(undefined);
      setApiState({
        status: 'unauthorized',
        message: 'Войдите в систему, чтобы синхронизировать данные с сервером.',
      });
      return;
    }

    const message = error instanceof Error ? error.message : 'API недоступен';
    setApiState({
      status: 'offline',
      message: `${message}. Данные сохраняются локально в браузере.`,
    });
  }, []);

  const syncFromApi = useCallback(async () => {
    try {
      const apiSnapshot = await loadApiSnapshot();
      applyApiSnapshot(apiSnapshot);
    } catch (error) {
      handleApiError(error);
    }
  }, [applyApiSnapshot, handleApiError]);

  const canUseApi = useCallback(() => Boolean(getAccessToken()), []);

  useEffect(() => {
    let isMounted = true;

    const bootstrap = async () => {
      if (!getAccessToken()) {
        if (isMounted) {
          setApiState({
            status: 'unauthorized',
            message: 'Войдите в систему, чтобы синхронизировать данные с сервером.',
          });
        }
        return;
      }

      try {
        const profile = await getProfile();
        if (isMounted && profile) {
          setAuthUser(profile);
        }
        await syncFromApi();
      } catch (error) {
        if (isMounted) {
          handleApiError(error);
        }
      }
    };

    bootstrap();

    return () => {
      isMounted = false;
    };
  }, [handleApiError, syncFromApi]);

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

  const createContract = useCallback(async (draft: ContractDraft) => {
    const createLocal = () => setSnapshot((current) => {
      const landPlot =
        current.landPlots.find((plot) => plot.id === draft.landPlotId) || current.landPlots[0];
      const contract = createContractFromDraft(draft, landPlot, current.contracts);

      return {
        ...current,
        contracts: [contract, ...current.contracts],
      };
    });

    if (!canUseApi()) {
      createLocal();
      return;
    }

    try {
      const contract = await createContractApi(draft, snapshot.landPlots);
      setSnapshot((current) => ({
        ...current,
        contracts: [contract, ...current.contracts.filter((item) => item.id !== contract.id)],
      }));
      setApiState({ status: 'connected', message: 'Договор сохранен на сервере.' });
    } catch (error) {
      handleApiError(error);
      createLocal();
    }
  }, [canUseApi, handleApiError, snapshot.landPlots]);

  const updateContract = useCallback(async (id: string, draft: ContractDraft) => {
    const updateLocal = () => setSnapshot((current) => {
      const landPlot =
        current.landPlots.find((plot) => plot.id === draft.landPlotId) || current.landPlots[0];

      return {
        ...current,
        contracts: current.contracts.map((contract) =>
          contract.id === id ? updateContractFromDraft(contract, draft, landPlot) : contract,
        ),
      };
    });

    if (!canUseApi()) {
      updateLocal();
      return;
    }

    try {
      const contract = await updateContractApi(id, draft, snapshot.landPlots);
      setSnapshot((current) => ({
        ...current,
        contracts: current.contracts.map((item) => (item.id === id ? contract : item)),
      }));
      setApiState({ status: 'connected', message: 'Договор обновлен на сервере.' });
    } catch (error) {
      handleApiError(error);
      updateLocal();
    }
  }, [canUseApi, handleApiError, snapshot.landPlots]);

  const changeContractStatus = useCallback(async (id: string, status: ContractStatus) => {
    const changeLocal = () => setSnapshot((current) => ({
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

    if (!canUseApi()) {
      changeLocal();
      return;
    }

    try {
      if (status === 'signed') {
        await signContractApi(id);
      } else {
        const contract = snapshot.contracts.find((item) => item.id === id);
        if (contract) {
          await updateContractApi(id, {
            title: contract.title,
            description: contract.description,
            sellerName: contract.seller.full_name,
            buyerName: contract.buyer.full_name,
            landPlotId: contract.land_plot.id,
            price: contract.price,
            currency: contract.currency,
            additionalFees: contract.additional_fees,
            status,
            startDate: contract.start_date,
            endDate: contract.end_date,
            paymentTerms: contract.payment_terms || '',
            specialConditions: contract.special_conditions || '',
            tags: contract.tags,
          }, snapshot.landPlots);
        }
      }
      await syncFromApi();
      setApiState({ status: 'connected', message: 'Статус договора обновлен на сервере.' });
    } catch (error) {
      handleApiError(error);
      changeLocal();
    }
  }, [canUseApi, handleApiError, snapshot.contracts, snapshot.landPlots, syncFromApi]);

  const deleteContract = useCallback(async (id: string) => {
    const deleteLocal = () => setSnapshot((current) => ({
      ...current,
      contracts: current.contracts.filter((contract) => contract.id !== id),
      tasks: current.tasks.map((task) =>
        task.contractId === id ? { ...task, contractId: undefined } : task,
      ),
      documents: current.documents.map((document) =>
        document.contractId === id ? { ...document, contractId: undefined } : document,
      ),
    }));

    if (!canUseApi()) {
      deleteLocal();
      return;
    }

    try {
      await deleteContractApi(id);
      deleteLocal();
      setApiState({ status: 'connected', message: 'Договор удален на сервере.' });
    } catch (error) {
      handleApiError(error);
      deleteLocal();
    }
  }, [canUseApi, handleApiError]);

  const createLandPlot = useCallback(async (draft: LandPlotDraft) => {
    const createLocal = () => setSnapshot((current) => {
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

    if (!canUseApi()) {
      createLocal();
      return;
    }

    try {
      const plot = await createLandPlotApi(draft);
      setSnapshot((current) => ({
        ...current,
        landPlots: [plot, ...current.landPlots.filter((item) => item.id !== plot.id)],
      }));
      setApiState({ status: 'connected', message: 'Участок сохранен на сервере.' });
    } catch (error) {
      handleApiError(error);
      createLocal();
    }
  }, [canUseApi, handleApiError]);

  const verifyLandPlot = useCallback(async (id: string) => {
    const verifyLocal = () => setSnapshot((current) => ({
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

    if (!canUseApi()) {
      verifyLocal();
      return;
    }

    try {
      const plot = await verifyLandPlotApi(id);
      setSnapshot((current) => ({
        ...current,
        landPlots: current.landPlots.map((item) => (item.id === id ? plot : item)),
      }));
      setApiState({ status: 'connected', message: 'Участок подтвержден на сервере.' });
    } catch (error) {
      handleApiError(error);
      verifyLocal();
    }
  }, [canUseApi, handleApiError]);

  const addTask = useCallback(
    async (title: string, priority: TaskPriority = 'medium', contractId?: string) => {
      const task: TaskItem = {
        id: createId('task'),
        title: title.trim(),
        contractId,
        dueDate: todayIsoDate(),
        assignee: 'Команда сделки',
        priority,
        completed: false,
      };

      const addLocal = () => setSnapshot((current) => ({
        ...current,
        tasks: [task, ...current.tasks],
      }));

      if (!canUseApi()) {
        addLocal();
        return;
      }

      try {
        const savedTask = await createTaskApi(title, priority, contractId);
        setSnapshot((current) => ({
          ...current,
          tasks: [savedTask, ...current.tasks.filter((item) => item.id !== savedTask.id)],
        }));
        setApiState({ status: 'connected', message: 'Задача сохранена на сервере.' });
      } catch (error) {
        handleApiError(error);
        addLocal();
      }
    },
    [canUseApi, handleApiError],
  );

  const toggleTask = useCallback(async (id: string) => {
    const toggleLocal = () => setSnapshot((current) => ({
      ...current,
      tasks: current.tasks.map((task) =>
        task.id === id ? { ...task, completed: !task.completed } : task,
      ),
    }));
    const task = snapshot.tasks.find((item) => item.id === id);

    if (!canUseApi() || !task) {
      toggleLocal();
      return;
    }

    try {
      const updatedTask = await toggleTaskApi(task);
      setSnapshot((current) => ({
        ...current,
        tasks: current.tasks.map((item) => (item.id === id ? updatedTask : item)),
      }));
      setApiState({ status: 'connected', message: 'Задача обновлена на сервере.' });
    } catch (error) {
      handleApiError(error);
      toggleLocal();
    }
  }, [canUseApi, handleApiError, snapshot.tasks]);

  const addDocument = useCallback(async (draft: DocumentDraft) => {
    const addLocal = () => setSnapshot((current) => {
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

    if (!canUseApi() || !draft.file || !draft.contractId) {
      addLocal();
      return;
    }

    try {
      const document = await uploadContractDocument(draft);
      setSnapshot((current) => ({
        ...current,
        documents: [document, ...current.documents.filter((item) => item.id !== document.id)],
        contracts: current.contracts.map((contract) =>
          contract.id === draft.contractId
            ? {
                ...contract,
                document_ids: [...new Set([...contract.document_ids, document.id])],
                updated_at: new Date().toISOString(),
              }
            : contract,
        ),
      }));
      setApiState({ status: 'connected', message: 'Документ загружен на сервер.' });
    } catch (error) {
      handleApiError(error);
      addLocal();
    }
  }, [canUseApi, handleApiError]);

  const approveDocument = useCallback(async (id: string) => {
    const approveLocal = () => setSnapshot((current) => ({
      ...current,
      documents: current.documents.map((document) =>
        document.id === id ? { ...document, status: 'approved' } : document,
      ),
    }));

    const document = snapshot.documents.find((item) => item.id === id);

    if (!canUseApi() || !document?.contractId) {
      approveLocal();
      return;
    }

    try {
      const approvedDocument = await approveContractDocument(document);
      setSnapshot((current) => ({
        ...current,
        documents: current.documents.map((item) =>
          item.id === id ? approvedDocument : item,
        ),
      }));
      setApiState({ status: 'connected', message: 'Документ принят на сервере.' });
    } catch (error) {
      handleApiError(error);
      approveLocal();
    }
  }, [canUseApi, handleApiError, snapshot.documents]);

  const resetDemoData = useCallback(() => {
    setSnapshot(createDemoSnapshot());
  }, []);

  const login = useCallback(async (draft: LoginDraft) => {
    const user = await loginApi(draft);
    setAuthUser(user);
    await syncFromApi();
    return user;
  }, [syncFromApi]);

  const register = useCallback(async (draft: RegisterDraft) => {
    const user = await registerApi(draft);
    setAuthUser(user);
    await syncFromApi();
    return user;
  }, [syncFromApi]);

  const logout = useCallback(async () => {
    await logoutApi();
    setAuthUser(undefined);
    setApiState({
      status: 'unauthorized',
      message: 'Вы вышли из системы. Данные сохраняются локально.',
    });
  }, []);

  return {
    ...snapshot,
    authUser,
    apiState,
    metrics,
    login,
    register,
    logout,
    syncFromApi,
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
