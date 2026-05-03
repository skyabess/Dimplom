import {
  AuthUser,
  Contract,
  ContractDraft,
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

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || '/api';

const ACCESS_TOKEN_KEY = 'land-contracts.accessToken';
const REFRESH_TOKEN_KEY = 'land-contracts.refreshToken';
const USER_KEY = 'land-contracts.user';

interface PaginatedResponse<T> {
  results?: T[];
  count?: number;
}

interface AuthResponse {
  user: AuthUser;
  access: string;
  refresh: string;
}

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const isRecord = (value: unknown): value is Record<string, any> =>
  typeof value === 'object' && value !== null;

export const getAccessToken = () =>
  localStorage.getItem(ACCESS_TOKEN_KEY) || localStorage.getItem('access_token');

const setAuthSession = (response: AuthResponse) => {
  localStorage.setItem(ACCESS_TOKEN_KEY, response.access);
  localStorage.setItem(REFRESH_TOKEN_KEY, response.refresh);
  localStorage.setItem(USER_KEY, JSON.stringify(response.user));
};

export const clearAuthSession = () => {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  localStorage.removeItem('access_token');
};

export const getStoredUser = (): AuthUser | undefined => {
  try {
    const stored = localStorage.getItem(USER_KEY);
    return stored ? JSON.parse(stored) : undefined;
  } catch {
    localStorage.removeItem(USER_KEY);
    return undefined;
  }
};

const parseErrorMessage = async (response: Response) => {
  try {
    const payload = await response.json();
    if (isRecord(payload)) {
      return payload.detail || payload.error || payload.message || `API вернул ${response.status}`;
    }
  } catch {
    // The response may be an HTML fallback from the dev server.
  }

  return `API вернул ${response.status}`;
};

const requestJson = async <T>(
  endpoint: string,
  options: RequestInit = {},
): Promise<T> => {
  const headers = new Headers(options.headers);
  const token = getAccessToken();

  if (!(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  headers.set('Accept', 'application/json');

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
    credentials: 'include',
  });

  if (!response.ok) {
    throw new ApiError(response.status, String(await parseErrorMessage(response)));
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
};

const normalizeList = <T>(payload: T[] | PaginatedResponse<T>): T[] => {
  if (Array.isArray(payload)) {
    return payload;
  }

  return payload.results || [];
};

const toNumber = (value: unknown, fallback = 0) => {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
};

const normalizeLandPlot = (raw: Record<string, any>): LandPlotSummary => ({
  id: String(raw.id || raw.cadastral_number || crypto.randomUUID()),
  cadastral_number: String(raw.cadastral_number || raw.cadastralNumber || 'Не указан'),
  region_name: String(raw.region_name || raw.regionName || raw.region || 'Регион не указан'),
  district_name: raw.district_name,
  settlement_name: raw.settlement_name,
  address: String(raw.address || raw.full_address || 'Адрес не указан'),
  area: toNumber(raw.area),
  area_hectares: raw.area_hectares ? toNumber(raw.area_hectares) : undefined,
  category_name: String(raw.category_name || raw.category || 'Категория не указана'),
  purpose_name: String(raw.purpose_name || raw.purpose || 'Назначение не указано'),
  ownership_type: raw.ownership_type || 'private',
  is_verified: Boolean(raw.is_verified),
  is_active: raw.is_active !== false,
  created_at: raw.created_at,
  notes: raw.notes || '',
  source: 'api',
});

const normalizeDocument = (raw: Record<string, any>): DocumentItem => ({
  id: String(raw.id || crypto.randomUUID()),
  title: String(raw.title || raw.file_name || 'Документ'),
  contractId: raw.contract ? String(raw.contract) : undefined,
  landPlotId: raw.land_plot ? String(raw.land_plot) : undefined,
  documentType:
    raw.document_type === 'registration'
      ? 'egrn'
      : raw.document_type === 'payment_proof'
        ? 'payment'
        : raw.document_type === 'draft' || raw.document_type === 'final'
          ? 'contract'
          : 'other',
  fileName: String(raw.file_name || raw.file?.split('/').pop() || raw.title || 'document'),
  fileSize: toNumber(raw.file_size),
  uploadedAt: raw.created_at || raw.uploaded_at || new Date().toISOString(),
  status: raw.is_signed ? 'approved' : 'review',
});

const normalizeTaskPriority = (value: unknown): TaskPriority => {
  if (value === 'low' || value === 'medium' || value === 'high') {
    return value;
  }

  return 'medium';
};

const normalizeTask = (raw: Record<string, any>): TaskItem => ({
  id: String(raw.id || crypto.randomUUID()),
  title: String(raw.title || 'Задача'),
  contractId: raw.contract ? String(raw.contract) : undefined,
  dueDate: raw.due_date || raw.dueDate || new Date().toISOString().slice(0, 10),
  assignee: String(raw.assignee || 'Команда сделки'),
  priority: normalizeTaskPriority(raw.priority),
  completed: Boolean(raw.is_completed ?? raw.completed),
});

const normalizeContract = (
  raw: Record<string, any>,
  landPlots: LandPlotSummary[],
): Contract => {
  const status = raw.status || 'draft';
  const foundPlot =
    isRecord(raw.land_plot)
      ? normalizeLandPlot(raw.land_plot)
      : landPlots.find(
          (plot) => plot.id === String(raw.land_plot) || plot.cadastral_number === raw.cadastral_number,
        );
  const price = toNumber(raw.price);
  const additionalFees = toNumber(raw.additional_fees);

  return {
    id: String(raw.id || crypto.randomUUID()),
    number: String(raw.number || raw.contract_number || `DK-${String(raw.id || '').slice(0, 8)}`),
    title: String(raw.title || 'Договор без названия'),
    description: String(raw.description || ''),
    seller: {
      id: isRecord(raw.seller) ? raw.seller.id : raw.seller,
      full_name:
        (isRecord(raw.seller) && raw.seller.full_name) ||
        raw.seller_name ||
        raw.seller_full_name ||
        'Продавец не указан',
    },
    buyer: {
      id: isRecord(raw.buyer) ? raw.buyer.id : raw.buyer,
      full_name:
        (isRecord(raw.buyer) && raw.buyer.full_name) ||
        raw.buyer_name ||
        raw.buyer_full_name ||
        'Покупатель не указан',
    },
    land_plot:
      foundPlot ||
      normalizeLandPlot({
        id: raw.land_plot || raw.land_plot_id,
        cadastral_number: raw.land_plot_cadastral_number || 'Не указан',
        region_name: 'Регион не указан',
      }),
    price,
    currency: raw.currency || 'RUB',
    additional_fees: additionalFees,
    total_amount: toNumber(raw.total_amount, price + additionalFees),
    status,
    created_at: raw.created_at || new Date().toISOString(),
    updated_at: raw.updated_at,
    start_date: raw.start_date || '',
    end_date: raw.end_date || '',
    signing_date: raw.signing_date,
    payment_terms: raw.payment_terms || '',
    special_conditions: raw.special_conditions || '',
    tags: Array.isArray(raw.tags) ? raw.tags : [],
    document_ids: Array.isArray(raw.documents)
      ? raw.documents.map((document: Record<string, any>) => String(document.id))
      : [],
    progress: raw.progress || contractStatusMeta[status]?.progress || 0,
  };
};

const contractPayload = (draft: ContractDraft) => ({
  title: draft.title,
  description: draft.description || draft.title,
  seller_full_name: draft.sellerName,
  buyer_full_name: draft.buyerName,
  land_plot: draft.landPlotId,
  price: draft.price,
  currency: draft.currency,
  additional_fees: draft.additionalFees,
  status: draft.status,
  start_date: draft.startDate,
  end_date: draft.endDate,
  payment_terms: draft.paymentTerms,
  special_conditions: draft.specialConditions,
});

const landPlotPayload = (draft: LandPlotDraft) => ({
  cadastral_number: draft.cadastralNumber,
  region_name: draft.regionName,
  address: draft.address,
  area: draft.area,
  category_name: draft.categoryName,
  purpose_name: draft.purposeName,
  ownership_type: draft.ownershipType,
  is_verified: draft.isVerified,
  notes: draft.notes,
});

const documentTypeMap: Record<DocumentItem['documentType'], string> = {
  contract: 'draft',
  egrn: 'registration',
  payment: 'payment_proof',
  identity: 'attachment',
  other: 'other',
};

export const login = async (draft: LoginDraft) => {
  const response = await requestJson<AuthResponse>('/auth/login/', {
    method: 'POST',
    body: JSON.stringify({
      email: draft.email,
      password: draft.password,
    }),
  });
  setAuthSession(response);
  return response.user;
};

export const register = async (draft: RegisterDraft) => {
  const response = await requestJson<AuthResponse>('/auth/register/', {
    method: 'POST',
    body: JSON.stringify({
      username: draft.username,
      email: draft.email,
      first_name: draft.firstName,
      last_name: draft.lastName,
      password: draft.password,
      password_confirm: draft.passwordConfirm,
    }),
  });
  setAuthSession(response);
  return response.user;
};

export const getProfile = async () => {
  const user = await requestJson<AuthUser>('/auth/profile/');
  localStorage.setItem(USER_KEY, JSON.stringify(user));
  return user;
};

export const logout = async () => {
  try {
    await requestJson('/auth/logout/', {
      method: 'POST',
      body: JSON.stringify({}),
    });
  } finally {
    clearAuthSession();
  }
};

export const loadApiSnapshot = async (): Promise<Partial<WorkspaceSnapshot>> => {
  const [landPlotPayloadResponse, contractPayloadResponse, taskPayloadResponse] = await Promise.all([
    requestJson<LandPlotSummary[] | PaginatedResponse<LandPlotSummary>>('/land-plots/plots/'),
    requestJson<Contract[] | PaginatedResponse<Contract>>('/contracts/'),
    requestJson<TaskItem[] | PaginatedResponse<TaskItem>>('/contracts/tasks/').catch((error) => {
      if (error instanceof ApiError && error.status === 404) {
        return [];
      }

      throw error;
    }),
  ]);

  const landPlots = normalizeList(landPlotPayloadResponse)
    .filter(isRecord)
    .map(normalizeLandPlot);

  const contractRows = normalizeList(contractPayloadResponse).filter(isRecord);
  const detailRows: Record<string, any>[] = await Promise.all(
    contractRows.map((contract) =>
      requestJson<Record<string, any>>(`/contracts/${contract.id}/`).catch(() => contract),
    ),
  );

  const contracts = detailRows.map((contract) => normalizeContract(contract, landPlots));
  const documents = detailRows.flatMap((contract) =>
    Array.isArray(contract.documents)
      ? contract.documents.filter(isRecord).map((document) => ({
          ...normalizeDocument(document),
          contractId: String(contract.id),
        }))
      : [],
  );
  const tasks = normalizeList(taskPayloadResponse)
    .filter(isRecord)
    .map(normalizeTask);

  return {
    contracts,
    landPlots,
    tasks,
    documents,
    updatedAt: new Date().toISOString(),
  };
};

export const createContract = async (draft: ContractDraft, landPlots: LandPlotSummary[]) => {
  const raw = await requestJson<Record<string, any>>('/contracts/', {
    method: 'POST',
    body: JSON.stringify(contractPayload(draft)),
  });
  return normalizeContract(raw, landPlots);
};

export const updateContract = async (
  id: string,
  draft: ContractDraft,
  landPlots: LandPlotSummary[],
) => {
  const raw = await requestJson<Record<string, any>>(`/contracts/${id}/`, {
    method: 'PATCH',
    body: JSON.stringify(contractPayload(draft)),
  });
  return normalizeContract(raw, landPlots);
};

export const deleteContract = async (id: string) => {
  await requestJson<void>(`/contracts/${id}/`, {
    method: 'DELETE',
  });
};

export const signContract = async (id: string) => {
  await requestJson(`/contracts/${id}/sign/`, {
    method: 'POST',
    body: JSON.stringify({
      signature_data: `signed:${new Date().toISOString()}`,
    }),
  });
};

export const createLandPlot = async (draft: LandPlotDraft) => {
  const raw = await requestJson<Record<string, any>>('/land-plots/plots/', {
    method: 'POST',
    body: JSON.stringify(landPlotPayload(draft)),
  });
  return normalizeLandPlot(raw);
};

export const verifyLandPlot = async (id: string) => {
  const raw = await requestJson<Record<string, any>>(`/land-plots/plots/${id}/`, {
    method: 'PATCH',
    body: JSON.stringify({ is_verified: true }),
  });
  return normalizeLandPlot(raw);
};

export const createTask = async (
  title: string,
  priority: TaskPriority = 'medium',
  contractId?: string,
) => {
  const raw = await requestJson<Record<string, any>>('/contracts/tasks/', {
    method: 'POST',
    body: JSON.stringify({
      title,
      contract: contractId || null,
      due_date: new Date().toISOString().slice(0, 10),
      assignee: 'Команда сделки',
      priority,
      is_completed: false,
    }),
  });

  return normalizeTask(raw);
};

export const toggleTask = async (task: TaskItem) => {
  const raw = await requestJson<Record<string, any>>(`/contracts/tasks/${task.id}/`, {
    method: 'PATCH',
    body: JSON.stringify({
      is_completed: !task.completed,
    }),
  });
  const normalizedTask = normalizeTask(raw);

  return {
    ...normalizedTask,
    contractId: normalizedTask.contractId || task.contractId,
  };
};

export const uploadContractDocument = async (draft: DocumentDraft) => {
  if (!draft.contractId || !draft.file) {
    throw new ApiError(400, 'Для загрузки документа нужен договор и файл.');
  }

  const body = new FormData();
  body.append('title', draft.title);
  body.append('document_type', documentTypeMap[draft.documentType]);
  body.append('file', draft.file);

  const raw = await requestJson<Record<string, any>>(`/contracts/${draft.contractId}/documents/`, {
    method: 'POST',
    body,
  });

  return normalizeDocument(raw);
};

export const approveContractDocument = async (document: DocumentItem) => {
  if (!document.contractId) {
    throw new ApiError(400, 'Документ не привязан к договору.');
  }

  const raw = await requestJson<Record<string, any>>(
    `/contracts/${document.contractId}/documents/${document.id}/`,
    {
      method: 'PATCH',
      body: JSON.stringify({ is_signed: true }),
    },
  );

  return {
    ...normalizeDocument(raw),
    contractId: document.contractId,
  };
};
