import { Contract, LandPlotSummary, WorkspaceSnapshot } from '../types/contract';
import { contractStatusMeta } from '../utils/status';

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || '/api';

interface PaginatedResponse<T> {
  results?: T[];
  count?: number;
}

const isRecord = (value: unknown): value is Record<string, any> =>
  typeof value === 'object' && value !== null;

const getAccessToken = () =>
  localStorage.getItem('land-contracts.accessToken') || localStorage.getItem('access_token');

const requestJson = async <T>(endpoint: string): Promise<T> => {
  const headers: HeadersInit = {
    Accept: 'application/json',
  };
  const token = getAccessToken();

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    headers,
    credentials: 'include',
  });

  if (!response.ok) {
    throw new Error(`API вернул ${response.status}`);
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

const normalizeContract = (
  raw: Record<string, any>,
  landPlots: LandPlotSummary[],
): Contract => {
  const status = raw.status || 'draft';
  const foundPlot =
    isRecord(raw.land_plot)
      ? normalizeLandPlot(raw.land_plot)
      : landPlots.find((plot) => plot.id === raw.land_plot || plot.cadastral_number === raw.cadastral_number);
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
    document_ids: Array.isArray(raw.document_ids) ? raw.document_ids : [],
    progress: raw.progress || contractStatusMeta[status]?.progress || 0,
  };
};

export const loadApiSnapshot = async (): Promise<Partial<WorkspaceSnapshot>> => {
  const [landPlotPayload, contractPayload] = await Promise.all([
    requestJson<LandPlotSummary[] | PaginatedResponse<LandPlotSummary>>('/land-plots/plots/'),
    requestJson<Contract[] | PaginatedResponse<Contract>>('/contracts/'),
  ]);

  const landPlots = normalizeList(landPlotPayload)
    .filter(isRecord)
    .map(normalizeLandPlot);

  const contracts = normalizeList(contractPayload)
    .filter(isRecord)
    .map((contract) => normalizeContract(contract, landPlots));

  return {
    contracts,
    landPlots,
    updatedAt: new Date().toISOString(),
  };
};
