export type ContractStatus =
  | 'draft'
  | 'pending_approval'
  | 'pending_signature'
  | 'signed'
  | 'active'
  | 'completed'
  | 'cancelled'
  | 'terminated';

export type CurrencyCode = 'RUB' | 'USD' | 'EUR';

export type TaskPriority = 'low' | 'medium' | 'high';

export type ApiConnectionStatus = 'checking' | 'connected' | 'offline';

export interface PartySummary {
  id?: string;
  full_name: string;
  email?: string;
  phone?: string;
  company_name?: string;
}

export interface LandPlotSummary {
  id: string;
  cadastral_number: string;
  region_name: string;
  district_name?: string;
  settlement_name?: string;
  address: string;
  area: number;
  area_hectares?: number;
  category_name: string;
  purpose_name: string;
  ownership_type: 'state' | 'municipal' | 'private' | 'shared';
  is_verified: boolean;
  is_active: boolean;
  created_at?: string;
  notes?: string;
  source?: 'api' | 'manual' | 'egrn';
}

export interface Contract {
  id: string;
  number: string;
  title: string;
  description: string;
  seller: PartySummary;
  buyer: PartySummary;
  land_plot: LandPlotSummary;
  price: number;
  currency: CurrencyCode;
  additional_fees: number;
  total_amount: number;
  status: ContractStatus;
  created_at: string;
  updated_at?: string;
  start_date: string;
  end_date: string;
  signing_date?: string;
  payment_terms?: string;
  special_conditions?: string;
  tags: string[];
  document_ids: string[];
  progress: number;
}

export interface TaskItem {
  id: string;
  title: string;
  contractId?: string;
  dueDate: string;
  assignee: string;
  priority: TaskPriority;
  completed: boolean;
}

export interface DocumentItem {
  id: string;
  title: string;
  contractId?: string;
  landPlotId?: string;
  documentType: 'contract' | 'egrn' | 'payment' | 'identity' | 'other';
  fileName: string;
  fileSize: number;
  uploadedAt: string;
  status: 'uploaded' | 'review' | 'approved';
}

export interface WorkspaceSnapshot {
  contracts: Contract[];
  landPlots: LandPlotSummary[];
  tasks: TaskItem[];
  documents: DocumentItem[];
  updatedAt: string;
}

export interface ContractDraft {
  title: string;
  description: string;
  sellerName: string;
  buyerName: string;
  landPlotId: string;
  price: number;
  currency: CurrencyCode;
  additionalFees: number;
  status: ContractStatus;
  startDate: string;
  endDate: string;
  paymentTerms: string;
  specialConditions: string;
  tags: string[];
}

export interface LandPlotDraft {
  cadastralNumber: string;
  regionName: string;
  address: string;
  area: number;
  categoryName: string;
  purposeName: string;
  ownershipType: LandPlotSummary['ownership_type'];
  isVerified: boolean;
  notes: string;
  source: LandPlotSummary['source'];
}

export interface DocumentDraft {
  title: string;
  contractId?: string;
  landPlotId?: string;
  documentType: DocumentItem['documentType'];
  fileName: string;
  fileSize: number;
}

export interface ApiState {
  status: ApiConnectionStatus;
  message: string;
}
