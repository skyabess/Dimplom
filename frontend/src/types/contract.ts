export interface Contract {
  id: number;
  title: string;
  price: number;
  status: 'draft' | 'active' | 'closed';
  tags?: string[];
}