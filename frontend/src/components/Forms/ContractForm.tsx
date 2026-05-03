import SaveIcon from '@mui/icons-material/Save';
import { FormEvent, useMemo, useState } from 'react';
import { Contract, ContractDraft, ContractStatus, LandPlotSummary } from '../../types/contract';

interface ContractFormProps {
  landPlots: LandPlotSummary[];
  initialContract?: Contract;
  onSubmit: (draft: ContractDraft) => void;
  onCancel: () => void;
}

const defaultDate = (offsetDays: number) => {
  const date = new Date();
  date.setDate(date.getDate() + offsetDays);
  return date.toISOString().slice(0, 10);
};

const ContractForm = ({
  landPlots,
  initialContract,
  onSubmit,
  onCancel,
}: ContractFormProps) => {
  const initialDraft = useMemo<ContractDraft>(() => {
    if (initialContract) {
      return {
        title: initialContract.title,
        description: initialContract.description,
        sellerName: initialContract.seller.full_name,
        buyerName: initialContract.buyer.full_name,
        landPlotId: initialContract.land_plot.id,
        price: initialContract.price,
        currency: initialContract.currency,
        additionalFees: initialContract.additional_fees,
        status: initialContract.status,
        startDate: initialContract.start_date,
        endDate: initialContract.end_date,
        paymentTerms: initialContract.payment_terms || '',
        specialConditions: initialContract.special_conditions || '',
        tags: initialContract.tags,
      };
    }

    return {
      title: '',
      description: '',
      sellerName: '',
      buyerName: '',
      landPlotId: landPlots[0]?.id || '',
      price: 0,
      currency: 'RUB',
      additionalFees: 0,
      status: 'draft',
      startDate: defaultDate(3),
      endDate: defaultDate(33),
      paymentTerms: '',
      specialConditions: '',
      tags: [],
    };
  }, [initialContract, landPlots]);

  const [draft, setDraft] = useState<ContractDraft>(initialDraft);
  const [tagText, setTagText] = useState(initialDraft.tags.join(', '));
  const [error, setError] = useState('');

  const updateField = <K extends keyof ContractDraft>(field: K, value: ContractDraft[K]) => {
    setDraft((current) => ({
      ...current,
      [field]: value,
    }));
  };

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();

    if (!draft.title.trim() || !draft.sellerName.trim() || !draft.buyerName.trim()) {
      setError('Заполните название, продавца и покупателя');
      return;
    }

    if (!draft.landPlotId) {
      setError('Выберите земельный участок');
      return;
    }

    if (draft.price <= 0) {
      setError('Укажите сумму договора');
      return;
    }

    onSubmit({
      ...draft,
      tags: tagText
        .split(',')
        .map((tag) => tag.trim())
        .filter(Boolean),
    });
  };

  return (
    <form className="form-grid" onSubmit={handleSubmit}>
      {error && <div className="form-error">{error}</div>}

      <label>
        <span>Название</span>
        <input
          onChange={(event) => updateField('title', event.target.value)}
          value={draft.title}
        />
      </label>

      <label>
        <span>Статус</span>
        <select
          onChange={(event) => updateField('status', event.target.value as ContractStatus)}
          value={draft.status}
        >
          <option value="draft">Черновик</option>
          <option value="pending_approval">На согласовании</option>
          <option value="pending_signature">На подписании</option>
          <option value="active">Активен</option>
        </select>
      </label>

      <label>
        <span>Продавец</span>
        <input
          onChange={(event) => updateField('sellerName', event.target.value)}
          value={draft.sellerName}
        />
      </label>

      <label>
        <span>Покупатель</span>
        <input
          onChange={(event) => updateField('buyerName', event.target.value)}
          value={draft.buyerName}
        />
      </label>

      <label className="full-span">
        <span>Участок</span>
        <select
          onChange={(event) => updateField('landPlotId', event.target.value)}
          value={draft.landPlotId}
        >
          {landPlots.map((plot) => (
            <option key={plot.id} value={plot.id}>
              {plot.cadastral_number} · {plot.region_name}
            </option>
          ))}
        </select>
      </label>

      <label>
        <span>Сумма</span>
        <input
          min="0"
          onChange={(event) => updateField('price', Number(event.target.value))}
          type="number"
          value={draft.price}
        />
      </label>

      <label>
        <span>Сборы</span>
        <input
          min="0"
          onChange={(event) => updateField('additionalFees', Number(event.target.value))}
          type="number"
          value={draft.additionalFees}
        />
      </label>

      <label>
        <span>Дата начала</span>
        <input
          onChange={(event) => updateField('startDate', event.target.value)}
          type="date"
          value={draft.startDate}
        />
      </label>

      <label>
        <span>Дата окончания</span>
        <input
          onChange={(event) => updateField('endDate', event.target.value)}
          type="date"
          value={draft.endDate}
        />
      </label>

      <label className="full-span">
        <span>Описание</span>
        <textarea
          onChange={(event) => updateField('description', event.target.value)}
          rows={3}
          value={draft.description}
        />
      </label>

      <label className="full-span">
        <span>Условия оплаты</span>
        <textarea
          onChange={(event) => updateField('paymentTerms', event.target.value)}
          rows={2}
          value={draft.paymentTerms}
        />
      </label>

      <label className="full-span">
        <span>Особые условия</span>
        <textarea
          onChange={(event) => updateField('specialConditions', event.target.value)}
          rows={2}
          value={draft.specialConditions}
        />
      </label>

      <label className="full-span">
        <span>Теги</span>
        <input onChange={(event) => setTagText(event.target.value)} value={tagText} />
      </label>

      <div className="form-actions full-span">
        <button className="secondary-button" onClick={onCancel} type="button">
          Отмена
        </button>
        <button className="primary-button" type="submit">
          <SaveIcon fontSize="small" />
          <span>{initialContract ? 'Сохранить' : 'Создать'}</span>
        </button>
      </div>
    </form>
  );
};

export default ContractForm;
