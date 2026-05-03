import SaveIcon from '@mui/icons-material/Save';
import { FormEvent, useState } from 'react';
import { LandPlotDraft, LandPlotSummary } from '../../types/contract';

interface LandPlotFormProps {
  mode?: 'manual' | 'egrn';
  onSubmit: (draft: LandPlotDraft) => void;
  onCancel: () => void;
}

const LandPlotForm = ({ mode = 'manual', onSubmit, onCancel }: LandPlotFormProps) => {
  const [draft, setDraft] = useState<LandPlotDraft>({
    cadastralNumber: '',
    regionName: '',
    address: '',
    area: 0,
    categoryName: 'Земли населенных пунктов',
    purposeName: '',
    ownershipType: 'private',
    isVerified: mode === 'egrn',
    notes: '',
    source: mode,
  });
  const [error, setError] = useState('');

  const updateField = <K extends keyof LandPlotDraft>(field: K, value: LandPlotDraft[K]) => {
    setDraft((current) => ({
      ...current,
      [field]: value,
    }));
  };

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();

    if (!draft.cadastralNumber.trim() || !draft.regionName.trim() || !draft.address.trim()) {
      setError('Заполните кадастровый номер, регион и адрес');
      return;
    }

    if (draft.area <= 0) {
      setError('Укажите площадь участка');
      return;
    }

    onSubmit(draft);
  };

  return (
    <form className="form-grid" onSubmit={handleSubmit}>
      {error && <div className="form-error">{error}</div>}

      <label>
        <span>Кадастровый номер</span>
        <input
          onChange={(event) => updateField('cadastralNumber', event.target.value)}
          placeholder="50:21:0040201:814"
          value={draft.cadastralNumber}
        />
      </label>

      <label>
        <span>Регион</span>
        <input
          onChange={(event) => updateField('regionName', event.target.value)}
          value={draft.regionName}
        />
      </label>

      <label className="full-span">
        <span>Адрес</span>
        <input onChange={(event) => updateField('address', event.target.value)} value={draft.address} />
      </label>

      <label>
        <span>Площадь, м²</span>
        <input
          min="0"
          onChange={(event) => updateField('area', Number(event.target.value))}
          type="number"
          value={draft.area}
        />
      </label>

      <label>
        <span>Собственность</span>
        <select
          onChange={(event) =>
            updateField('ownershipType', event.target.value as LandPlotSummary['ownership_type'])
          }
          value={draft.ownershipType}
        >
          <option value="private">Частная</option>
          <option value="municipal">Муниципальная</option>
          <option value="state">Государственная</option>
          <option value="shared">Долевая</option>
        </select>
      </label>

      <label>
        <span>Категория</span>
        <input
          onChange={(event) => updateField('categoryName', event.target.value)}
          value={draft.categoryName}
        />
      </label>

      <label>
        <span>Назначение</span>
        <input
          onChange={(event) => updateField('purposeName', event.target.value)}
          value={draft.purposeName}
        />
      </label>

      <label className="checkbox-label full-span">
        <input
          checked={draft.isVerified}
          onChange={(event) => updateField('isVerified', event.target.checked)}
          type="checkbox"
        />
        <span>Проверен по ЕГРН</span>
      </label>

      <label className="full-span">
        <span>Примечание</span>
        <textarea onChange={(event) => updateField('notes', event.target.value)} rows={3} value={draft.notes} />
      </label>

      <div className="form-actions full-span">
        <button className="secondary-button" onClick={onCancel} type="button">
          Отмена
        </button>
        <button className="primary-button" type="submit">
          <SaveIcon fontSize="small" />
          <span>{mode === 'egrn' ? 'Импортировать' : 'Добавить'}</span>
        </button>
      </div>
    </form>
  );
};

export default LandPlotForm;
