import UploadFileIcon from '@mui/icons-material/UploadFile';
import { FormEvent, useState } from 'react';
import { Contract, DocumentDraft, DocumentItem, LandPlotSummary } from '../../types/contract';

interface DocumentFormProps {
  contracts: Contract[];
  landPlots: LandPlotSummary[];
  initialContractId?: string;
  onSubmit: (draft: DocumentDraft) => void;
  onCancel: () => void;
}

const DocumentForm = ({
  contracts,
  landPlots,
  initialContractId = '',
  onSubmit,
  onCancel,
}: DocumentFormProps) => {
  const [title, setTitle] = useState('');
  const [contractId, setContractId] = useState(initialContractId);
  const [landPlotId, setLandPlotId] = useState('');
  const [documentType, setDocumentType] = useState<DocumentItem['documentType']>('contract');
  const [fileName, setFileName] = useState('');
  const [fileSize, setFileSize] = useState(0);
  const [file, setFile] = useState<File | undefined>();
  const [error, setError] = useState('');

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();

    if (!title.trim()) {
      setError('Укажите название документа');
      return;
    }

    if (!fileName) {
      setError('Выберите файл');
      return;
    }

    onSubmit({
      title,
      contractId: contractId || undefined,
      landPlotId: landPlotId || undefined,
      documentType,
      fileName,
      fileSize,
      file,
    });
  };

  return (
    <form className="form-grid" onSubmit={handleSubmit}>
      {error && <div className="form-error">{error}</div>}

      <label className="full-span">
        <span>Название</span>
        <input onChange={(event) => setTitle(event.target.value)} value={title} />
      </label>

      <label>
        <span>Тип</span>
        <select
          onChange={(event) => setDocumentType(event.target.value as DocumentItem['documentType'])}
          value={documentType}
        >
          <option value="contract">Договор</option>
          <option value="egrn">ЕГРН</option>
          <option value="payment">Оплата</option>
          <option value="identity">Личность</option>
          <option value="other">Другое</option>
        </select>
      </label>

      <label>
        <span>Договор</span>
        <select onChange={(event) => setContractId(event.target.value)} value={contractId}>
          <option value="">Без договора</option>
          {contracts.map((contract) => (
            <option key={contract.id} value={contract.id}>
              {contract.number}
            </option>
          ))}
        </select>
      </label>

      <label className="full-span">
        <span>Участок</span>
        <select onChange={(event) => setLandPlotId(event.target.value)} value={landPlotId}>
          <option value="">Без участка</option>
          {landPlots.map((plot) => (
            <option key={plot.id} value={plot.id}>
              {plot.cadastral_number}
            </option>
          ))}
        </select>
      </label>

      <label className="file-input full-span">
        <UploadFileIcon fontSize="small" />
        <span>{fileName || 'Выберите файл'}</span>
        <input
          onChange={(event) => {
            const selectedFile = event.target.files?.[0];
            setFile(selectedFile);
            setFileName(selectedFile?.name || '');
            setFileSize(selectedFile?.size || 0);
          }}
          type="file"
        />
      </label>

      <div className="form-actions full-span">
        <button className="secondary-button" onClick={onCancel} type="button">
          Отмена
        </button>
        <button className="primary-button" type="submit">
          <UploadFileIcon fontSize="small" />
          <span>Загрузить</span>
        </button>
      </div>
    </form>
  );
};

export default DocumentForm;
