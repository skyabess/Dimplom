import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import UploadFileIcon from '@mui/icons-material/UploadFile';
import { Contract, DocumentItem } from '../../types/contract';
import { formatDate, formatFileSize } from '../../utils/formatters';
import { documentStatusMeta, documentTypeLabel } from '../../utils/status';

interface DocumentPanelProps {
  documents: DocumentItem[];
  contracts: Contract[];
  onUpload: () => void;
  onApprove: (id: string) => void;
}

const DocumentPanel = ({ documents, contracts, onUpload, onApprove }: DocumentPanelProps) => (
  <section className="panel">
    <div className="panel-header">
      <div>
        <h2>Документы</h2>
        <p>Загруженные файлы, проверка и привязка к сделкам</p>
      </div>
      <button className="icon-text-button" onClick={onUpload} type="button">
        <UploadFileIcon fontSize="small" />
        <span>Загрузить</span>
      </button>
    </div>

    {documents.length > 0 ? (
      <div className="document-list">
        {documents.map((document) => {
          const contract = contracts.find((item) => item.id === document.contractId);
          const status = documentStatusMeta[document.status];

          return (
            <article className="document-item" key={document.id}>
              <div className="document-icon">
                <UploadFileIcon fontSize="small" />
              </div>
              <div>
                <h3>{document.title}</h3>
                <span>
                  {documentTypeLabel[document.documentType]} · {formatFileSize(document.fileSize)} ·{' '}
                  {formatDate(document.uploadedAt)}
                </span>
                {contract && <small>{contract.number} · {contract.title}</small>}
              </div>
              <span className={`status-pill ${status.tone}`}>{status.label}</span>
              <button
                aria-label="Принять документ"
                className="icon-action success"
                disabled={document.status === 'approved'}
                onClick={() => onApprove(document.id)}
                title="Принять"
                type="button"
              >
                <CheckCircleIcon fontSize="small" />
              </button>
            </article>
          );
        })}
      </div>
    ) : (
      <div className="empty-state">Документы не найдены</div>
    )}
  </section>
);

export default DocumentPanel;
