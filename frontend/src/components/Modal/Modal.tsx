import CloseIcon from '@mui/icons-material/Close';
import { ReactNode, useEffect } from 'react';

interface ModalProps {
  title: string;
  children: ReactNode;
  open: boolean;
  onClose: () => void;
  width?: 'medium' | 'wide';
}

const Modal = ({ title, children, open, onClose, width = 'medium' }: ModalProps) => {
  useEffect(() => {
    if (!open) {
      return;
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  if (!open) {
    return null;
  }

  return (
    <div className="modal-backdrop" role="presentation">
      <section
        aria-modal="true"
        className={`modal-panel ${width}`}
        role="dialog"
      >
        <header className="modal-header">
          <h2>{title}</h2>
          <button aria-label="Закрыть" className="icon-action" onClick={onClose} type="button">
            <CloseIcon fontSize="small" />
          </button>
        </header>
        {children}
      </section>
    </div>
  );
};

export default Modal;
