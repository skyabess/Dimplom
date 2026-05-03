import AddIcon from '@mui/icons-material/Add';
import { FormEvent, useState } from 'react';
import { Contract, TaskItem, TaskPriority } from '../../types/contract';
import { formatDate } from '../../utils/formatters';
import { priorityMeta } from '../../utils/status';

interface TaskPanelProps {
  tasks: TaskItem[];
  contracts: Contract[];
  onAddTask: (title: string, priority: TaskPriority, contractId?: string) => void;
  onToggleTask: (id: string) => void;
}

const TaskPanel = ({ tasks, contracts, onAddTask, onToggleTask }: TaskPanelProps) => {
  const [title, setTitle] = useState('');
  const [priority, setPriority] = useState<TaskPriority>('medium');
  const [contractId, setContractId] = useState('');

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();

    if (!title.trim()) {
      return;
    }

    onAddTask(title, priority, contractId || undefined);
    setTitle('');
    setPriority('medium');
  };

  return (
    <section className="panel">
      <div className="panel-header compact">
        <div>
          <h2>Задачи</h2>
          <p>Рабочий список по договорам и проверкам</p>
        </div>
      </div>

      <form className="task-form" onSubmit={handleSubmit}>
        <input
          aria-label="Новая задача"
          onChange={(event) => setTitle(event.target.value)}
          placeholder="Новая задача"
          value={title}
        />
        <select
          aria-label="Приоритет"
          onChange={(event) => setPriority(event.target.value as TaskPriority)}
          value={priority}
        >
          <option value="medium">Средний</option>
          <option value="high">Высокий</option>
          <option value="low">Низкий</option>
        </select>
        <select
          aria-label="Договор"
          onChange={(event) => setContractId(event.target.value)}
          value={contractId}
        >
          <option value="">Без договора</option>
          {contracts.map((contract) => (
            <option key={contract.id} value={contract.id}>
              {contract.number}
            </option>
          ))}
        </select>
        <button className="icon-action success" aria-label="Добавить задачу" type="submit">
          <AddIcon fontSize="small" />
        </button>
      </form>

      <div className="task-list">
        {tasks.map((task) => {
          const linkedContract = contracts.find((contract) => contract.id === task.contractId);

          return (
            <label className={`task-item ${task.completed ? 'done' : ''}`} key={task.id}>
              <input
                checked={task.completed}
                onChange={() => onToggleTask(task.id)}
                type="checkbox"
              />
              <span>
                <strong>{task.title}</strong>
                <small>
                  {linkedContract?.number || 'Общая задача'} · {formatDate(task.dueDate)} · {task.assignee}
                </small>
              </span>
              <em className={`status-pill ${priorityMeta[task.priority].tone}`}>
                {priorityMeta[task.priority].label}
              </em>
            </label>
          );
        })}
      </div>
    </section>
  );
};

export default TaskPanel;
