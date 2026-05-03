import { FormEvent, useEffect, useMemo, useState } from 'react';
import './App.css';

type UserProfile = {
  id: string;
  email: string;
  first_name?: string;
  last_name?: string;
  full_name?: string;
};

type ApiContract = {
  id: string;
  title: string;
  cadastral?: string;
  cadastral_number?: string;
  buyer?: { full_name?: string; email?: string } | string;
  seller?: { full_name?: string; email?: string } | string;
  land_plot?: { cadastral_number?: string; address?: string };
  price?: string | number;
  currency?: string;
  status?: string;
};

type ApiLandPlot = {
  id?: string;
  cadastral_number?: string;
  region_name?: string;
  district_name?: string;
  area?: string | number;
  purpose_name?: string;
  is_verified?: boolean;
};

type ContractRow = {
  id: string;
  number: string;
  title: string;
  cadastral: string;
  buyer: string;
  amount: string;
  status: string;
  statusClass: string;
};

type LoginForm = {
  email: string;
  password: string;
};

type RegisterForm = LoginForm & {
  username: string;
  first_name: string;
  last_name: string;
  password_confirm: string;
  phone: string;
};

const sampleContracts: ContractRow[] = [
  {
    id: 'demo-1',
    number: 'DK-2026-014',
    title: 'Продажа участка под ИЖС',
    cadastral: '50:21:0040201:814',
    buyer: 'ООО Северный Берег',
    amount: '8 450 000 ₽',
    status: 'На подписании',
    statusClass: 'warning',
  },
  {
    id: 'demo-2',
    number: 'DK-2026-011',
    title: 'Аренда муниципальной земли',
    cadastral: '77:18:0004028:221',
    buyer: 'ИП Ковалев А. М.',
    amount: '1 920 000 ₽',
    status: 'Активен',
    statusClass: 'success',
  },
  {
    id: 'demo-3',
    number: 'DK-2026-009',
    title: 'Предварительный договор',
    cadastral: '23:43:0125001:109',
    buyer: 'Маркова Елена',
    amount: '5 300 000 ₽',
    status: 'Проверка',
    statusClass: 'info',
  },
];

const sampleLandPlots = [
  ['50:21:0040201:814', 'Московская область', '1 840 м²', 'ИЖС', 'Проверен'],
  ['77:18:0004028:221', 'Москва', '620 м²', 'Коммерция', 'Ожидает'],
  ['23:43:0125001:109', 'Краснодарский край', '3 100 м²', 'С/х', 'Проверен'],
];

const tasks = [
  'Проверить документы продавца',
  'Запросить выписку ЕГРН',
  'Подготовить договор к подписанию',
  'Согласовать график оплаты',
];

const API_BASE = '/api';
const tokenKey = 'land_contract_access';
const refreshKey = 'land_contract_refresh';
const sessionKey = 'land_contract_session';

function getStoredToken() {
  return localStorage.getItem(tokenKey) || '';
}

async function apiRequest<T>(path: string, options: RequestInit = {}, token = getStoredToken()): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  const contentType = response.headers.get('content-type') || '';
  const payload = contentType.includes('application/json') ? await response.json() : await response.text();

  if (!response.ok) {
    const message = typeof payload === 'string'
      ? payload
      : payload.detail || payload.error || Object.values(payload).flat().join(' ');
    throw new Error(message || `Ошибка API ${response.status}`);
  }

  return payload as T;
}

function normalizeList<T>(payload: T[] | { results?: T[] }): T[] {
  return Array.isArray(payload) ? payload : payload.results || [];
}

function formatMoney(value?: string | number, currency = 'RUB') {
  if (value === undefined || value === null || value === '') {
    return 'Не указано';
  }

  const amount = Number(value);
  if (Number.isNaN(amount)) {
    return String(value);
  }

  return new Intl.NumberFormat('ru-RU', {
    style: 'currency',
    currency,
    maximumFractionDigits: 0,
  }).format(amount);
}

function personName(value: ApiContract['buyer']) {
  if (!value) return 'Не указан';
  if (typeof value === 'string') return value;
  return value.full_name || value.email || 'Не указан';
}

function statusClass(status = '') {
  if (['active', 'signed', 'completed'].includes(status)) return 'success';
  if (['draft', 'pending_approval', 'pending_signature'].includes(status)) return 'warning';
  return 'info';
}

function statusLabel(status = '') {
  const labels: Record<string, string> = {
    draft: 'Черновик',
    pending_approval: 'На проверке',
    pending_signature: 'На подписании',
    signed: 'Подписан',
    active: 'Активен',
    completed: 'Завершен',
    cancelled: 'Отменен',
    terminated: 'Расторгнут',
  };

  return labels[status] || status || 'Без статуса';
}

function mapContract(contract: ApiContract, index: number): ContractRow {
  return {
    id: contract.id || `contract-${index}`,
    number: `DK-${String(index + 1).padStart(3, '0')}`,
    title: contract.title || 'Договор без названия',
    cadastral: contract.land_plot?.cadastral_number || contract.cadastral_number || contract.cadastral || 'Кадастр не указан',
    buyer: personName(contract.buyer),
    amount: formatMoney(contract.price, contract.currency || 'RUB'),
    status: statusLabel(contract.status),
    statusClass: statusClass(contract.status),
  };
}

function mapLandPlot(plot: ApiLandPlot) {
  return [
    plot.cadastral_number || 'Не указан',
    plot.region_name || plot.district_name || 'Не указан',
    plot.area ? `${plot.area} м²` : 'Не указана',
    plot.purpose_name || 'Не указано',
    plot.is_verified ? 'Проверен' : 'Ожидает',
  ];
}

function App() {
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [loginForm, setLoginForm] = useState<LoginForm>({ email: '', password: '' });
  const [registerForm, setRegisterForm] = useState<RegisterForm>({
    email: '',
    password: '',
    username: '',
    first_name: '',
    last_name: '',
    password_confirm: '',
    phone: '',
  });
  const [user, setUser] = useState<UserProfile | null>(null);
  const [contracts, setContracts] = useState<ContractRow[]>(sampleContracts);
  const [landPlots, setLandPlots] = useState<string[][]>(sampleLandPlots);
  const [selectedContractId, setSelectedContractId] = useState(sampleContracts[0].id);
  const [loading, setLoading] = useState(false);
  const [workspaceLoading, setWorkspaceLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('Демо-данные будут заменены данными из API после входа.');

  const selectedContract = useMemo(
    () => contracts.find((contract) => contract.id === selectedContractId) || contracts[0],
    [contracts, selectedContractId],
  );

  useEffect(() => {
    const token = getStoredToken();
    if (!token) return;

    apiRequest<UserProfile>('/auth/profile/', {}, token)
      .then((profile) => {
        setUser(profile);
        loadWorkspace(token);
      })
      .catch(() => {
        clearSession();
      });
  }, []);

  async function loadWorkspace(token = getStoredToken()) {
    if (!token) return;

    setWorkspaceLoading(true);
    try {
      const [contractsPayload, landPlotsPayload] = await Promise.allSettled([
        apiRequest<ApiContract[] | { results?: ApiContract[] }>('/contracts/', {}, token),
        apiRequest<ApiLandPlot[] | { results?: ApiLandPlot[] }>('/land-plots/plots/', {}, token),
      ]);

      if (contractsPayload.status === 'fulfilled') {
        const nextContracts = normalizeList(contractsPayload.value).map(mapContract);
        if (nextContracts.length) {
          setContracts(nextContracts);
          setSelectedContractId(nextContracts[0].id);
        }
      }

      if (landPlotsPayload.status === 'fulfilled') {
        const nextLandPlots = normalizeList(landPlotsPayload.value).map(mapLandPlot);
        if (nextLandPlots.length) {
          setLandPlots(nextLandPlots);
        }
      }

      setNotice('Данные обновлены. Если списки пустые, показаны демо-строки для ориентира.');
    } catch (requestError) {
      setNotice(requestError instanceof Error ? requestError.message : 'Не удалось загрузить рабочие данные');
    } finally {
      setWorkspaceLoading(false);
    }
  }

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError('');

    try {
      const result = await apiRequest<{
        access: string;
        refresh: string;
        session_id?: string;
        user: UserProfile;
      }>('/auth/login/', {
        method: 'POST',
        body: JSON.stringify(loginForm),
      }, '');

      saveSession(result.access, result.refresh, result.session_id);
      setUser(result.user);
      setNotice('Вход выполнен. Загружаю данные кабинета.');
      await loadWorkspace(result.access);
    } catch (loginError) {
      setError(loginError instanceof Error ? loginError.message : 'Не удалось войти');
    } finally {
      setLoading(false);
    }
  }

  async function handleRegister(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError('');

    const username = registerForm.username || registerForm.email.split('@')[0];

    try {
      const result = await apiRequest<{
        access: string;
        refresh: string;
        user: UserProfile;
      }>('/auth/register/', {
        method: 'POST',
        body: JSON.stringify({
          ...registerForm,
          username,
          phone: registerForm.phone || null,
        }),
      }, '');

      saveSession(result.access, result.refresh);
      setUser(result.user);
      setNotice('Аккаунт создан. Кабинет готов к работе.');
      await loadWorkspace(result.access);
    } catch (registerError) {
      setError(registerError instanceof Error ? registerError.message : 'Не удалось зарегистрироваться');
    } finally {
      setLoading(false);
    }
  }

  async function handleLogout() {
    const sessionId = localStorage.getItem(sessionKey);
    try {
      if (getStoredToken()) {
        await apiRequest('/auth/logout/', {
          method: 'POST',
          body: JSON.stringify({ session_id: sessionId }),
        });
      }
    } catch {
      // Logout should clear the client even if the API token is already stale.
    }

    clearSession();
    setNotice('Вы вышли из системы.');
  }

  function saveSession(access: string, refresh: string, sessionId?: string) {
    localStorage.setItem(tokenKey, access);
    localStorage.setItem(refreshKey, refresh);
    if (sessionId) {
      localStorage.setItem(sessionKey, String(sessionId));
    }
  }

  function clearSession() {
    localStorage.removeItem(tokenKey);
    localStorage.removeItem(refreshKey);
    localStorage.removeItem(sessionKey);
    setUser(null);
    setLoginForm({ email: '', password: '' });
  }

  if (!user) {
    return (
      <main className="auth-page">
        <section className="auth-card">
          <div className="brand auth-brand">
            <div className="brand-mark">LC</div>
            <div>
              <strong>Land Contracts</strong>
              <span>система земельных сделок</span>
            </div>
          </div>

          <div className="auth-tabs">
            <button className={authMode === 'login' ? 'active' : ''} onClick={() => setAuthMode('login')}>
              Вход
            </button>
            <button className={authMode === 'register' ? 'active' : ''} onClick={() => setAuthMode('register')}>
              Регистрация
            </button>
          </div>

          {error && <div className="alert error">{error}</div>}
          <div className="alert info">API: {API_BASE}. После входа кабинет загрузит профиль, договоры и участки.</div>

          {authMode === 'login' ? (
            <form className="auth-form" onSubmit={handleLogin}>
              <label>
                Email
                <input
                  type="email"
                  value={loginForm.email}
                  onChange={(event) => setLoginForm({ ...loginForm, email: event.target.value })}
                  required
                />
              </label>
              <label>
                Пароль
                <input
                  type="password"
                  value={loginForm.password}
                  onChange={(event) => setLoginForm({ ...loginForm, password: event.target.value })}
                  required
                />
              </label>
              <button className="primary-button full-width" disabled={loading}>
                {loading ? 'Входим...' : 'Войти'}
              </button>
            </form>
          ) : (
            <form className="auth-form" onSubmit={handleRegister}>
              <div className="form-grid">
                <label>
                  Имя
                  <input
                    value={registerForm.first_name}
                    onChange={(event) => setRegisterForm({ ...registerForm, first_name: event.target.value })}
                    required
                  />
                </label>
                <label>
                  Фамилия
                  <input
                    value={registerForm.last_name}
                    onChange={(event) => setRegisterForm({ ...registerForm, last_name: event.target.value })}
                    required
                  />
                </label>
              </div>
              <label>
                Email
                <input
                  type="email"
                  value={registerForm.email}
                  onChange={(event) => setRegisterForm({ ...registerForm, email: event.target.value })}
                  required
                />
              </label>
              <label>
                Логин
                <input
                  value={registerForm.username}
                  onChange={(event) => setRegisterForm({ ...registerForm, username: event.target.value })}
                  placeholder="Можно оставить пустым"
                />
              </label>
              <label>
                Телефон
                <input
                  value={registerForm.phone}
                  onChange={(event) => setRegisterForm({ ...registerForm, phone: event.target.value })}
                  placeholder="+79990000000"
                />
              </label>
              <div className="form-grid">
                <label>
                  Пароль
                  <input
                    type="password"
                    value={registerForm.password}
                    onChange={(event) => setRegisterForm({ ...registerForm, password: event.target.value })}
                    required
                  />
                </label>
                <label>
                  Повтор
                  <input
                    type="password"
                    value={registerForm.password_confirm}
                    onChange={(event) => setRegisterForm({ ...registerForm, password_confirm: event.target.value })}
                    required
                  />
                </label>
              </div>
              <button className="primary-button full-width" disabled={loading}>
                {loading ? 'Создаем...' : 'Создать аккаунт'}
              </button>
            </form>
          )}
        </section>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">LC</div>
          <div>
            <strong>Land Contracts</strong>
            <span>кабинет сделок</span>
          </div>
        </div>

        <nav className="nav-list" aria-label="Главная навигация">
          <button className="nav-item active">Обзор</button>
          <button className="nav-item" onClick={() => setNotice('Раздел договоров открыт в центральной панели.')}>Договоры</button>
          <button className="nav-item" onClick={() => setNotice('Таблица участков находится ниже договоров.')}>Участки</button>
          <button className="nav-item" onClick={() => setNotice('Карточка текущего пользователя показана вверху справа.')}>Клиенты</button>
          <button className="nav-item" onClick={() => setNotice('Загрузка документов подключается к выбранному договору.')}>Документы</button>
          <button className="nav-item" onClick={() => setNotice('Отчеты будут строиться по данным договоров и участков.')}>Отчеты</button>
        </nav>

        <div className="sidebar-note">
          <span>Пользователь</span>
          <strong>{user.full_name || `${user.first_name || ''} ${user.last_name || ''}`.trim() || user.email}</strong>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Система управления земельными контрактами</p>
            <h1>Рабочий стол</h1>
          </div>
          <div className="topbar-actions">
            <button className="secondary-button" onClick={() => loadWorkspace()}>
              {workspaceLoading ? 'Обновляем...' : 'Обновить'}
            </button>
            <button className="secondary-button" onClick={() => setNotice('Импорт ЕГРН готов к подключению к API интеграций.')}>Импорт ЕГРН</button>
            <button className="primary-button" onClick={() => setNotice('Создание договора требует выбранного участка, продавца и покупателя.')}>Новый договор</button>
            <button className="danger-button" onClick={handleLogout}>Выйти</button>
          </div>
        </header>

        {notice && <div className="alert info workspace-alert">{notice}</div>}

        <section className="metrics-grid" aria-label="Ключевые показатели">
          <article className="metric-card">
            <span>Договоры в списке</span>
            <strong>{contracts.length}</strong>
            <small>{contracts === sampleContracts ? 'демо-данные' : 'из API'}</small>
          </article>
          <article className="metric-card">
            <span>Сумма сделок</span>
            <strong>184,2 млн ₽</strong>
            <small>расчетный показатель</small>
          </article>
          <article className="metric-card">
            <span>Участки</span>
            <strong>{landPlots.length}</strong>
            <small>{landPlots === sampleLandPlots ? 'демо-данные' : 'из API'}</small>
          </article>
          <article className="metric-card">
            <span>Подписания</span>
            <strong>{contracts.filter((contract) => contract.statusClass === 'warning').length}</strong>
            <small>требуют внимания</small>
          </article>
        </section>

        <section className="content-grid">
          <article className="panel contracts-panel">
            <div className="panel-header">
              <div>
                <h2>Договоры</h2>
                <p>Последние сделки и статусы согласования</p>
              </div>
              <button className="text-button" onClick={() => loadWorkspace()}>Все договоры</button>
            </div>

            <div className="contracts-list">
              {contracts.map((contract) => (
                <div className="contract-row" key={contract.id}>
                  <div>
                    <strong>{contract.title}</strong>
                    <span>{contract.number} · {contract.cadastral}</span>
                  </div>
                  <div className="contract-meta">
                    <span>{contract.buyer}</span>
                    <strong>{contract.amount}</strong>
                  </div>
                  <span className={`status-pill ${contract.statusClass}`}>{contract.status}</span>
                  <button className="row-action" onClick={() => setSelectedContractId(contract.id)}>Открыть</button>
                </div>
              ))}
            </div>
          </article>

          <article className="panel action-panel">
            <div className="panel-header compact">
              <h2>Выбранный договор</h2>
            </div>
            {selectedContract && (
              <div className="detail-card">
                <strong>{selectedContract.title}</strong>
                <span>{selectedContract.cadastral}</span>
                <span>{selectedContract.buyer}</span>
                <b>{selectedContract.amount}</b>
              </div>
            )}
            <div className="quick-actions">
              <button onClick={() => setNotice('Форма создания участка будет отправлять POST /api/land-plots/plots/.')}>Создать участок</button>
              <button onClick={() => setNotice('Загрузка документа требует выбранного договора или участка.')}>Загрузить документ</button>
              <button onClick={() => setNotice('Проверка назначена локально. API задач можно добавить следующим шагом.')}>Назначить проверку</button>
              <button onClick={() => window.print()}>Сформировать отчет</button>
            </div>
          </article>

          <article className="panel">
            <div className="panel-header">
              <div>
                <h2>Земельные участки</h2>
                <p>Кадастровые объекты в работе</p>
              </div>
            </div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Кадастр</th>
                  <th>Регион</th>
                  <th>Площадь</th>
                  <th>Назначение</th>
                  <th>Статус</th>
                </tr>
              </thead>
              <tbody>
                {landPlots.map((plot) => (
                  <tr key={plot[0]}>
                    {plot.map((value) => <td key={value}>{value}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </article>

          <article className="panel">
            <div className="panel-header compact">
              <h2>Задачи</h2>
              <button className="text-button" onClick={() => setNotice('Новая задача добавляется локально до подключения API задач.')}>Добавить</button>
            </div>
            <div className="task-list">
              {tasks.map((task, index) => (
                <label className="task-item" key={task}>
                  <input type="checkbox" defaultChecked={index === 0} />
                  <span>{task}</span>
                </label>
              ))}
            </div>
          </article>
        </section>
      </main>
    </div>
  );
}

export default App;
