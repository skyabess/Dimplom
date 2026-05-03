import './App.css';

const contracts = [
  {
    number: 'DK-2026-014',
    title: 'Продажа участка под ИЖС',
    cadastral: '50:21:0040201:814',
    buyer: 'ООО Северный Берег',
    amount: '8 450 000 ₽',
    status: 'На подписании',
    statusClass: 'warning',
  },
  {
    number: 'DK-2026-011',
    title: 'Аренда муниципальной земли',
    cadastral: '77:18:0004028:221',
    buyer: 'ИП Ковалев А. М.',
    amount: '1 920 000 ₽',
    status: 'Активен',
    statusClass: 'success',
  },
  {
    number: 'DK-2026-009',
    title: 'Предварительный договор',
    cadastral: '23:43:0125001:109',
    buyer: 'Маркова Елена',
    amount: '5 300 000 ₽',
    status: 'Проверка',
    statusClass: 'info',
  },
];

const landPlots = [
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

function App() {
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
          <button className="nav-item">Договоры</button>
          <button className="nav-item">Участки</button>
          <button className="nav-item">Клиенты</button>
          <button className="nav-item">Документы</button>
          <button className="nav-item">Отчеты</button>
        </nav>

        <div className="sidebar-note">
          <span>Сегодня</span>
          <strong>7 действий требуют внимания</strong>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Система управления земельными контрактами</p>
            <h1>Рабочий стол</h1>
          </div>
          <div className="topbar-actions">
            <button className="icon-button" aria-label="Поиск">⌕</button>
            <button className="secondary-button">Импорт ЕГРН</button>
            <button className="primary-button">Новый договор</button>
          </div>
        </header>

        <section className="metrics-grid" aria-label="Ключевые показатели">
          <article className="metric-card">
            <span>Активные договоры</span>
            <strong>38</strong>
            <small>+6 за неделю</small>
          </article>
          <article className="metric-card">
            <span>Сумма сделок</span>
            <strong>184,2 млн ₽</strong>
            <small>12 сделок в работе</small>
          </article>
          <article className="metric-card">
            <span>Участки на проверке</span>
            <strong>14</strong>
            <small>4 ожидают ЕГРН</small>
          </article>
          <article className="metric-card">
            <span>Подписания</span>
            <strong>9</strong>
            <small>3 истекают сегодня</small>
          </article>
        </section>

        <section className="content-grid">
          <article className="panel contracts-panel">
            <div className="panel-header">
              <div>
                <h2>Договоры</h2>
                <p>Последние сделки и статусы согласования</p>
              </div>
              <button className="text-button">Все договоры</button>
            </div>

            <div className="contracts-list">
              {contracts.map((contract) => (
                <div className="contract-row" key={contract.number}>
                  <div>
                    <strong>{contract.title}</strong>
                    <span>{contract.number} · {contract.cadastral}</span>
                  </div>
                  <div className="contract-meta">
                    <span>{contract.buyer}</span>
                    <strong>{contract.amount}</strong>
                  </div>
                  <span className={`status-pill ${contract.statusClass}`}>{contract.status}</span>
                  <button className="row-action">Открыть</button>
                </div>
              ))}
            </div>
          </article>

          <article className="panel action-panel">
            <div className="panel-header compact">
              <h2>Быстрые действия</h2>
            </div>
            <div className="quick-actions">
              <button>Создать участок</button>
              <button>Загрузить документ</button>
              <button>Назначить проверку</button>
              <button>Сформировать отчет</button>
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
              <button className="text-button">Добавить</button>
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
