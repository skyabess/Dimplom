# Архитектура фронтенда для системы автоматизации договоров купли-продажи земли

## Обзор

Документ описывает архитектуру фронтенда системы автоматизации договоров купли-продажи земли, разработанную с использованием React.js и современных подходов к построению масштабируемых веб-приложений.

## Технологический стек

- **Фреймворк**: React 18+ с функциональными компонентами и хуками
- **Менеджер состояний**: Redux Toolkit + RTK Query
- **Маршрутизация**: React Router v6
- **UI библиотека**: Material-UI (MUI) v5
- **Формы**: React Hook Form + Yup для валидации
- **Стили**: Emotion (CSS-in-JS) + MUI theme system
- **Типизация**: TypeScript
- **Сборка**: Vite
- **Тестирование**: Jest + React Testing Library + Cypress
- **Интернационализация**: react-i18next
- **Графики**: Chart.js / Recharts
- **Мапы**: Leaflet / React-Leaflet
- **Загрузка файлов**: react-dropzone
- **Пагинация**: react-paginate
- **Уведомления**: react-toastify

## Архитектурные принципы

1. **Компонентный подход**: Переиспользуемые компоненты с четкой ответственностью
2. **Управление состоянием**: Централизованное состояние с Redux Toolkit
3. **Типизация**: Полная типизация с TypeScript
4. **Производительность**: Оптимизация рендеринга и загрузки
5. **Доступность**: Соответствие WCAG 2.1 AA
6. **Адаптивность**: Mobile-first подход
7. **Безопасность**: Защита от XSS и других уязвимостей

## Структура приложения

```
frontend/
├── public/                     # Статические ресурсы
│   ├── index.html
│   ├── favicon.ico
│   └── manifest.json
├── src/
│   ├── components/             # Переиспользуемые компоненты
│   │   ├── common/            # Общие компоненты
│   │   │   ├── Button/
│   │   │   ├── Input/
│   │   │   ├── Modal/
│   │   │   ├── Table/
│   │   │   └── Layout/
│   │   ├── forms/             # Компоненты форм
│   │   │   ├── ContractForm/
│   │   │   ├── LandPlotForm/
│   │   │   └── UserForm/
│   │   └── charts/            # Компоненты графиков
│   ├── pages/                 # Страницы приложения
│   │   ├── auth/              # Страницы аутентификации
│   │   │   ├── Login/
│   │   │   ├── Register/
│   │   │   └── ForgotPassword/
│   │   ├── dashboard/         # Дашборд
│   │   ├── contracts/         # Управление договорами
│   │   │   ├── ContractList/
│   │   │   ├── ContractDetail/
│   │   │   └── ContractCreate/
│   │   ├── land-plots/        # Управление участками
│   │   ├── documents/         # Управление документами
│   │   ├── profile/           # Профиль пользователя
│   │   └── admin/             # Административные функции
│   ├── store/                 # Redux store
│   │   ├── index.ts           # Конфигурация store
│   │   ├── slices/            # Redux slices
│   │   │   ├── authSlice.ts
│   │   │   ├── contractsSlice.ts
│   │   │   ├── landPlotsSlice.ts
│   │   │   └── uiSlice.ts
│   │   └── api/               # RTK Query API
│   │       ├── authApi.ts
│   │       ├── contractsApi.ts
│   │       └── landPlotsApi.ts
│   ├── hooks/                 # Кастомные хуки
│   │   ├── useAuth.ts
│   │   ├── useLocalStorage.ts
│   │   └── useDebounce.ts
│   ├── utils/                 # Утилиты
│   │   ├── api.ts             # API клиент
│   │   ├── constants.ts       # Константы
│   │   ├── helpers.ts         # Вспомогательные функции
│   │   └── validators.ts      # Валидаторы
│   ├── styles/                # Стили и темы
│   │   ├── theme.ts           # MUI тема
│   │   ├── globals.css        # Глобальные стили
│   │   └── variables.css      # CSS переменные
│   ├── types/                 # TypeScript типы
│   │   ├── api.ts             # API типы
│   │   ├── auth.ts            # Аутентификация типы
│   │   └── contract.ts        # Договор типы
│   ├── assets/                # Статические ресурсы
│   │   ├── images/
│   │   ├── icons/
│   │   └── fonts/
│   ├── locales/               # Файлы локализации
│   │   ├── ru.json
│   │   └── en.json
│   ├── App.tsx                # Корневой компонент
│   ├── index.tsx              # Точка входа
│   └── setupTests.ts          # Конфигурация тестов
├── tests/                     # Тесты
│   ├── __mocks__/             # Моки
│   ├── components/            # Тесты компонентов
│   ├── pages/                 # Тесты страниц
│   └── utils/                 # Тесты утилит
├── cypress/                   # E2E тесты
│   ├── fixtures/
│   ├── integration/
│   └── support/
├── package.json
├── tsconfig.json
├── vite.config.ts
├── .eslintrc.js
├── .prettierrc
└── README.md
```

## Архитектура состояний

### Redux Store Structure

```typescript
interface RootState {
  auth: AuthState;
  contracts: ContractsState;
  landPlots: LandPlotsState;
  documents: DocumentsState;
  ui: UIState;
  api: ApiState;
}
```

### Auth Slice

```typescript
interface AuthState {
  user: User | null;
  token: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}
```

### Contracts Slice

```typescript
interface ContractsState {
  contracts: Contract[];
  currentContract: Contract | null;
  isLoading: boolean;
  error: string | null;
  pagination: {
    page: number;
    limit: number;
    total: number;
  };
  filters: ContractFilters;
}
```

## Компонентная архитектура

### 1. Атомарные компоненты

Базовые компоненты, которые не имеют зависимостей:

```typescript
// components/common/Button/Button.tsx
interface ButtonProps {
  variant?: 'primary' | 'secondary' | 'danger';
  size?: 'small' | 'medium' | 'large';
  disabled?: boolean;
  loading?: boolean;
  onClick?: () => void;
  children: React.ReactNode;
}
```

### 2. Молекулярные компоненты

Компоненты, объединяющие атомарные компоненты:

```typescript
// components/forms/FormField/FormField.tsx
interface FormFieldProps {
  name: string;
  label: string;
  type?: 'text' | 'email' | 'password' | 'number';
  required?: boolean;
  placeholder?: string;
  helperText?: string;
  error?: string;
}
```

### 3. Организмические компоненты

Сложные компоненты, объединяющие молекулярные компоненты:

```typescript
// components/ContractCard/ContractCard.tsx
interface ContractCardProps {
  contract: Contract;
  onView: (id: string) => void;
  onEdit: (id: string) => void;
  onDelete: (id: string) => void;
}
```

## Архитектура маршрутизации

```typescript
// App.tsx
const App = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        
        <Route element={<ProtectedRoute />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/contracts" element={<ContractsPage />} />
          <Route path="/contracts/:id" element={<ContractDetailPage />} />
          <Route path="/contracts/create" element={<ContractCreatePage />} />
          <Route path="/land-plots" element={<LandPlotsPage />} />
          <Route path="/documents" element={<DocumentsPage />} />
          <Route path="/profile" element={<ProfilePage />} />
          
          <Route element={<AdminRoute />}>
            <Route path="/admin" element={<AdminDashboard />} />
            <Route path="/admin/users" element={<UsersManagement />} />
          </Route>
        </Route>
        
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </BrowserRouter>
  );
};
```

## Архитектура API интеграции

### RTK Query API

```typescript
// store/api/contractsApi.ts
export const contractsApi = createApi({
  reducerPath: 'contractsApi',
  baseQuery: fetchBaseQuery({
    baseUrl: '/api/v1/contracts/',
    prepareHeaders: (headers, { getState }) => {
      const token = (getState() as RootState).auth.token;
      if (token) {
        headers.set('authorization', `Bearer ${token}`);
      }
      return headers;
    },
  }),
  tagTypes: ['Contract'],
  endpoints: (builder) => ({
    getContracts: builder.query<ContractsResponse, ContractsParams>({
      query: (params) => ({
        url: '',
        params,
      }),
      providesTags: ['Contract'],
    }),
    getContract: builder.query<Contract, string>({
      query: (id) => `${id}`,
      providesTags: (result, error, id) => [{ type: 'Contract', id }],
    }),
    createContract: builder.mutation<Contract, Partial<Contract>>({
      query: (contract) => ({
        url: '',
        method: 'POST',
        body: contract,
      }),
      invalidatesTags: ['Contract'],
    }),
    updateContract: builder.mutation<Contract, { id: string; contract: Partial<Contract> }>({
      query: ({ id, contract }) => ({
        url: `${id}`,
        method: 'PUT',
        body: contract,
      }),
      invalidatesTags: (result, error, { id }) => [{ type: 'Contract', id }],
    }),
    deleteContract: builder.mutation<void, string>({
      query: (id) => ({
        url: `${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Contract'],
    }),
  }),
});
```

## Архитектура форм

### React Hook Form + Yup

```typescript
// components/forms/ContractForm/ContractForm.tsx
interface ContractFormData {
  title: string;
  description: string;
  landPlotId: string;
  sellerId: string;
  buyerId: string;
  price: number;
  currency: string;
  startDate: string;
  endDate: string;
}

const contractSchema = yup.object().shape({
  title: yup.string().required('Название обязательно'),
  description: yup.string().required('Описание обязательно'),
  landPlotId: yup.string().required('Участок обязателен'),
  sellerId: yup.string().required('Продавец обязателен'),
  buyerId: yup.string().required('Покупатель обязателен'),
  price: yup.number().positive('Цена должна быть положительной').required('Цена обязательна'),
  currency: yup.string().required('Валюта обязательна'),
  startDate: yup.date().required('Дата начала обязательна'),
  endDate: yup.date().min(yup.ref('startDate'), 'Дата окончания должна быть после даты начала').required('Дата окончания обязательна'),
});

const ContractForm: React.FC = () => {
  const { control, handleSubmit, formState: { errors } } = useForm<ContractFormData>({
    resolver: yupResolver(contractSchema),
    defaultValues: {
      title: '',
      description: '',
      landPlotId: '',
      sellerId: '',
      buyerId: '',
      price: 0,
      currency: 'RUB',
      startDate: new Date().toISOString().split('T')[0],
      endDate: '',
    },
  });

  const [createContract, { isLoading }] = useCreateContractMutation();

  const onSubmit = async (data: ContractFormData) => {
    try {
      await createContract(data).unwrap();
      toast.success('Договор создан успешно');
    } catch (error) {
      toast.error('Ошибка при создании договора');
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <Controller
        name="title"
        control={control}
        render={({ field }) => (
          <TextField
            {...field}
            label="Название договора"
            error={!!errors.title}
            helperText={errors.title?.message}
            fullWidth
            margin="normal"
          />
        )}
      />
      {/* Другие поля формы */}
      <Button
        type="submit"
        variant="primary"
        loading={isLoading}
        fullWidth
      >
        Создать договор
      </Button>
    </form>
  );
};
```

## Архитектура тем и стилей

### MUI Theme Configuration

```typescript
// styles/theme.ts
import { createTheme } from '@mui/material/styles';

export const lightTheme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
      light: '#42a5f5',
      dark: '#1565c0',
    },
    secondary: {
      main: '#dc004e',
    },
    background: {
      default: '#f5f5f5',
      paper: '#ffffff',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    h1: {
      fontSize: '2.5rem',
      fontWeight: 500,
    },
    h2: {
      fontSize: '2rem',
      fontWeight: 500,
    },
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          borderRadius: 8,
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
        },
      },
    },
  },
});

export const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#90caf9',
    },
    background: {
      default: '#121212',
      paper: '#1e1e1e',
    },
  },
});
```

## Архитектура производительности

### 1. Код-сплиттинг

```typescript
// Ленивая загрузка компонентов
const ContractsPage = lazy(() => import('../pages/contracts/ContractsPage'));
const ContractDetailPage = lazy(() => import('../pages/contracts/ContractDetailPage'));

// Использование Suspense
<Suspense fallback={<CircularProgress />}>
  <Routes>
    <Route path="/contracts" element={<ContractsPage />} />
    <Route path="/contracts/:id" element={<ContractDetailPage />} />
  </Routes>
</Suspense>
```

### 2. Мемоизация компонентов

```typescript
// Использование React.memo
const ContractCard = React.memo(({ contract, onView, onEdit, onDelete }: ContractCardProps) => {
  return (
    <Card>
      {/* Контент карточки */}
    </Card>
  );
});

// Использование useMemo и useCallback
const ContractsList: React.FC = () => {
  const { contracts, isLoading } = useSelector((state: RootState) => state.contracts);
  
  const filteredContracts = useMemo(() => {
    return contracts.filter(contract => contract.status === 'active');
  }, [contracts]);

  const handleView = useCallback((id: string) => {
    // Обработка просмотра
  }, []);

  return (
    <Grid container spacing={2}>
      {filteredContracts.map(contract => (
        <Grid item xs={12} sm={6} md={4} key={contract.id}>
          <ContractCard
            contract={contract}
            onView={handleView}
          />
        </Grid>
      ))}
    </Grid>
  );
};
```

### 3. Виртуализация списков

```typescript
// Использование react-window для больших списков
import { FixedSizeList as List } from 'react-window';

const VirtualizedContractsList: React.FC = () => {
  const { contracts } = useSelector((state: RootState) => state.contracts);

  const Row = ({ index, style }: { index: number; style: React.CSSProperties }) => (
    <div style={style}>
      <ContractCard contract={contracts[index]} />
    </div>
  );

  return (
    <List
      height={600}
      itemCount={contracts.length}
      itemSize={200}
    >
      {Row}
    </List>
  );
};
```

## Архитектура безопасности

### 1. Защита от XSS

```typescript
// Использование DOMPurify для очистки HTML
import DOMPurify from 'dompurify';

const SafeHTML: React.FC<{ html: string }> = ({ html }) => {
  const cleanHTML = DOMPurify.sanitize(html);
  return <div dangerouslySetInnerHTML={{ __html: cleanHTML }} />;
};
```

### 2. Защита CSRF

```typescript
// Добавление CSRF токена к запросам
const api = createApi({
  baseQuery: fetchBaseQuery({
    baseUrl: '/api/v1/',
    prepareHeaders: (headers, { getState }) => {
      const token = (getState() as RootState).auth.token;
      const csrfToken = getCookie('csrftoken');
      
      if (token) {
        headers.set('authorization', `Bearer ${token}`);
      }
      if (csrfToken) {
        headers.set('X-CSRFToken', csrfToken);
      }
      
      return headers;
    },
  }),
});
```

### 3. Безопасное хранение токенов

```typescript
// Использование httpOnly cookies для токенов
const useAuth = () => {
  const dispatch = useAppDispatch();
  
  const login = async (credentials: LoginCredentials) => {
    try {
      const response = await authApi.login(credentials);
      // Токен сохраняется в httpOnly cookie бэкендом
      dispatch(setAuth(response.user));
    } catch (error) {
      dispatch(setAuthError(error.message));
    }
  };
  
  return { login };
};
```

## Архитектура тестирования

### 1. Unit тесты

```typescript
// tests/components/Button/Button.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { Button } from './Button';

describe('Button', () => {
  it('renders correctly', () => {
    render(<Button>Click me</Button>);
    expect(screen.getByText('Click me')).toBeInTheDocument();
  });

  it('calls onClick when clicked', () => {
    const handleClick = jest.fn();
    render(<Button onClick={handleClick}>Click me</Button>);
    
    fireEvent.click(screen.getByText('Click me'));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('is disabled when disabled prop is true', () => {
    render(<Button disabled>Click me</Button>);
    expect(screen.getByText('Click me')).toBeDisabled();
  });
});
```

### 2. Интеграционные тесты

```typescript
// tests/pages/ContractCreate/ContractCreate.test.tsx
import { render, screen, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { BrowserRouter } from 'react-router-dom';
import { store } from '../../../store';
import { ContractCreatePage } from './ContractCreate';

const renderWithProviders = (component: React.ReactElement) => {
  return render(
    <Provider store={store}>
      <BrowserRouter>
        {component}
      </BrowserRouter>
    </Provider>
  );
};

describe('ContractCreatePage', () => {
  it('renders form correctly', () => {
    renderWithProviders(<ContractCreatePage />);
    
    expect(screen.getByLabelText('Название договора')).toBeInTheDocument();
    expect(screen.getByLabelText('Описание')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Создать договор' })).toBeInTheDocument();
  });

  it('submits form with valid data', async () => {
    renderWithProviders(<ContractCreatePage />);
    
    fireEvent.change(screen.getByLabelText('Название договора'), {
      target: { value: 'Test Contract' }
    });
    
    fireEvent.click(screen.getByRole('button', { name: 'Создать договор' }));
    
    await waitFor(() => {
      expect(screen.getByText('Договор создан успешно')).toBeInTheDocument();
    });
  });
});
```

### 3. E2E тесты

```typescript
// cypress/integration/contract.spec.ts
describe('Contract Management', () => {
  beforeEach(() => {
    cy.login('test@example.com', 'password');
    cy.visit('/contracts');
  });

  it('should create a new contract', () => {
    cy.get('[data-testid="create-contract-button"]').click();
    cy.get('[data-testid="contract-title"]').type('Test Contract');
    cy.get('[data-testid="contract-description"]').type('Test Description');
    cy.get('[data-testid="contract-price"]').type('100000');
    cy.get('[data-testid="submit-button"]').click();
    
    cy.url().should('include', '/contracts/');
    cy.contains('Test Contract').should('be.visible');
  });

  it('should view contract details', () => {
    cy.get('[data-testid="contract-card"]').first().click();
    cy.get('[data-testid="contract-details"]').should('be.visible');
    cy.get('[data-testid="contract-title"]').should('contain', 'Test Contract');
  });
});
```

## Архитектура интернационализации

```typescript
// locales/ru.json
{
  "common": {
    "save": "Сохранить",
    "cancel": "Отмена",
    "delete": "Удалить",
    "edit": "Редактировать"
  },
  "contracts": {
    "title": "Договоры",
    "create": "Создать договор",
    "edit": "Редактировать договор",
    "delete": "Удалить договор",
    "fields": {
      "title": "Название договора",
      "description": "Описание",
      "price": "Цена",
      "status": "Статус"
    }
  }
}

// Использование в компонентах
import { useTranslation } from 'react-i18next';

const ContractForm: React.FC = () => {
  const { t } = useTranslation();
  
  return (
    <form>
      <TextField label={t('contracts.fields.title')} />
      <TextField label={t('contracts.fields.description')} />
      <Button>{t('common.save')}</Button>
    </form>
  );
};
```

## Заключение

Архитектура фронтенда спроектирована с учетом современных подходов к разработке веб-приложений, обеспечивая масштабируемость, производительность и поддерживаемость кода. Компонентный подход, централизованное управление состоянием и полная типизация позволяют создавать надежные и расширяемые пользовательские интерфейсы для системы автоматизации договоров купли-продажи земли.