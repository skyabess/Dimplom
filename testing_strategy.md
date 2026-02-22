# Стратегия тестирования и обеспечения качества для системы автоматизации договоров купли-продажи земли

## Обзор

Документ описывает комплексную стратегию тестирования и обеспечения качества, охватывающую все уровни тестирования от юнит-тестов до приемочного тестирования, с учетом специфики системы автоматизации договоров купли-продажи земли и требований российского законодательства.

## Цели тестирования

1. **Качество функциональности**: Обеспечение соответствия системы бизнес-требованиям
2. **Надежность**: Гарантия стабильной работы в различных условиях
3. **Безопасность**: Проверка защиты данных и соответствия ФЗ-152
4. **Производительность**: Обеспечение приемлемого времени отклика
5. **Совместимость**: Проверка работы в различных браузерах и устройствах
6. **Доступность**: Соответствие WCAG 2.1 AA
7. **Юридическая корректность**: Проверка правильности генерации документов

## Пирамида тестирования

```mermaid
graph TB
    subgraph "Testing Pyramid"
        E2E[E2E Tests<br/>5%]
        INT[Integration Tests<br/>25%]
        UNIT[Unit Tests<br/>70%]
    end
    
    subgraph "Test Types"
        UNIT --> UT1[Component Tests]
        UNIT --> UT2[Service Tests]
        UNIT --> UT3[Utility Tests]
        
        INT --> IT1[API Tests]
        INT --> IT2[Database Tests]
        INT --> IT3[Integration Tests]
        
        E2E --> ET1[User Journey Tests]
        E2E --> ET2[Critical Path Tests]
        E2E --> ET3[Cross-browser Tests]
    end
```

## Стратегия юнит-тестирования

### Backend Unit Tests

**Технологии**: pytest, Django Test Framework, factory_boy, mock

**Покрытие**: Минимум 90% по строкам, 85% по ветвям

```python
# tests/test_models.py
import pytest
from django.test import TestCase
from factory import Faker
from contracts.models import Contract
from contracts.factories import ContractFactory

class TestContractModel(TestCase):
    def setUp(self):
        self.contract = ContractFactory()
    
    def test_contract_creation(self):
        """Тест создания договора"""
        self.assertTrue(isinstance(self.contract, Contract))
        self.assertEqual(self.contract.status, 'draft')
    
    def test_contract_str_representation(self):
        """Тест строкового представления"""
        expected = f"Contract {self.contract.id}"
        self.assertEqual(str(self.contract), expected)
    
    def test_contract_total_amount_calculation(self):
        """Тест расчета общей суммы"""
        expected_amount = self.contract.price + self.contract.additional_fees
        self.assertEqual(self.contract.total_amount, expected_amount)

# tests/test_services.py
import pytest
from unittest.mock import Mock, patch
from contracts.services import ContractService
from contracts.exceptions import ContractValidationError

class TestContractService:
    def setup_method(self):
        self.service = ContractService()
        self.mock_repo = Mock()
        self.service.repository = self.mock_repo
    
    def test_create_contract_success(self):
        """Тест успешного создания договора"""
        contract_data = {
            'title': 'Test Contract',
            'price': 100000,
            'land_plot_id': 'uuid',
            'seller_id': 'uuid',
            'buyer_id': 'uuid'
        }
        
        expected_contract = Mock(id='uuid', **contract_data)
        self.mock_repo.create.return_value = expected_contract
        
        result = self.service.create_contract(contract_data)
        
        self.mock_repo.create.assert_called_once_with(contract_data)
        self.assertEqual(result.id, expected_contract.id)
    
    def test_create_contract_validation_error(self):
        """Тест ошибки валидации при создании договора"""
        invalid_data = {'title': ''}  # Пустое название
        
        with pytest.raises(ContractValidationError):
            self.service.create_contract(invalid_data)
    
    @patch('contracts.services.send_notification')
    def test_contract_approval_notification(self, mock_notification):
        """Тест отправки уведомления при утверждении договора"""
        contract = Mock(id='uuid', status='approved')
        
        self.service.approve_contract(contract.id)
        
        mock_notification.assert_called_once_with(
            recipient=contract.seller_id,
            message='Contract approved'
        )
```

### Frontend Unit Tests

**Технологии**: Jest, React Testing Library, @testing-library/user-event, MSW

**Покрытие**: Минимум 85% по строкам, 80% по ветвям

```typescript
// src/components/ContractCard/ContractCard.test.tsx
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ContractCard } from './ContractCard';
import { Contract } from '../../types/contract';

const mockContract: Contract = {
  id: '1',
  title: 'Test Contract',
  price: 100000,
  status: 'draft',
  createdAt: '2023-01-01T00:00:00Z',
};

describe('ContractCard', () => {
  const mockOnView = jest.fn();
  const mockOnEdit = jest.fn();
  const mockOnDelete = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders contract information correctly', () => {
    render(
      <ContractCard
        contract={mockContract}
        onView={mockOnView}
        onEdit={mockOnEdit}
        onDelete={mockOnDelete}
      />
    );

    expect(screen.getByText('Test Contract')).toBeInTheDocument();
    expect(screen.getByText('100 000 ₽')).toBeInTheDocument();
    expect(screen.getByText('Черновик')).toBeInTheDocument();
  });

  it('calls onView when view button is clicked', () => {
    render(
      <ContractCard
        contract={mockContract}
        onView={mockOnView}
        onEdit={mockOnEdit}
        onDelete={mockOnDelete}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /просмотреть/i }));
    expect(mockOnView).toHaveBeenCalledWith('1');
  });

  it('shows delete confirmation dialog when delete button is clicked', () => {
    render(
      <ContractCard
        contract={mockContract}
        onView={mockOnView}
        onEdit={mockOnEdit}
        onDelete={mockOnDelete}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /удалить/i }));
    expect(screen.getByText(/вы уверены/i)).toBeInTheDocument();
  });
});

// src/hooks/useContracts.test.ts
import { renderHook, act } from '@testing-library/react';
import { Provider } from 'react-redux';
import { store } from '../store';
import { useContracts } from './useContracts';
import { setupServer } from 'msw/node';
import { rest } from 'msw';

const server = setupServer(
  rest.get('/api/v1/contracts/', (req, res, ctx) => {
    return res(ctx.json({
      results: [
        { id: '1', title: 'Contract 1', price: 100000 },
        { id: '2', title: 'Contract 2', price: 200000 },
      ],
      count: 2,
    }));
  })
);

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe('useContracts', () => {
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <Provider store={store}>{children}</Provider>
  );

  it('fetches contracts on mount', async () => {
    const { result } = renderHook(() => useContracts(), { wrapper });

    expect(result.current.isLoading).toBe(true);

    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 0));
    });

    expect(result.current.isLoading).toBe(false);
    expect(result.current.contracts).toHaveLength(2);
  });
});
```

## Стратегия интеграционного тестирования

### API Integration Tests

**Технологии**: pytest, Django Test Framework, requests, factory_boy

```python
# tests/integration/test_api.py
import pytest
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from contracts.factories import ContractFactory, LandPlotFactory
from users.factories import UserFactory

User = get_user_model()

class TestContractAPIIntegration(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory()
        self.client.force_authenticate(user=self.user)
        
        self.land_plot = LandPlotFactory()
        self.contract_data = {
            'title': 'Test Contract',
            'price': 100000,
            'land_plot_id': str(self.land_plot.id),
            'seller_id': str(self.user.id),
            'buyer_id': str(UserFactory().id),
        }

    def test_create_contract_flow(self):
        """Тест полного потока создания договора"""
        # Создание договора
        response = self.client.post('/api/v1/contracts/', self.contract_data)
        self.assertEqual(response.status_code, 201)
        
        contract_id = response.data['id']
        
        # Проверка создания
        response = self.client.get(f'/api/v1/contracts/{contract_id}/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['title'], 'Test Contract')
        
        # Обновление статуса
        response = self.client.patch(
            f'/api/v1/contracts/{contract_id}/',
            {'status': 'approved'}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['status'], 'approved')

    def test_contract_with_documents(self):
        """Тест создания договора с документами"""
        # Создание договора
        response = self.client.post('/api/v1/contracts/', self.contract_data)
        contract_id = response.data['id']
        
        # Загрузка документа
        with open('tests/fixtures/test_document.pdf', 'rb') as f:
            response = self.client.post(
                f'/api/v1/contracts/{contract_id}/documents/',
                {'file': f, 'type': 'contract_draft'},
                format='multipart'
            )
        
        self.assertEqual(response.status_code, 201)
        
        # Проверка наличия документа
        response = self.client.get(f'/api/v1/contracts/{contract_id}/documents/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
```

### Database Integration Tests

```python
# tests/integration/test_database.py
import pytest
from django.test import TestCase, TransactionTestCase
from django.db import transaction
from contracts.models import Contract, LandPlot
from contracts.factories import ContractFactory, LandPlotFactory

class TestDatabaseIntegration(TransactionTestCase):
    def test_contract_land_plot_relationship(self):
        """Тест связи между договором и участком"""
        land_plot = LandPlotFactory()
        contract = ContractFactory(land_plot=land_plot)
        
        # Проверка связи со стороны договора
        self.assertEqual(contract.land_plot.id, land_plot.id)
        
        # Проверка обратной связи
        self.assertIn(contract, land_plot.contracts.all())

    def test_contract_transaction_rollback(self):
        """Тест отката транзакции при ошибке"""
        initial_count = Contract.objects.count()
        
        with transaction.atomic():
            ContractFactory()
            # Вызов исключения для отката
            raise Exception("Test exception")
        
        # Проверка, что количество договоров не изменилось
        self.assertEqual(Contract.objects.count(), initial_count)

    def test_database_constraints(self):
        """Тест ограничений базы данных"""
        land_plot = LandPlotFactory()
        
        # Попытка создания договора с отрицательной ценой
        with self.assertRaises(Exception):
            ContractFactory(
                land_plot=land_plot,
                price=-1000
            )
```

## Стратегия end-to-end тестирования

**Технологии**: Cypress, Docker, TestContainers

```typescript
// cypress/e2e/contract-lifecycle.cy.ts
describe('Contract Lifecycle', () => {
  beforeEach(() => {
    cy.login('seller@example.com', 'password');
    cy.visit('/contracts');
  });

  it('should create and manage contract through full lifecycle', () => {
    // Создание договора
    cy.get('[data-testid="create-contract-btn"]').click();
    cy.get('[data-testid="contract-title"]').type('Test Land Sale Contract');
    cy.get('[data-testid="contract-price"]').type('500000');
    cy.get('[data-testid="land-plot-select"]').select('Test Land Plot');
    cy.get('[data-testid="buyer-select"]').select('Test Buyer');
    cy.get('[data-testid="submit-btn"]').click();
    
    // Проверка создания
    cy.url().should('include', '/contracts/');
    cy.get('[data-testid="contract-card"]').should('contain', 'Test Land Sale Contract');
    cy.get('[data-testid="contract-status"]').should('contain', 'Черновик');
    
    // Загрузка документов
    cy.get('[data-testid="upload-documents-btn"]').click();
    cy.get('[data-testid="file-input"]').attachFile('contract-draft.pdf');
    cy.get('[data-testid="upload-btn"]').click();
    
    // Отправка на подписание
    cy.get('[data-testid="send-for-signing-btn"]').click();
    cy.get('[data-testid="confirm-modal"]').should('be.visible');
    cy.get('[data-testid="confirm-btn"]').click();
    
    // Проверка изменения статуса
    cy.get('[data-testid="contract-status"]').should('contain', 'Ожидает подписания');
    
    // Выход и вход как покупатель
    cy.logout();
    cy.login('buyer@example.com', 'password');
    cy.visit('/contracts');
    
    // Подписание договора
    cy.get('[data-testid="contract-card"]').contains('Test Land Sale Contract').click();
    cy.get('[data-testid="sign-contract-btn"]').click();
    cy.get('[data-testid="signature-input"]').type('Test Signature');
    cy.get('[data-testid="confirm-signature-btn"]').click();
    
    // Проверка финального статуса
    cy.get('[data-testid="contract-status"]').should('contain', 'Подписан');
  });
});

// cypress/e2e/document-generation.cy.ts
describe('Document Generation', () => {
  it('should generate legally correct contract document', () => {
    cy.login('seller@example.com', 'password');
    
    // Создание договора с полными данными
    cy.createContractWithFullData();
    
    // Генерация документа
    cy.get('[data-testid="generate-document-btn"]').click();
    cy.get('[data-testid="document-type-select"]').select('sale_contract');
    cy.get('[data-testid="generate-btn"]').click();
    
    // Проверка содержимого документа
    cy.get('[data-testid="document-preview"]').should('be.visible');
    cy.get('[data-testid="document-content"]').should('contain', 'Договор купли-продажи');
    cy.get('[data-testid="document-content"]').should('contain', 'Продавец:');
    cy.get('[data-testid="document-content"]').should('contain', 'Покупатель:');
    cy.get('[data-testid="document-content"]').should('contain', 'Предмет договора');
    
    // Проверка реквизитов
    cy.get('[data-testid="document-content"]').should('contain', 'ИНН');
    cy.get('[data-testid="document-content"]').should('contain', 'Кадастровый номер');
  });
});
```

## Стратегия производительного тестирования

### Нагрузочное тестирование

**Технологии**: k6, Locust, Artillery

```javascript
// tests/performance/load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');

export let options = {
  stages: [
    { duration: '2m', target: 100 }, // Ramp up to 100 users
    { duration: '5m', target: 100 }, // Stay at 100 users
    { duration: '2m', target: 200 }, // Ramp up to 200 users
    { duration: '5m', target: 200 }, // Stay at 200 users
    { duration: '2m', target: 0 },   // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests under 500ms
    http_req_failed: ['rate<0.1'],    // Error rate under 10%
    errors: ['rate<0.1'],
  },
};

export default function () {
  // Авторизация
  const loginResponse = http.post('https://api.landcontracts.com/api/v1/auth/token/', {
    email: 'test@example.com',
    password: 'password',
  });
  
  const token = loginResponse.json('access');
  
  // Получение списка договоров
  const contractsResponse = http.get('https://api.landcontracts.com/api/v1/contracts/', {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });
  
  const success = check(contractsResponse, {
    'contracts status is 200': (r) => r.status === 200,
    'contracts response time < 500ms': (r) => r.timings.duration < 500,
  });
  
  errorRate.add(!success);
  
  sleep(1);
}
```

### Стресс-тестирование

```python
# tests/performance/stress_test.py
from locust import HttpUser, task, between

class ContractUser(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        """Авторизация при старте"""
        response = self.client.post("/api/v1/auth/token/", json={
            "email": "test@example.com",
            "password": "password"
        })
        self.token = response.json()["access"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    @task(3)
    def view_contracts(self):
        """Просмотр списка договоров"""
        self.client.get("/api/v1/contracts/", headers=self.headers)
    
    @task(2)
    def view_contract_detail(self):
        """Просмотр деталей договора"""
        self.client.get("/api/v1/contracts/uuid/", headers=self.headers)
    
    @task(1)
    def create_contract(self):
        """Создание договора"""
        contract_data = {
            "title": "Test Contract",
            "price": 100000,
            "land_plot_id": "uuid",
            "seller_id": "uuid",
            "buyer_id": "uuid"
        }
        self.client.post("/api/v1/contracts/", json=contract_data, headers=self.headers)
```

## Стратегия тестирования безопасности

### Тесты безопасности API

```python
# tests/security/test_api_security.py
import pytest
from django.test import TestCase
from rest_framework.test import APIClient
from users.factories import UserFactory

class TestAPISecurity(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory()
    
    def test_unauthorized_access(self):
        """Тест неавторизованного доступа"""
        response = self.client.get('/api/v1/contracts/')
        self.assertEqual(response.status_code, 401)
    
    def test_sql_injection_protection(self):
        """Тест защиты от SQL-инъекций"""
        self.client.force_authenticate(user=self.user)
        
        malicious_input = "'; DROP TABLE contracts; --"
        response = self.client.get(f'/api/v1/contracts/?search={malicious_input}')
        
        # Проверка, что таблица не удалена
        response = self.client.get('/api/v1/contracts/')
        self.assertNotEqual(response.status_code, 500)
    
    def test_xss_protection(self):
        """Тест защиты от XSS"""
        self.client.force_authenticate(user=self.user)
        
        xss_payload = "<script>alert('xss')</script>"
        contract_data = {
            'title': xss_payload,
            'price': 100000,
        }
        
        response = self.client.post('/api/v1/contracts/', contract_data)
        self.assertEqual(response.status_code, 201)
        
        # Проверка, что скрипт не выполняется
        response = self.client.get(f'/api/v1/contracts/{response.data["id"]}/')
        self.assertNotIn('<script>', response.data['title'])
    
    def test_rate_limiting(self):
        """Тест ограничения частоты запросов"""
        self.client.force_authenticate(user=self.user)
        
        # Отправка множества запросов
        for _ in range(100):
            response = self.client.get('/api/v1/contracts/')
            if response.status_code == 429:
                break
        
        # Проверка, что запросы ограничены
        self.assertEqual(response.status_code, 429)
```

### Тесты безопасности фронтенда

```typescript
// cypress/e2e/security.cy.ts
describe('Security Tests', () => {
  it('should not expose sensitive data in localStorage', () => {
    cy.visit('/login');
    cy.get('[data-testid="email-input"]').type('test@example.com');
    cy.get('[data-testid="password-input"]').type('password');
    cy.get('[data-testid="login-btn"]').click();
    
    // Проверка, что токены не хранятся в localStorage
    cy.window().then((win) => {
      expect(win.localStorage.getItem('token')).to.be.null;
      expect(win.localStorage.getItem('refreshToken')).to.be.null;
    });
  });
  
  it('should sanitize user input', () => {
    cy.login('test@example.com', 'password');
    cy.visit('/contracts/create');
    
    const xssPayload = '<script>alert("xss")</script>';
    cy.get('[data-testid="contract-title"]').type(xssPayload);
    cy.get('[data-testid="submit-btn"]').click();
    
    // Проверка, что скрипт не выполняется
    cy.window().then((win) => {
      expect(win.alert).to.not.have.been.called;
    });
  });
});
```

## Стратегия тестирования доступности

### Тесты WCAG 2.1 AA

```typescript
// cypress/e2e/accessibility.cy.ts
import { injectAxe, checkA11y } from 'cypress-axe';

describe('Accessibility Tests', () => {
  beforeEach(() => {
    cy.visit('/');
    injectAxe();
  });

  it('should be accessible on main page', () => {
    checkA11y();
  });

  it('should be accessible on contract creation page', () => {
    cy.login('test@example.com', 'password');
    cy.visit('/contracts/create');
    checkA11y();
  });

  it('should support keyboard navigation', () => {
    cy.get('[data-testid="create-contract-btn"]').focus();
    cy.focused().click();
    
    // Проверка навигации по форме с клавиатуры
    cy.get('[data-testid="contract-title"]').focus();
    cy.focused().type('Test Contract');
    cy.tab();
    cy.focused().should('have.attr', 'data-testid', 'contract-description');
  });

  it('should have proper ARIA labels', () => {
    cy.get('[data-testid="contract-status"]').should('have.attr', 'aria-label');
    cy.get('[data-testid="notification-toast"]').should('have.attr', 'role', 'alert');
  });
});
```

## Стратегия тестирования совместимости

### Кросс-браузерное тестирование

```yaml
# .github/workflows/browser-tests.yml
name: Browser Tests

on: [push, pull_request]

jobs:
  browser-tests:
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        browser: [chrome, firefox, edge]
        os: [ubuntu-latest, windows-latest, macos-latest]
        exclude:
          - os: macos-latest
            browser: edge
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Node.js
      uses: actions/setup-node@v2
      with:
        node-version: '18'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run tests
      run: npm run test:e2e:browser
      env:
        BROWSER: ${{ matrix.browser }}
```

## Стратегия тестирования UI/UX

### Визуальное регрессионное тестирование

```typescript
// cypress/e2e/visual-regression.cy.ts
import { matchImageSnapshot } from 'cypress-image-snapshot';

describe('Visual Regression Tests', () => {
  beforeEach(() => {
    cy.login('test@example.com', 'password');
  });

  it('should match contract list snapshot', () => {
    cy.visit('/contracts');
    cy.get('[data-testid="contract-list"]').matchImageSnapshot();
  });

  it('should match contract form snapshot', () => {
    cy.visit('/contracts/create');
    cy.get('[data-testid="contract-form"]').matchImageSnapshot();
  });

  it('should match contract detail snapshot', () => {
    cy.visit('/contracts/uuid');
    cy.get('[data-testid="contract-detail"]').matchImageSnapshot();
  });
});
```

## Стратегия тестирования документации

### Тесты API документации

```python
# tests/documentation/test_api_docs.py
import pytest
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from drf_spectacular.openapi import AutoSchema
from drf_spectacular.validation import validate_schema

class TestAPIDocumentation(TestCase):
    def test_api_schema_is_valid(self):
        """Тест валидности схемы API"""
        schema = AutoSchema().get_schema(None, public=True)
        validate_schema(schema)
    
    def test_api_endpoints_documented(self):
        """Тест документации эндпоинтов"""
        client = APIClient()
        
        # Проверка доступности документации
        response = client.get('/api/docs/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response = client.get('/api/redoc/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response = client.get('/api/schema/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
```

## Стратегия CI/CD тестирования

### Конвейер тестирования

```yaml
# .github/workflows/test-pipeline.yml
name: Test Pipeline

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -r requirements/development.txt
    
    - name: Run backend unit tests
      run: |
        pytest --cov=apps --cov-report=xml --cov-fail-under=90
    
    - name: Upload coverage
      uses: codecov/codecov-action@v1
      with:
        file: ./coverage.xml

  frontend-tests:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Node.js
      uses: actions/setup-node@v2
      with:
        node-version: '18'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run frontend unit tests
      run: npm run test:unit -- --coverage
    
    - name: Upload coverage
      uses: codecov/codecov-action@v1
      with:
        file: ./coverage/lcov.info

  integration-tests:
    runs-on: ubuntu-latest
    needs: [unit-tests, frontend-tests]
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:6
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -r requirements/development.txt
    
    - name: Run integration tests
      run: |
        pytest tests/integration/
      env:
        DATABASE_URL: postgres://postgres:postgres@localhost:5432/test
        REDIS_URL: redis://localhost:6379/0

  e2e-tests:
    runs-on: ubuntu-latest
    needs: [integration-tests]
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Node.js
      uses: actions/setup-node@v2
      with:
        node-version: '18'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Start application
      run: |
        docker-compose -f docker-compose.test.yml up -d
        sleep 30
    
    - name: Run E2E tests
      run: npm run test:e2e
    
    - name: Stop application
      run: |
        docker-compose -f docker-compose.test.yml down
```

## Метрики качества

### KPI тестирования

1. **Покрытие кода**: Backend ≥ 90%, Frontend ≥ 85%
2. **Проход тестов**: ≥ 95% в CI/CD
3. **Время выполнения**: Unit < 5 мин, Integration < 15 мин, E2E < 30 мин
4. **Обнаружение дефектов**: ≥ 80% до продакшена
5. **Время исправления**: Critical < 4 часа, High < 24 часа
6. **Регрессионные тесты**: 100% критического пути

### Отчетность

```python
# tests/utils/test_reporter.py
import json
import pytest
from datetime import datetime

class TestReporter:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'tests': [],
            'summary': {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'skipped': 0,
                'coverage': 0
            }
        }
    
    def pytest_runtest_logreport(self, report):
        if report.when == 'call':
            test_result = {
                'name': report.nodeid,
                'status': report.outcome,
                'duration': report.duration,
                'error': str(report.longrepr) if report.failed else None
            }
            self.results['tests'].append(test_result)
            
            self.results['summary']['total'] += 1
            if report.passed:
                self.results['summary']['passed'] += 1
            elif report.failed:
                self.results['summary']['failed'] += 1
            elif report.skipped:
                self.results['summary']['skipped'] += 1
    
    def pytest_sessionfinish(self, session):
        # Генерация отчета
        with open('test-results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Отправка в систему мониторинга
        self.send_to_monitoring()
    
    def send_to_monitoring(self):
        # Интеграция с системой мониторинга
        pass
```

## Заключение

Комплексная стратегия тестирования обеспечивает высокое качество и надежность системы автоматизации договоров купли-продажи земли. Многоуровневый подход к тестированию, автоматизация процессов и непрерывный мониторинг качества позволяют своевременно выявлять и устранять дефекты, обеспечивая соответствие системы бизнес-требованиям и законодательным нормам.