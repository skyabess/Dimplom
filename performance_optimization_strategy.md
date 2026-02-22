# Стратегия оптимизации производительности для системы автоматизации договоров купли-продажи земли

## Обзор

Документ описывает комплексную стратегию оптимизации производительности системы автоматизации договоров купли-продажи земли, охватывающую все уровни архитектуры от базы данных до фронтенда, с учетом требований к масштабируемости и ожиданий пользователей.

## Цели производительности

### Метрики производительности

| Метрика | Целевое значение | Критическое значение | Метод измерения |
|---------|------------------|---------------------|-----------------|
| Время отклика API | < 200 мс (p95) | > 500 мс (p95) | APM, Load Testing |
| Время загрузки страницы | < 2 секунды | > 5 секунд | Real User Monitoring |
| Время обработки запроса БД | < 50 мс (p95) | > 200 мс (p95) | Database Monitoring |
| Пропускная способность | 1000 RPS | 500 RPS | Load Testing |
| Использование CPU | < 70% | > 90% | Infrastructure Monitoring |
| Использование памяти | < 80% | > 95% | Infrastructure Monitoring |

### Бенчмарки производительности

```yaml
# performance/benchmarks.yml
benchmarks:
  api_endpoints:
    contracts_list:
      target_rps: 500
      target_response_time: 150ms
      target_cpu_usage: 60%
      
    contract_detail:
      target_rps: 200
      target_response_time: 200ms
      target_cpu_usage: 50%
      
    contract_create:
      target_rps: 100
      target_response_time: 300ms
      target_cpu_usage: 70%
      
    document_upload:
      target_rps: 50
      target_response_time: 500ms
      target_cpu_usage: 80%
      
  database_operations:
    select_queries:
      target_response_time: 30ms
      target_cpu_usage: 40%
      
    insert_operations:
      target_response_time: 50ms
      target_cpu_usage: 60%
      
    update_operations:
      target_response_time: 40ms
      target_cpu_usage: 50%
      
  frontend_performance:
    first_contentful_paint: 1.5s
    largest_contentful_paint: 2.5s
    first_input_delay: 100ms
    cumulative_layout_shift: 0.1
```

## Оптимизация базы данных

### Индексация

```sql
-- Оптимизация индексов для таблицы договоров
CREATE INDEX CONCURRENTLY idx_contracts_status_created 
ON contracts(status, created_at DESC);

CREATE INDEX CONCURRENTLY idx_contracts_seller_buyer 
ON contracts(seller_id, buyer_id);

CREATE INDEX CONCURRENTLY idx_contracts_land_plot 
ON contracts(land_plot_id);

-- Частичный индекс для активных договоров
CREATE INDEX CONCURRENTLY idx_contracts_active 
ON contracts(created_at DESC) 
WHERE status IN ('active', 'pending_signature');

-- Индекс для полнотекстового поиска
CREATE INDEX CONCURRENTLY idx_contracts_search 
ON contracts USING gin(to_tsvector('russian', title || ' ' || description));

-- Оптимизация индексов для таблицы участков
CREATE INDEX CONCURRENTLY idx_land_plots_cadastral 
ON land_plots(cadastral_number);

CREATE INDEX CONCURRENTLY idx_land_plots_location 
ON land_plots USING gist(location);

-- Индексы для таблицы документов
CREATE INDEX CONCURRENTLY idx_documents_contract_type 
ON documents(contract_id, document_type);

CREATE INDEX CONCURRENTLY idx_documents_created 
ON documents(created_at DESC);
```

### Оптимизация запросов

```python
# database/optimized_queries.py
from django.db import models
from django.db.models import Prefetch, Q, F, Count, Sum
from django.core.cache import cache

class ContractQuerySet(models.QuerySet):
    def optimized_list(self, user_id=None, status=None):
        """Оптимизированный список договоров"""
        queryset = self.select_related(
            'land_plot',
            'seller',
            'buyer'
        ).prefetch_related(
            Prefetch(
                'documents',
                queryset=Document.objects.filter(
                    document_type='contract_draft'
                ).only('id', 'file_url'),
                to_attr='draft_documents'
            )
        ).annotate(
            documents_count=Count('documents'),
            total_amount=F('price') + F('additional_fees')
        )
        
        if user_id:
            queryset = queryset.filter(
                Q(seller_id=user_id) | Q(buyer_id=user_id)
            )
        
        if status:
            queryset = queryset.filter(status=status)
            
        return queryset
    
    def optimized_detail(self, contract_id):
        """Оптимизированная детализация договора"""
        cache_key = f'contract_detail_{contract_id}'
        contract = cache.get(cache_key)
        
        if not contract:
            contract = self.select_related(
                'land_plot',
                'seller',
                'buyer'
            ).prefetch_related(
                'documents',
                'signatures',
                'contract_stages'
            ).annotate(
                documents_count=Count('documents'),
                signatures_count=Count('signatures')
            ).get(id=contract_id)
            
            # Кэширование на 15 минут
            cache.set(cache_key, contract, 900)
        
        return contract
    
    def search_contracts(self, query):
        """Оптимизированный поиск договоров"""
        return self.filter(
            Q(title__search=query) |
            Q(description__search=query) |
            Q(land_plot__cadastral_number__icontains=query)
        ).select_related(
            'land_plot',
            'seller',
            'buyer'
        )

class ContractManager(models.Manager):
    def get_queryset(self):
        return ContractQuerySet(self.model, using=self._db)
    
    def get_dashboard_stats(self, user_id):
        """Статистика для дашборда"""
        cache_key = f'dashboard_stats_{user_id}'
        stats = cache.get(cache_key)
        
        if not stats:
            stats = {
                'total_contracts': self.filter(
                    Q(seller_id=user_id) | Q(buyer_id=user_id)
                ).count(),
                'active_contracts': self.filter(
                    Q(seller_id=user_id) | Q(buyer_id=user_id),
                    status='active'
                ).count(),
                'pending_contracts': self.filter(
                    Q(seller_id=user_id) | Q(buyer_id=user_id),
                    status='pending_signature'
                ).count(),
                'total_value': self.filter(
                    Q(seller_id=user_id) | Q(buyer_id=user_id),
                    status='active'
                ).aggregate(
                    total=Sum('price')
                )['total'] or 0
            }
            
            # Кэширование на 5 минут
            cache.set(cache_key, stats, 300)
        
        return stats
```

### Оптимизация соединений

```python
# database/connection_pooling.py
import psycopg2
from psycopg2 import pool
from django.conf import settings

class DatabaseConnectionPool:
    def __init__(self):
        self.pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=5,
            maxconn=20,
            host=settings.DATABASE_HOST,
            database=settings.DATABASE_NAME,
            user=settings.DATABASE_USER,
            password=settings.DATABASE_PASSWORD,
            port=settings.DATABASE_PORT
        )
    
    def get_connection(self):
        return self.pool.getconn()
    
    def release_connection(self, connection):
        self.pool.putconn(connection)
    
    def close_all_connections(self):
        self.pool.closeall()

# Настройки Django для оптимизации соединений
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'land_contracts',
        'USER': 'postgres',
        'PASSWORD': 'password',
        'HOST': 'localhost',
        'PORT': '5432',
        'OPTIONS': {
            'MAX_CONNS': 20,
            'MIN_CONNS': 5,
            'connect_timeout': 10,
            'application_name': 'land_contracts_app',
        }
    }
}
```

## Оптимизация API

### Кэширование API

```python
# api/caching.py
from django.core.cache import cache
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator
from rest_framework.decorators import action
from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response

class CachedContractViewSet(ModelViewSet):
    """ViewSet с кэшированием"""
    
    @method_decorator(cache_page(60 * 5))  # 5 минут
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)
    
    @method_decorator(cache_page(60 * 15))  # 15 минут
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)
    
    @action(detail=False, methods=['get'])
    @cache_page(60 * 30)  # 30 минут
    def statistics(self, request):
        """Статистика с длительным кэшированием"""
        stats = self.get_queryset().get_statistics()
        return Response(stats)
    
    def perform_create(self, serializer):
        """Инвалидация кэша при создании"""
        super().perform_create(serializer)
        self.invalidate_cache()
    
    def perform_update(self, serializer):
        """Инвалидация кэша при обновлении"""
        super().perform_update(serializer)
        self.invalidate_cache()
    
    def perform_destroy(self, instance):
        """Инвалидация кэша при удалении"""
        super().perform_destroy(instance)
        self.invalidate_cache()
    
    def invalidate_cache(self):
        """Инвалидация связанного кэша"""
        cache.delete_many([
            'contract_list_*',
            'contract_statistics',
            'dashboard_stats_*'
        ])
```

### Оптимизация сериализаторов

```python
# api/optimized_serializers.py
from rest_framework import serializers
from django.db.models import Prefetch

class OptimizedContractSerializer(serializers.ModelSerializer):
    """Оптимизированный сериализатор договоров"""
    
    land_plot_info = serializers.SerializerMethodField()
    seller_info = serializers.SerializerMethodField()
    buyer_info = serializers.SerializerMethodField()
    documents_count = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = Contract
        fields = [
            'id', 'title', 'price', 'status', 'created_at',
            'land_plot_info', 'seller_info', 'buyer_info',
            'documents_count'
        ]
        read_only_fields = ['created_at']
    
    def get_land_plot_info(self, obj):
        """Оптимизированная информация об участке"""
        if hasattr(obj, 'land_plot'):
            return {
                'id': obj.land_plot.id,
                'cadastral_number': obj.land_plot.cadastral_number,
                'area': obj.land_plot.area,
                'address': obj.land_plot.address
            }
        return None
    
    def get_seller_info(self, obj):
        """Оптимизированная информация о продавце"""
        if hasattr(obj, 'seller'):
            return {
                'id': obj.seller.id,
                'full_name': obj.seller.get_full_name(),
                'email': obj.seller.email
            }
        return None
    
    def get_buyer_info(self, obj):
        """Оптимизированная информация о покупателе"""
        if hasattr(obj, 'buyer'):
            return {
                'id': obj.buyer.id,
                'full_name': obj.buyer.get_full_name(),
                'email': obj.buyer.email
            }
        return None

class MinimalContractSerializer(serializers.ModelSerializer):
    """Минимальный сериализатор для списков"""
    
    class Meta:
        model = Contract
        fields = ['id', 'title', 'price', 'status', 'created_at']
```

### Пагинация и фильтрация

```python
# api/pagination.py
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

class OptimizedPagination(PageNumberPagination):
    """Оптимизированная пагинация"""
    
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100
    
    def get_paginated_response(self, data):
        return Response({
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link()
            },
            'count': self.page.paginator.count,
            'total_pages': self.page.paginator.num_pages,
            'current_page': self.page.number,
            'page_size': self.page_size,
            'results': data
        })

class CursorPagination(CursorPagination):
    """Курсорная пагинация для больших наборов данных"""
    
    page_size = 20
    ordering = '-created_at'
    cursor_query_param = 'cursor'
```

## Оптимизация фронтенда

### Ленивая загрузка компонентов

```typescript
// frontend/lazy-loading.tsx
import React, { Suspense, lazy } from 'react';
import { Routes, Route } from 'react-router-dom';
import { CircularProgress, Box } from '@mui/material';

// Ленивая загрузка компонентов
const ContractList = lazy(() => import('../pages/contracts/ContractList'));
const ContractDetail = lazy(() => import('../pages/contracts/ContractDetail'));
const ContractCreate = lazy(() => import('../pages/contracts/ContractCreate'));
const LandPlotList = lazy(() => import('../pages/land-plots/LandPlotList'));

const LoadingFallback = () => (
  <Box display="flex" justifyContent="center" alignItems="center" height="200px">
    <CircularProgress />
  </Box>
);

const OptimizedRoutes: React.FC = () => {
  return (
    <Suspense fallback={<LoadingFallback />}>
      <Routes>
        <Route path="/contracts" element={<ContractList />} />
        <Route path="/contracts/:id" element={<ContractDetail />} />
        <Route path="/contracts/create" element={<ContractCreate />} />
        <Route path="/land-plots" element={<LandPlotList />} />
      </Routes>
    </Suspense>
  );
};

export default OptimizedRoutes;
```

### Виртуализация списков

```typescript
// frontend/virtualized-list.tsx
import React from 'react';
import { FixedSizeList as List } from 'react-window';
import { Contract } from '../types/contract';
import ContractCard from './ContractCard';

interface VirtualizedContractListProps {
  contracts: Contract[];
  onContractClick: (id: string) => void;
}

const VirtualizedContractList: React.FC<VirtualizedContractListProps> = ({
  contracts,
  onContractClick
}) => {
  const Row = ({ index, style }: { index: number; style: React.CSSProperties }) => (
    <div style={style}>
      <ContractCard
        contract={contracts[index]}
        onClick={() => onContractClick(contracts[index].id)}
      />
    </div>
  );

  return (
    <List
      height={600}
      itemCount={contracts.length}
      itemSize={200}
      itemData={contracts}
    >
      {Row}
    </List>
  );
};

export default VirtualizedContractList;
```

### Оптимизация рендеринга

```typescript
// frontend/optimized-components.tsx
import React, { memo, useMemo, useCallback } from 'react';
import { Grid, Card, CardContent, Typography } from '@mui/material';
import { Contract } from '../types/contract';

interface ContractCardProps {
  contract: Contract;
  onView: (id: string) => void;
  onEdit: (id: string) => void;
  onDelete: (id: string) => void;
}

// Мемоизация компонента
const ContractCard = memo<ContractCardProps>(({ contract, onView, onEdit, onDelete }) => {
  // Мемоизация обработчиков
  const handleView = useCallback(() => onView(contract.id), [contract.id, onView]);
  const handleEdit = useCallback(() => onEdit(contract.id), [contract.id, onEdit]);
  const handleDelete = useCallback(() => onDelete(contract.id), [contract.id, onDelete]);
  
  // Мемоизация форматированных данных
  const formattedPrice = useMemo(() => {
    return new Intl.NumberFormat('ru-RU', {
      style: 'currency',
      currency: 'RUB'
    }).format(contract.price);
  }, [contract.price]);
  
  const formattedDate = useMemo(() => {
    return new Date(contract.created_at).toLocaleDateString('ru-RU');
  }, [contract.created_at]);

  return (
    <Card>
      <CardContent>
        <Typography variant="h6">{contract.title}</Typography>
        <Typography variant="body1">{formattedPrice}</Typography>
        <Typography variant="body2" color="textSecondary">
          {formattedDate}
        </Typography>
        <div>
          <button onClick={handleView}>Просмотр</button>
          <button onClick={handleEdit}>Редактировать</button>
          <button onClick={handleDelete}>Удалить</button>
        </div>
      </CardContent>
    </Card>
  );
});

ContractCard.displayName = 'ContractCard';

interface ContractListProps {
  contracts: Contract[];
  onContractView: (id: string) => void;
  onContractEdit: (id: string) => void;
  onContractDelete: (id: string) => void;
}

const ContractList: React.FC<ContractListProps> = ({
  contracts,
  onContractView,
  onContractEdit,
  onContractDelete
}) => {
  // Фильтрация и сортировка с мемоизацией
  const sortedContracts = useMemo(() => {
    return contracts.sort((a, b) => 
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
  }, [contracts]);

  return (
    <Grid container spacing={2}>
      {sortedContracts.map(contract => (
        <Grid item xs={12} sm={6} md={4} key={contract.id}>
          <ContractCard
            contract={contract}
            onView={onContractView}
            onEdit={onContractEdit}
            onDelete={onContractDelete}
          />
        </Grid>
      ))}
    </Grid>
  );
};

export default ContractList;
```

## Оптимизация инфраструктуры

### CDN и статические ресурсы

```yaml
# infrastructure/cdn.yml
AWSTemplateFormatVersion: '2010-09-09'
Description: CDN Configuration for Land Contracts

Resources:
  CloudFrontDistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Origins:
          - Id: S3Origin
            DomainName: !GetAtt S3Bucket.DomainName
            S3OriginConfig:
              OriginAccessIdentity: !Sub 'origin-access-identity/cloudfront/${CloudFrontOAI}'
          - Id: APIOrigin
            DomainName: !Sub 'api.${DomainName}'
            CustomOriginConfig:
              HTTPPort: 80
              HTTPSPort: 443
              OriginProtocolPolicy: https-only
        
        DefaultCacheBehavior:
          TargetOriginId: S3Origin
          ViewerProtocolPolicy: redirect-to-https
          CachePolicyId: 4135ea2d-6df8-44a3-9df3-4b5a84be39ad  # Managed-CachingOptimized
          Compress: true
        
        CacheBehaviors:
          - PathPattern: '/api/*'
            TargetOriginId: APIOrigin
            ViewerProtocolPolicy: https-only
            CachePolicyId: 4135ea2d-6df8-44a3-9df3-4b5a84be39ad
            Compress: true
            AllowedMethods: [GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE]
            CachedMethods: [GET, HEAD]
            TTL:
              Default: 0
              Min: 0
              Max: 0
        
        Enabled: true
        HttpVersion: http2
        PriceClass: PriceClass_100
        
        DefaultRootObject: index.html
        
        CustomErrorResponses:
          - ErrorCode: 404
            ResponseCode: 200
            ResponsePagePath: /index.html
          - ErrorCode: 403
            ResponseCode: 200
            ResponsePagePath: /index.html

  S3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub 'land-contracts-static-${Environment}'
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      
  CloudFrontOAI:
    Type: AWS::CloudFront::OriginAccessIdentity
    Properties:
      OriginAccessIdentityConfig:
        Comment: !Sub 'OAI for ${S3Bucket}'
```

### Автомасштабирование

```yaml
# infrastructure/auto-scaling.yml
AWSTemplateFormatVersion: '2010-09-09'
Description: Auto Scaling Configuration

Resources:
  ApplicationAutoScaling:
    Type: AWS::ApplicationAutoScaling::ScalableTarget
    Properties:
      MaxCapacity: 10
      MinCapacity: 2
      ResourceId: !Sub 'service/${ClusterName}/${ServiceName}'
      RoleARN: !GetAtt AutoScalingRole.Arn
      ScalableDimension: ecs:service:DesiredCount
      ServiceNamespace: ecs

  CPUAutoScalingPolicy:
    Type: AWS::ApplicationAutoScaling::ScalingPolicy
    Properties:
      PolicyName: CPUAutoScalingPolicy
      PolicyType: TargetTrackingScaling
      ScalingTargetId: !Ref ApplicationAutoScaling
      TargetTrackingScalingPolicyConfiguration:
        TargetValue: 70.0
        PredefinedMetricSpecification:
          PredefinedMetricType: ECSServiceAverageCPUUtilization
        ScaleInCooldown: 300
        ScaleOutCooldown: 60

  MemoryAutoScalingPolicy:
    Type: AWS::ApplicationAutoScaling::ScalingPolicy
    Properties:
      PolicyName: MemoryAutoScalingPolicy
      PolicyType: TargetTrackingScaling
      ScalingTargetId: !Ref ApplicationAutoScaling
      TargetTrackingScalingPolicyConfiguration:
        TargetValue: 80.0
        PredefinedMetricSpecification:
          PredefinedMetricType: ECSServiceAverageMemoryUtilization
        ScaleInCooldown: 300
        ScaleOutCooldown: 60

  RequestCountAutoScalingPolicy:
    Type: AWS::ApplicationAutoScaling::ScalingPolicy
    Properties:
      PolicyName: RequestCountAutoScalingPolicy
      PolicyType: TargetTrackingScaling
      ScalingTargetId: !Ref ApplicationAutoScaling
      TargetTrackingScalingPolicyConfiguration:
        TargetValue: 1000.0
        PredefinedMetricSpecification:
          PredefinedMetricType: ALBRequestCountPerTarget
          ResourceLabel: !Sub '${LoadBalancerARNSuffix}'
        ScaleInCooldown: 300
        ScaleOutCooldown: 60
```

## Мониторинг производительности

### APM интеграция

```python
# monitoring/apm.py
from elasticapm import Client, instrument
from elasticapm.contrib.django.client import DjangoClient
from django.conf import settings

class CustomAPMClient(DjangoClient):
    """Кастомный APM клиент с дополнительной функциональностью"""
    
    def capture_transaction(self, transaction_name, transaction_type='custom'):
        """Захват транзакции с дополнительными метриками"""
        with self.capture_transaction(transaction_name, transaction_type) as transaction:
            # Добавление кастомных метрик
            transaction.set_custom_context({
                'service': 'land_contracts',
                'environment': settings.ENVIRONMENT,
                'version': settings.VERSION
            })
            
            # Измерение времени выполнения
            start_time = time.time()
            yield
            duration = time.time() - start_time
            
            transaction.set_custom_context({
                'execution_time': duration
            })
            
            # Отправка метрик
            if duration > settings.SLOW_TRANSACTION_THRESHOLD:
                transaction.set_tag('slow_transaction', True)

# Декоратор для измерения производительности функций
def measure_performance(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start_time
        
        # Отправка метрик в APM
        apm_client = Client()
        apm_client.capture_message(
            f'Function {func.__name__} executed in {duration:.2f}s',
            level='info',
            extra={
                'function_name': func.__name__,
                'execution_time': duration,
                'args_count': len(args),
                'kwargs_count': len(kwargs)
            }
        )
        
        return result
    return wrapper

# Использование декоратора
@measure_performance
def process_contract(contract_id):
    """Обработка договора с измерением производительности"""
    contract = Contract.objects.get(id=contract_id)
    # Логика обработки
    return contract
```

### Метрики производительности

```python
# monitoring/metrics.py
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time

# Определение метрик
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

ACTIVE_CONNECTIONS = Gauge(
    'active_connections',
    'Number of active connections'
)

DATABASE_QUERY_DURATION = Histogram(
    'database_query_duration_seconds',
    'Database query duration',
    ['query_type', 'table']
)

CACHE_HIT_RATE = Gauge(
    'cache_hit_rate',
    'Cache hit rate percentage'
)

class PerformanceMiddleware:
    """Middleware для сбора метрик производительности"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        start_time = time.time()
        
        response = self.get_response(request)
        
        duration = time.time() - start_time
        
        # Запись метрик
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.path,
            status=response.status_code
        ).inc()
        
        REQUEST_DURATION.labels(
            method=request.method,
            endpoint=request.path
        ).observe(duration)
        
        return response

class DatabaseMetrics:
    """Метрики базы данных"""
    
    @staticmethod
    def record_query_duration(query_type, table, duration):
        DATABASE_QUERY_DURATION.labels(
            query_type=query_type,
            table=table
        ).observe(duration)
    
    @staticmethod
    def update_cache_hit_rate(hit_rate):
        CACHE_HIT_RATE.set(hit_rate)

# Запуск сервера метрик
def start_metrics_server(port=8000):
    start_http_server(port)
```

## Тестирование производительности

### Нагрузочное тестирование

```python
# performance/load_testing.py
import asyncio
import aiohttp
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class LoadTestResult:
    total_requests: int
    successful_requests: int
    failed_requests: int
    average_response_time: float
    min_response_time: float
    max_response_time: float
    requests_per_second: float

class LoadTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def make_request(self, endpoint: str, method: str = 'GET', **kwargs) -> Dict:
        """Выполнение одиночного запроса"""
        start_time = time.time()
        
        try:
            url = f"{self.base_url}{endpoint}"
            
            async with self.session.request(method, url, **kwargs) as response:
                await response.text()
                duration = time.time() - start_time
                
                return {
                    'status_code': response.status,
                    'response_time': duration,
                    'success': 200 <= response.status < 400
                }
        except Exception as e:
            duration = time.time() - start_time
            return {
                'status_code': 0,
                'response_time': duration,
                'success': False,
                'error': str(e)
            }
    
    async def run_load_test(
        self,
        endpoint: str,
        concurrent_users: int = 10,
        duration_seconds: int = 60,
        method: str = 'GET'
    ) -> LoadTestResult:
        """Запуск нагрузочного теста"""
        print(f"Starting load test: {concurrent_users} users for {duration_seconds}s")
        
        tasks = []
        start_time = time.time()
        
        # Создание задач для каждого пользователя
        for _ in range(concurrent_users):
            task = asyncio.create_task(
                self._user_simulation(endpoint, method, start_time, duration_seconds)
            )
            tasks.append(task)
        
        # Ожидание завершения всех задач
        results = await asyncio.gather(*tasks)
        
        # Агрегация результатов
        all_requests = []
        for user_results in results:
            all_requests.extend(user_results)
        
        successful_requests = [r for r in all_requests if r['success']]
        failed_requests = [r for r in all_requests if not r['success']]
        
        response_times = [r['response_time'] for r in all_requests]
        
        total_duration = time.time() - start_time
        
        return LoadTestResult(
            total_requests=len(all_requests),
            successful_requests=len(successful_requests),
            failed_requests=len(failed_requests),
            average_response_time=sum(response_times) / len(response_times),
            min_response_time=min(response_times),
            max_response_time=max(response_times),
            requests_per_second=len(all_requests) / total_duration
        )
    
    async def _user_simulation(
        self,
        endpoint: str,
        method: str,
        start_time: float,
        duration_seconds: int
    ) -> List[Dict]:
        """Симуляция поведения пользователя"""
        results = []
        
        while time.time() - start_time < duration_seconds:
            result = await self.make_request(endpoint, method)
            results.append(result)
            
            # Пауза между запросами
            await asyncio.sleep(0.1)
        
        return results

# Пример использования
async def main():
    async with LoadTester('https://api.landcontracts.com') as tester:
        # Тестирование списка договоров
        result = await tester.run_load_test(
            endpoint='/api/v1/contracts/',
            concurrent_users=50,
            duration_seconds=60
        )
        
        print(f"Load test results:")
        print(f"Total requests: {result.total_requests}")
        print(f"Successful: {result.successful_requests}")
        print(f"Failed: {result.failed_requests}")
        print(f"Average response time: {result.average_response_time:.2f}s")
        print(f"Requests per second: {result.requests_per_second:.2f}")

if __name__ == '__main__':
    asyncio.run(main())
```

### Стресс-тестирование

```python
# performance/stress_testing.py
import asyncio
import aiohttp
import time
from typing import List, Dict

class StressTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
    
    async def stress_test_endpoints(self, endpoints: List[str]) -> Dict:
        """Стресс-тестирование нескольких эндпоинтов"""
        results = {}
        
        for endpoint in endpoints:
            print(f"Stress testing {endpoint}")
            
            # Постепенное увеличение нагрузки
            for users in [10, 25, 50, 100, 200]:
                result = await self._run_stress_test(endpoint, users)
                results[f"{endpoint}_{users}_users"] = result
                
                # Проверка пороговых значений
                if result.average_response_time > 5.0:  # 5 секунд
                    print(f"Threshold exceeded at {users} users")
                    break
        
        return results
    
    async def _run_stress_test(self, endpoint: str, users: int) -> Dict:
        """Запуск стресс-теста для указанного количества пользователей"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            # Создание задач
            for _ in range(users):
                task = asyncio.create_task(
                    self._make_stress_request(session, endpoint)
                )
                tasks.append(task)
            
            # Ожидание завершения
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Анализ результатов
            successful = sum(1 for r in results if isinstance(r, dict) and r.get('success'))
            failed = len(results) - successful
            
            response_times = [
                r['response_time'] for r in results 
                if isinstance(r, dict) and 'response_time' in r
            ]
            
            return {
                'users': users,
                'successful_requests': successful,
                'failed_requests': failed,
                'average_response_time': sum(response_times) / len(response_times) if response_times else 0,
                'max_response_time': max(response_times) if response_times else 0,
                'error_rate': failed / len(results) * 100
            }
    
    async def _make_stress_request(self, session: aiohttp.ClientSession, endpoint: str) -> Dict:
        """Выполнение стресс-запроса"""
        start_time = time.time()
        
        try:
            url = f"{self.base_url}{endpoint}"
            
            async with session.get(url) as response:
                await response.text()
                duration = time.time() - start_time
                
                return {
                    'success': 200 <= response.status < 400,
                    'response_time': duration,
                    'status_code': response.status
                }
        except Exception as e:
            duration = time.time() - start_time
            return {
                'success': False,
                'response_time': duration,
                'error': str(e)
            }
```

## Заключение

Комплексная стратегия оптимизации производительности обеспечивает высокую скорость работы системы автоматизации договоров купли-продажи земли. Регулярный мониторинг, тестирование производительности и непрерывная оптимизация на всех уровнях архитектуры позволяют поддерживать систему в состоянии, соответствующем ожиданиям пользователей и требованиям бизнеса.