# Архитектура API для системы автоматизации договоров купли-продажи земли

## Обзор

API спроектирован с использованием Django REST Framework и следует RESTful принципам. Все эндпоинты используют JSON для обмена данными и JWT для аутентификации.

## Базовая структура URL

```
https://api.landcontracts.com/api/v1/
```

## Аутентификация и авторизация

### JWT-аутентификация

Для доступа к защищенным эндпоинтам необходимо предоставить JWT-токен в заголовке:

```
Authorization: Bearer <jwt_token>
```

### Получение токена

```http
POST /api/v1/auth/token/
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "password123"
}
```

Ответ:
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": "uuid",
        "email": "user@example.com",
        "role": "seller"
    }
}
```

### Обновление токена

```http
POST /api/v1/auth/token/refresh/
Content-Type: application/json

{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

## Эндпоинты API

### 1. Аутентификация (/api/v1/auth/)

#### Регистрация
```http
POST /api/v1/auth/register/
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "password123",
    "password_confirm": "password123",
    "first_name": "Иван",
    "last_name": "Иванов",
    "patronymic": "Иванович",
    "phone": "+79991234567",
    "role": "seller"
}
```

#### Вход
```http
POST /api/v1/auth/login/
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "password123"
}
```

#### Выход
```http
POST /api/v1/auth/logout/
Authorization: Bearer <jwt_token>
```

#### Восстановление пароля
```http
POST /api/v1/auth/password-reset/
Content-Type: application/json

{
    "email": "user@example.com"
}
```

### 2. Управление пользователями (/api/v1/users/)

#### Получение текущего пользователя
```http
GET /api/v1/users/me/
Authorization: Bearer <jwt_token>
```

#### Обновление профиля
```http
PUT /api/v1/users/me/
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "first_name": "Иван",
    "last_name": "Иванов",
    "patronymic": "Иванович",
    "phone": "+79991234567"
}
```

#### Получение списка пользователей (только для персонала)
```http
GET /api/v1/users/
Authorization: Bearer <jwt_token>
```

### 3. Земельные участки (/api/v1/land-plots/)

#### Получение списка участков
```http
GET /api/v1/land-plots/
Authorization: Bearer <jwt_token>

# Параметры запроса:
# - page: номер страницы
# - page_size: количество элементов на странице
# - area_min: минимальная площадь
# - area_max: максимальная площадь
# - price_min: минимальная цена
# - price_max: максимальная цена
# - category: категория земель
# - search: поиск по адресу или кадастровому номеру
```

#### Создание участка
```http
POST /api/v1/land-plots/
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "cadastral_number": "77:01:0001001:1234",
    "address": "г. Москва, ул. Примерная, д. 1",
    "area": 10.5,
    "category": "земли населенных пунктов",
    "permitted_use": "для индивидуального жилищного строительства",
    "ownership_type": "частная собственность",
    "price": 1500000.00,
    "characteristics": {
        "communications": ["электричество", "водоснабжение"],
        "relief": "ровный",
        "soil_type": "чернозем"
    },
    "coordinates": {
        "type": "Polygon",
        "coordinates": [[[37.6173, 55.7558], [37.6174, 55.7559], [37.6175, 55.7558], [37.6173, 55.7558]]]
    }
}
```

#### Получение детальной информации об участке
```http
GET /api/v1/land-plots/{uuid}/
Authorization: Bearer <jwt_token>
```

#### Обновление информации об участке
```http
PUT /api/v1/land-plots/{uuid}/
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

#### Удаление участка
```http
DELETE /api/v1/land-plots/{uuid}/
Authorization: Bearer <jwt_token>
```

### 4. Договоры (/api/v1/contracts/)

#### Получение списка договоров
```http
GET /api/v1/contracts/
Authorization: Bearer <jwt_token>

# Параметры запроса:
# - status: статус договора
# - seller_id: ID продавца
# - buyer_id: ID покупателя
# - land_plot_id: ID земельного участка
# - date_from: дата начала периода
# - date_to: дата окончания периода
```

#### Создание договора
```http
POST /api/v1/contracts/
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "seller_id": "uuid",
    "buyer_id": "uuid",
    "land_plot_id": "uuid",
    "price": 1500000.00,
    "terms": {
        "payment_method": "безналичный расчет",
        "payment_terms": "в течение 5 банковских дней",
        "transfer_conditions": "после полной оплаты",
        "additional_conditions": "участок передается в состоянии, соответствующем акту осмотра"
    }
}
```

#### Получение детальной информации о договоре
```http
GET /api/v1/contracts/{uuid}/
Authorization: Bearer <jwt_token>
```

#### Обновление договора
```http
PUT /api/v1/contracts/{uuid}/
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

#### Изменение статуса договора
```http
PATCH /api/v1/contracts/{uuid}/status/
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "status": "signed",
    "comment": "Договор подписан обеими сторонами"
}
```

### 5. Версии договоров (/api/v1/contracts/{uuid}/versions/)

#### Получение версий договора
```http
GET /api/v1/contracts/{uuid}/versions/
Authorization: Bearer <jwt_token>
```

#### Создание новой версии
```http
POST /api/v1/contracts/{uuid}/versions/
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "content": {
        "sections": [
            {
                "title": "Предмет договора",
                "content": "Продавец обязуется передать в собственность Покупателя земельный участок..."
            }
        ]
    }
}
```

### 6. Документы (/api/v1/documents/)

#### Получение списка документов
```http
GET /api/v1/documents/
Authorization: Bearer <jwt_token>

# Параметры запроса:
# - contract_id: ID договора
# - type: тип документа
```

#### Загрузка документа
```http
POST /api/v1/documents/
Authorization: Bearer <jwt_token>
Content-Type: multipart/form-data

contract_id: uuid
title: "Договор купли-продажи"
type: "contract"
file: [файл]
```

#### Получение документа
```http
GET /api/v1/documents/{uuid}/
Authorization: Bearer <jwt_token>
```

#### Скачивание файла документа
```http
GET /api/v1/documents/{uuid}/download/
Authorization: Bearer <jwt_token>
```

### 7. Электронные подписи (/api/v1/signatures/)

#### Подписание документа
```http
POST /api/v1/signatures/
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "document_id": "uuid",
    "signature_data": "base64_encoded_signature",
    "certificate_info": {
        "issuer": "УЦ ФСБ России",
        "serial_number": "1234567890",
        "valid_from": "2023-01-01",
        "valid_to": "2025-01-01"
    }
}
```

#### Проверка подписи
```http
GET /api/v1/signatures/{uuid}/verify/
Authorization: Bearer <jwt_token>
```

#### Получение подписей документа
```http
GET /api/v1/documents/{uuid}/signatures/
Authorization: Bearer <jwt_token>
```

### 8. Этапы исполнения договоров (/api/v1/contract-stages/)

#### Получение этапов договора
```http
GET /api/v1/contracts/{uuid}/stages/
Authorization: Bearer <jwt_token>
```

#### Создание этапа
```http
POST /api/v1/contracts/{uuid}/stages/
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "name": "Регистрация перехода права собственности",
    "description": "Подача документов в Росреестр для регистрации перехода права собственности",
    "planned_date": "2023-12-15",
    "requirements": [
        "Заверенный договор купли-продажи",
        "Кадастровый паспорт",
        "Выписка из ЕГРН",
        "Паспорта сторон"
    ]
}
```

#### Обновление этапа
```http
PUT /api/v1/contract-stages/{uuid}/
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "status": "completed",
    "actual_date": "2023-12-14",
    "comment": "Регистрация завершена успешно"
}
```

### 9. Уведомления (/api/v1/notifications/)

#### Получение уведомлений
```http
GET /api/v1/notifications/
Authorization: Bearer <jwt_token>

# Параметры запроса:
# - is_read: флаг прочтения
# - type: тип уведомления
```

#### Отметить как прочитанное
```http
PATCH /api/v1/notifications/{uuid}/read/
Authorization: Bearer <jwt_token>
```

#### Отметить все как прочитанные
```http
PATCH /api/v1/notifications/read-all/
Authorization: Bearer <jwt_token>
```

## Форматы ответов

### Успешный ответ
```json
{
    "success": true,
    "data": {
        // данные ответа
    },
    "message": "Операция выполнена успешно"
}
```

### Ответ с пагинацией
```json
{
    "success": true,
    "data": {
        "count": 100,
        "next": "https://api.landcontracts.com/api/v1/land-plots/?page=2",
        "previous": null,
        "results": [
            // элементы
        ]
    }
}
```

### Ошибка
```json
{
    "success": false,
    "error": {
        "code": "VALIDATION_ERROR",
        "message": "Ошибка валидации данных",
        "details": {
            "field_name": ["Ошибка в поле"]
        }
    }
}
```

## Коды ошибок

| Код | Описание |
|-----|----------|
| AUTHENTICATION_REQUIRED | Требуется аутентификация |
| PERMISSION_DENIED | Доступ запрещен |
| VALIDATION_ERROR | Ошибка валидации данных |
| NOT_FOUND | Ресурс не найден |
| CONFLICT | Конфликт данных |
| RATE_LIMIT_EXCEEDED | Превышен лимит запросов |
| INTERNAL_ERROR | Внутренняя ошибка сервера |

## Ограничения API

- 100 запросов в минуту на пользователя
- 1000 запросов в минуту на IP-адрес
- Максимальный размер файла для загрузки: 50 МБ
- Максимальное количество элементов в ответе: 100

## Версионирование API

API использует версионирование через URL. Текущая версия - v1. При изменении API, нарушающем обратную совместимость, будет выпущена новая версия.

## Документация API

Интерактивная документация доступна по адресу:
- Swagger UI: https://api.landcontracts.com/api/docs/
- ReDoc: https://api.landcontracts.com/api/redoc/