# Backend autotests

Автотесты написаны на стандартном `django.test` и `rest_framework.test`, без дополнительных зависимостей.

## Что проверяется

- Авторизация: успешный вход, ошибка пароля, доступ к профилю.
- Пользователи: создание профиля, роли, сессии и лога входа.
- Земельные участки: доступ только после входа, список, создание администратором, запрет создания обычному клиенту.
- Договоры: доступ только после входа, видимость договоров по ролям, создание договора, создание задачи по договору.

## Запуск в Docker

Тесты запускаются штатной командой Django `test`. Флаг `--run-syncdb` нужен для `migrate`, но не поддерживается командой `test`.

```bash
docker compose exec backend python manage.py test apps.users apps.land_plots apps.contracts
```

Если контейнеры ещё не запущены:

```bash
docker compose up -d --build
docker compose exec backend python manage.py test apps.users apps.land_plots apps.contracts
```

## Запуск конкретного набора

```bash
docker compose exec backend python manage.py test apps.users
docker compose exec backend python manage.py test apps.land_plots
docker compose exec backend python manage.py test apps.contracts
```
