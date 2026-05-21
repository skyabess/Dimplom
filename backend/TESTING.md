# Backend autotests

Автотесты написаны на стандартном `django.test` и `rest_framework.test`, без дополнительных зависимостей.

## Что проверяется

- Авторизация: успешный вход, ошибка пароля, доступ к профилю.
- Пользователи: создание профиля, роли, сессии и лога входа.
- Земельные участки: доступ только после входа, список, создание администратором, запрет создания обычному клиенту.
- Договоры: доступ только после входа, видимость договоров по ролям, создание договора, создание задачи по договору.

## Запуск в Docker

Так как в приложениях проекта нет миграций, при запуске тестов нужен `--run-syncdb`.

```bash
docker compose exec backend python manage.py test apps.users apps.land_plots apps.contracts --run-syncdb
```

Если контейнеры ещё не запущены:

```bash
docker compose up -d --build
docker compose exec backend python manage.py test apps.users apps.land_plots apps.contracts --run-syncdb
```

## Запуск конкретного набора

```bash
docker compose exec backend python manage.py test apps.users --run-syncdb
docker compose exec backend python manage.py test apps.land_plots --run-syncdb
docker compose exec backend python manage.py test apps.contracts --run-syncdb
```
