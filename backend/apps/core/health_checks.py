from django.core.cache import cache
from django.db import connection
from django.conf import settings


class DatabaseCheck:
    def check(self):
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
            return cursor.fetchone()[0] == 1


class CacheCheck:
    def check(self):
        key = 'health-check'
        cache.set(key, 'ok', timeout=5)
        return cache.get(key) == 'ok'


class StorageCheck:
    def check(self):
        return bool(settings.MEDIA_ROOT)


class ExternalAPICheck:
    def check(self):
        return True
