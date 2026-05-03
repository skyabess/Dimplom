from django.core.management.base import BaseCommand

from apps.users.models import User, UserProfile, UserRole


TEST_USERS = [
    {
        'email': 'admin1@test.local',
        'username': 'admin1',
        'password': 'Admin12345!',
        'first_name': 'Иван',
        'last_name': 'Администратор',
        'role': 'system_admin',
        'is_staff': True,
        'is_superuser': True,
    },
    {
        'email': 'admin2@test.local',
        'username': 'admin2',
        'password': 'Admin12345!',
        'first_name': 'Мария',
        'last_name': 'Администратор',
        'role': 'company_admin',
        'is_staff': True,
        'is_superuser': False,
    },
    {
        'email': 'user1@test.local',
        'username': 'user1',
        'password': 'User12345!',
        'first_name': 'Алексей',
        'last_name': 'Пользователь',
        'role': 'client',
        'is_staff': False,
        'is_superuser': False,
    },
    {
        'email': 'user2@test.local',
        'username': 'user2',
        'password': 'User12345!',
        'first_name': 'Елена',
        'last_name': 'Пользователь',
        'role': 'client',
        'is_staff': False,
        'is_superuser': False,
    },
]


class Command(BaseCommand):
    help = 'Create default test users for local and demo environments.'

    def handle(self, *args, **options):
        for data in TEST_USERS:
            password = data.pop('password')
            role = data.pop('role')

            user, created = User.objects.get_or_create(
                email=data['email'],
                defaults=data,
            )

            changed_fields = []
            for field, value in data.items():
                if getattr(user, field) != value:
                    setattr(user, field, value)
                    changed_fields.append(field)

            if created or not user.check_password(password):
                user.set_password(password)
                changed_fields.append('password')

            if changed_fields:
                user.save(update_fields=list(set(changed_fields + ['updated_at'])))

            UserProfile.objects.get_or_create(user=user)
            UserRole.objects.update_or_create(
                user=user,
                role=role,
                defaults={'is_active': True},
            )

            status = 'created' if created else 'updated'
            self.stdout.write(self.style.SUCCESS(f'{status}: {user.email} / {role}'))
