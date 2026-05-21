import uuid

import django.contrib.auth.models
import django.contrib.auth.validators
import django.core.validators
import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=254, unique=True, verbose_name='email address')),
                ('phone', models.CharField(blank=True, max_length=20, null=True, validators=[django.core.validators.RegexValidator(message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.", regex='^\\+?1?\\d{9,15}$')])),
                ('patronymic', models.CharField(blank=True, max_length=150, null=True, verbose_name='Patronymic')),
                ('birth_date', models.DateField(blank=True, null=True, verbose_name='Birth Date')),
                ('is_verified', models.BooleanField(default=False, verbose_name='Is Verified')),
                ('verification_date', models.DateTimeField(blank=True, null=True, verbose_name='Verification Date')),
                ('company_name', models.CharField(blank=True, max_length=255, null=True, verbose_name='Company Name')),
                ('company_inn', models.CharField(blank=True, max_length=12, null=True, verbose_name='Company INN')),
                ('company_ogrn', models.CharField(blank=True, max_length=13, null=True, verbose_name='Company OGRN')),
                ('has_digital_signature', models.BooleanField(default=False, verbose_name='Has Digital Signature')),
                ('certificate_issued_date', models.DateField(blank=True, null=True, verbose_name='Certificate Issued Date')),
                ('certificate_expires_date', models.DateField(blank=True, null=True, verbose_name='Certificate Expires Date')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'User',
                'verbose_name_plural': 'Users',
                'db_table': 'users',
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('address', models.TextField(blank=True, null=True, verbose_name='Address')),
                ('postal_code', models.CharField(blank=True, max_length=10, null=True, verbose_name='Postal Code')),
                ('city', models.CharField(blank=True, max_length=100, null=True, verbose_name='City')),
                ('region', models.CharField(blank=True, max_length=100, null=True, verbose_name='Region')),
                ('language', models.CharField(default='ru', max_length=10, verbose_name='Language')),
                ('timezone', models.CharField(default='Europe/Moscow', max_length=50, verbose_name='Timezone')),
                ('email_notifications', models.BooleanField(default=True, verbose_name='Email Notifications')),
                ('sms_notifications', models.BooleanField(default=False, verbose_name='SMS Notifications')),
                ('passport_scan', models.FileField(blank=True, null=True, upload_to='documents/passports/', verbose_name='Passport Scan')),
                ('inn_scan', models.FileField(blank=True, null=True, upload_to='documents/inn/', verbose_name='INN Scan')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to='users.user')),
            ],
            options={
                'verbose_name': 'User Profile',
                'verbose_name_plural': 'User Profiles',
                'db_table': 'user_profiles',
            },
        ),
        migrations.CreateModel(
            name='UserRole',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('role', models.CharField(choices=[('client', 'Client'), ('realtor', 'Realtor'), ('lawyer', 'Lawyer'), ('notary', 'Notary'), ('company_admin', 'Company Administrator'), ('system_admin', 'System Administrator')], max_length=20, verbose_name='Role')),
                ('assigned_at', models.DateTimeField(auto_now_add=True, verbose_name='Assigned At')),
                ('expires_at', models.DateTimeField(blank=True, null=True, verbose_name='Expires At')),
                ('is_active', models.BooleanField(default=True, verbose_name='Is Active')),
                ('assigned_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='assigned_roles', to='users.user', verbose_name='Assigned By')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='roles', to='users.user')),
            ],
            options={
                'verbose_name': 'User Role',
                'verbose_name_plural': 'User Roles',
                'db_table': 'user_roles',
                'unique_together': {('user', 'role')},
            },
        ),
        migrations.CreateModel(
            name='UserSession',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('session_key', models.CharField(max_length=40, unique=True)),
                ('ip_address', models.GenericIPAddressField()),
                ('user_agent', models.TextField()),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_activity', models.DateTimeField(auto_now=True)),
                ('expires_at', models.DateTimeField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sessions', to='users.user')),
            ],
            options={
                'verbose_name': 'User Session',
                'verbose_name_plural': 'User Sessions',
                'db_table': 'user_sessions',
            },
        ),
        migrations.CreateModel(
            name='UserActivityLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(choices=[('login', 'Login'), ('logout', 'Logout'), ('create_contract', 'Create Contract'), ('sign_contract', 'Sign Contract'), ('upload_document', 'Upload Document'), ('view_contract', 'View Contract'), ('edit_contract', 'Edit Contract'), ('delete_contract', 'Delete Contract'), ('create_land_plot', 'Create Land Plot'), ('edit_land_plot', 'Edit Land Plot'), ('delete_land_plot', 'Delete Land Plot'), ('edit_profile', 'Edit Profile'), ('password_change', 'Password Change'), ('upload_signature', 'Upload Digital Signature'), ('assign_role', 'Assign Role'), ('add_plot_owner', 'Add Land Plot Owner'), ('upload_plot_doc', 'Upload Land Plot Document')], max_length=20, verbose_name='Action')),
                ('object_type', models.CharField(blank=True, max_length=50, null=True, verbose_name='Object Type')),
                ('object_id', models.CharField(blank=True, max_length=50, null=True, verbose_name='Object ID')),
                ('description', models.TextField(blank=True, null=True, verbose_name='Description')),
                ('ip_address', models.GenericIPAddressField()),
                ('user_agent', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True, verbose_name='Timestamp')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='activities', to='users.user')),
            ],
            options={
                'verbose_name': 'User Activity Log',
                'verbose_name_plural': 'User Activity Logs',
                'db_table': 'user_activity_logs',
                'ordering': ['-timestamp'],
            },
        ),
    ]
