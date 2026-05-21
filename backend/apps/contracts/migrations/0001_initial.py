import uuid

import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('land_plots', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Contract',
            fields=[
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('is_deleted', models.BooleanField(default=False, verbose_name='Deleted')),
                ('deleted_at', models.DateTimeField(blank=True, null=True, verbose_name='Deleted At')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=255, verbose_name='Название договора')),
                ('description', models.TextField(verbose_name='Описание')),
                ('price', models.DecimalField(decimal_places=2, max_digits=12, validators=[django.core.validators.MinValueValidator(0.01)], verbose_name='Цена')),
                ('currency', models.CharField(choices=[('RUB', 'Российский рубль'), ('USD', 'Доллар США'), ('EUR', 'Евро')], default='RUB', max_length=3, verbose_name='Валюта')),
                ('additional_fees', models.DecimalField(decimal_places=2, default='0.00', max_digits=12, verbose_name='Дополнительные сборы')),
                ('start_date', models.DateField(verbose_name='Дата начала')),
                ('end_date', models.DateField(verbose_name='Дата окончания')),
                ('signing_date', models.DateField(blank=True, null=True, verbose_name='Дата подписания')),
                ('status', models.CharField(choices=[('draft', 'Черновик'), ('pending_approval', 'Ожидает утверждения'), ('pending_signature', 'Ожидает подписания'), ('signed', 'Подписан'), ('active', 'Активен'), ('completed', 'Завершен'), ('cancelled', 'Отменен'), ('terminated', 'Расторгнут')], default='draft', max_length=20, verbose_name='Статус')),
                ('payment_terms', models.TextField(blank=True, verbose_name='Условия оплаты')),
                ('special_conditions', models.TextField(blank=True, verbose_name='Особые условия')),
                ('buyer', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='purchased_contracts', to=settings.AUTH_USER_MODEL, verbose_name='Покупатель')),
                ('land_plot', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='contracts', to='land_plots.landplot', verbose_name='Земельный участок')),
                ('seller', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='sold_contracts', to=settings.AUTH_USER_MODEL, verbose_name='Продавец')),
            ],
            options={'ordering': ['-created_at']},
        ),
        migrations.CreateModel(
            name='ContractStage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('name', models.CharField(max_length=100, verbose_name='Название этапа')),
                ('description', models.TextField(verbose_name='Описание этапа')),
                ('order', models.PositiveIntegerField(verbose_name='Порядок')),
                ('is_completed', models.BooleanField(default=False, verbose_name='Завершен')),
                ('completed_at', models.DateTimeField(blank=True, null=True, verbose_name='Дата завершения')),
                ('contract', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='stages', to='contracts.contract', verbose_name='Договор')),
            ],
            options={'ordering': ['order'], 'unique_together': {('contract', 'order')}},
        ),
        migrations.CreateModel(
            name='ContractDocument',
            fields=[
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=255, verbose_name='Название документа')),
                ('document_type', models.CharField(choices=[('draft', 'Проект договора'), ('final', 'Итоговый договор'), ('attachment', 'Приложение'), ('payment_proof', 'Доказательство оплаты'), ('registration', 'Регистрационный документ'), ('other', 'Другое')], max_length=20, verbose_name='Тип документа')),
                ('file', models.FileField(upload_to='contracts/documents/%Y/%m/', verbose_name='Файл')),
                ('file_size', models.PositiveIntegerField(verbose_name='Размер файла')),
                ('mime_type', models.CharField(max_length=100, verbose_name='MIME тип')),
                ('is_required', models.BooleanField(default=False, verbose_name='Обязательный')),
                ('is_signed', models.BooleanField(default=False, verbose_name='Подписан')),
                ('contract', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='documents', to='contracts.contract', verbose_name='Договор')),
            ],
            options={'ordering': ['-created_at']},
        ),
        migrations.CreateModel(
            name='ContractSignature',
            fields=[
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('signature_type', models.CharField(choices=[('seller', 'Подпись продавца'), ('buyer', 'Подпись покупателя'), ('notary', 'Нотариальное удостоверение'), ('witness', 'Подпись свидетеля')], max_length=20, verbose_name='Тип подписи')),
                ('certificate_data', models.JSONField(default=dict, verbose_name='Данные сертификата')),
                ('signature_data', models.TextField(verbose_name='Данные подписи')),
                ('ip_address', models.GenericIPAddressField(verbose_name='IP адрес')),
                ('user_agent', models.TextField(blank=True, verbose_name='User Agent')),
                ('is_valid', models.BooleanField(default=True, verbose_name='Действительна')),
                ('validated_at', models.DateTimeField(verbose_name='Дата валидации')),
                ('contract', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='signatures', to='contracts.contract', verbose_name='Договор')),
                ('signer', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='signatures', to=settings.AUTH_USER_MODEL, verbose_name='Подписант')),
            ],
            options={'ordering': ['-created_at'], 'unique_together': {('contract', 'signer', 'signature_type')}},
        ),
        migrations.CreateModel(
            name='ContractTemplate',
            fields=[
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255, verbose_name='Название шаблона')),
                ('description', models.TextField(verbose_name='Описание')),
                ('template_type', models.CharField(max_length=50, verbose_name='Тип шаблона')),
                ('content', models.TextField(verbose_name='Содержимое')),
                ('variables', models.JSONField(default=dict, verbose_name='Переменные')),
                ('is_active', models.BooleanField(default=True, verbose_name='Активен')),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='created_templates', to=settings.AUTH_USER_MODEL, verbose_name='Создал')),
            ],
            options={'ordering': ['name']},
        ),
        migrations.CreateModel(
            name='ContractComment',
            fields=[
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('content', models.TextField(verbose_name='Содержание')),
                ('is_internal', models.BooleanField(default=False, verbose_name='Внутренний')),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='contract_comments', to=settings.AUTH_USER_MODEL, verbose_name='Автор')),
                ('contract', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='comments', to='contracts.contract', verbose_name='Договор')),
                ('parent', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='replies', to='contracts.contractcomment', verbose_name='Родительский комментарий')),
            ],
            options={'ordering': ['created_at']},
        ),
        migrations.CreateModel(
            name='ContractTask',
            fields=[
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=255, verbose_name='Title')),
                ('due_date', models.DateField(verbose_name='Due Date')),
                ('assignee', models.CharField(blank=True, max_length=255, verbose_name='Assignee')),
                ('priority', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], default='medium', max_length=20, verbose_name='Priority')),
                ('is_completed', models.BooleanField(default=False, verbose_name='Is Completed')),
                ('contract', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='tasks', to='contracts.contract', verbose_name='Contract')),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_contract_tasks', to=settings.AUTH_USER_MODEL, verbose_name='Created By')),
            ],
            options={'ordering': ['is_completed', 'due_date', '-created_at']},
        ),
    ]
