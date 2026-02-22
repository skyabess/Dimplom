"""
Models for contracts app
"""
import uuid
from decimal import Decimal
from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator
from django.utils.translation import gettext_lazy as _
from apps.core.models import TimeStampedModel, SoftDeleteModel
from apps.users.models import User
from apps.land_plots.models import LandPlot


class Contract(TimeStampedModel, SoftDeleteModel):
    """
    Contract model for land purchase agreements
    """
    STATUS_CHOICES = [
        ('draft', _('Черновик')),
        ('pending_approval', _('Ожидает утверждения')),
        ('pending_signature', _('Ожидает подписания')),
        ('signed', _('Подписан')),
        ('active', _('Активен')),
        ('completed', _('Завершен')),
        ('cancelled', _('Отменен')),
        ('terminated', _('Расторгнут')),
    ]
    
    CURRENCY_CHOICES = [
        ('RUB', _('Российский рубль')),
        ('USD', _('Доллар США')),
        ('EUR', _('Евро')),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(
        _('Название договора'),
        max_length=255,
        help_text=_('Уникальное название для идентификации договора')
    )
    description = models.TextField(
        _('Описание'),
        help_text=_('Подробное описание условий договора')
    )
    
    # Relationships
    seller = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='sold_contracts',
        verbose_name=_('Продавец'),
        help_text=_('Пользователь, продающий земельный участок')
    )
    buyer = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='purchased_contracts',
        verbose_name=_('Покупатель'),
        help_text=_('Пользователь, покупающий земельный участок')
    )
    land_plot = models.ForeignKey(
        LandPlot,
        on_delete=models.PROTECT,
        related_name='contracts',
        verbose_name=_('Земельный участок'),
        help_text=_('Земельный участок, являющийся предметом договора')
    )
    
    # Financial details
    price = models.DecimalField(
        _('Цена'),
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],
        help_text=_('Базовая стоимость земельного участка')
    )
    currency = models.CharField(
        _('Валюта'),
        max_length=3,
        choices=CURRENCY_CHOICES,
        default='RUB',
        help_text=_('Валюта расчетов')
    )
    additional_fees = models.DecimalField(
        _('Дополнительные сборы'),
        max_digits=12,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Дополнительные расходы (комиссии, налоги и т.д.)')
    )
    
    # Dates
    start_date = models.DateField(
        _('Дата начала'),
        help_text=_('Дата вступления договора в силу')
    )
    end_date = models.DateField(
        _('Дата окончания'),
        help_text=_('Дата окончания действия договора')
    )
    signing_date = models.DateField(
        _('Дата подписания'),
        null=True,
        blank=True,
        help_text=_('Дата фактического подписания договора')
    )
    
    # Status and workflow
    status = models.CharField(
        _('Статус'),
        max_length=20,
        choices=STATUS_CHOICES,
        default='draft',
        help_text=_('Текущий статус договора')
    )
    
    # Additional terms
    payment_terms = models.TextField(
        _('Условия оплаты'),
        blank=True,
        help_text=_('Детальные условия оплаты и график платежей')
    )
    special_conditions = models.TextField(
        _('Особые условия'),
        blank=True,
        help_text=_('Дополнительные условия и соглашения')
    )
    
    class Meta:
        verbose_name = _('Договор')
        verbose_name_plural = _('Договоры')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['seller', 'status']),
            models.Index(fields=['buyer', 'status']),
            models.Index(fields=['land_plot', 'status']),
        ]
    
    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"
    
    @property
    def total_amount(self):
        """Общая сумма договора"""
        return self.price + self.additional_fees
    
    @property
    def is_active(self):
        """Проверка активности договора"""
        return self.status in ['active', 'signed']
    
    @property
    def can_be_signed(self):
        """Проверка возможности подписания"""
        return self.status == 'pending_signature'
    
    @property
    def days_until_expiry(self):
        """Количество дней до окончания"""
        from datetime import date
        if self.end_date:
            delta = self.end_date - date.today()
            return delta.days
        return None


class ContractStage(TimeStampedModel):
    """
    Contract stages for tracking workflow progress
    """
    contract = models.ForeignKey(
        Contract,
        on_delete=models.CASCADE,
        related_name='stages',
        verbose_name=_('Договор')
    )
    name = models.CharField(
        _('Название этапа'),
        max_length=100,
        help_text=_('Название этапа в процессе договора')
    )
    description = models.TextField(
        _('Описание этапа'),
        help_text=_('Подробное описание этапа')
    )
    order = models.PositiveIntegerField(
        _('Порядок'),
        help_text=_('Порядковый номер этапа')
    )
    is_completed = models.BooleanField(
        _('Завершен'),
        default=False,
        help_text=_('Флаг завершения этапа')
    )
    completed_at = models.DateTimeField(
        _('Дата завершения'),
        null=True,
        blank=True,
        help_text=_('Дата и время завершения этапа')
    )
    
    class Meta:
        verbose_name = _('Этап договора')
        verbose_name_plural = _('Этапы договоров')
        ordering = ['order']
        unique_together = ['contract', 'order']
    
    def __str__(self):
        return f"{self.contract.title} - {self.name}"


class ContractDocument(TimeStampedModel):
    """
    Documents attached to contracts
    """
    DOCUMENT_TYPES = [
        ('draft', _('Проект договора')),
        ('final', _('Итоговый договор')),
        ('attachment', _('Приложение')),
        ('payment_proof', _('Доказательство оплаты')),
        ('registration', _('Регистрационный документ')),
        ('other', _('Другое')),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    contract = models.ForeignKey(
        Contract,
        on_delete=models.CASCADE,
        related_name='documents',
        verbose_name=_('Договор')
    )
    title = models.CharField(
        _('Название документа'),
        max_length=255,
        help_text=_('Название документа для идентификации')
    )
    document_type = models.CharField(
        _('Тип документа'),
        max_length=20,
        choices=DOCUMENT_TYPES,
        help_text=_('Тип документа в контексте договора')
    )
    file = models.FileField(
        _('Файл'),
        upload_to='contracts/documents/%Y/%m/',
        help_text=_('Файл документа')
    )
    file_size = models.PositiveIntegerField(
        _('Размер файла'),
        help_text=_('Размер файла в байтах')
    )
    mime_type = models.CharField(
        _('MIME тип'),
        max_length=100,
        help_text=_('MIME тип файла')
    )
    is_required = models.BooleanField(
        _('Обязательный'),
        default=False,
        help_text=_('Флаг обязательности документа')
    )
    is_signed = models.BooleanField(
        _('Подписан'),
        default=False,
        help_text=_('Флаг подписания документа')
    )
    
    class Meta:
        verbose_name = _('Документ договора')
        verbose_name_plural = _('Документы договоров')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['contract', 'document_type']),
            models.Index(fields=['contract', 'is_required']),
        ]
    
    def __str__(self):
        return f"{self.contract.title} - {self.title}"
    
    @property
    def file_extension(self):
        """Расширение файла"""
        if self.file:
            return self.file.name.split('.')[-1].lower()
        return None
    
    @property
    def is_pdf(self):
        """Проверка PDF формата"""
        return self.mime_type == 'application/pdf'


class ContractSignature(TimeStampedModel):
    """
    Electronic signatures for contracts
    """
    SIGNATURE_TYPES = [
        ('seller', _('Подпись продавца')),
        ('buyer', _('Подпись покупателя')),
        ('notary', _('Нотариальное удостоверение')),
        ('witness', _('Подпись свидетеля')),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    contract = models.ForeignKey(
        Contract,
        on_delete=models.CASCADE,
        related_name='signatures',
        verbose_name=_('Договор')
    )
    signer = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='signatures',
        verbose_name=_('Подписант')
    )
    signature_type = models.CharField(
        _('Тип подписи'),
        max_length=20,
        choices=SIGNATURE_TYPES,
        help_text=_('Роль подписанта в договоре')
    )
    certificate_data = models.JSONField(
        _('Данные сертификата'),
        default=dict,
        help_text=_('Информация о сертификате электронной подписи')
    )
    signature_data = models.TextField(
        _('Данные подписи'),
        help_text=_('Закодированные данные электронной подписи')
    )
    ip_address = models.GenericIPAddressField(
        _('IP адрес'),
        help_text=_('IP адрес с которого была создана подпись')
    )
    user_agent = models.TextField(
        _('User Agent'),
        blank=True,
        help_text=_('User Agent браузера подписанта')
    )
    is_valid = models.BooleanField(
        _('Действительна'),
        default=True,
        help_text=_('Флаг действительности подписи')
    )
    validated_at = models.DateTimeField(
        _('Дата валидации'),
        help_text=_('Дата и время проверки подписи')
    )
    
    class Meta:
        verbose_name = _('Подпись договора')
        verbose_name_plural = _('Подписи договоров')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['contract', 'signature_type']),
            models.Index(fields=['signer', 'is_valid']),
        ]
        unique_together = ['contract', 'signer', 'signature_type']
    
    def __str__(self):
        return f"{self.contract.title} - {self.get_signature_type_display()}"


class ContractTemplate(TimeStampedModel):
    """
    Templates for contract generation
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(
        _('Название шаблона'),
        max_length=255,
        help_text=_('Название шаблона для идентификации')
    )
    description = models.TextField(
        _('Описание'),
        help_text=_('Описание шаблона и его назначения')
    )
    template_type = models.CharField(
        _('Тип шаблона'),
        max_length=50,
        help_text=_('Тип договора для которого предназначен шаблон')
    )
    content = models.TextField(
        _('Содержимое'),
        help_text=_('HTML содержимое шаблона с плейсхолдерами')
    )
    variables = models.JSONField(
        _('Переменные'),
        default=dict,
        help_text=_('Список переменных для подстановки в шаблон')
    )
    is_active = models.BooleanField(
        _('Активен'),
        default=True,
        help_text=_('Флаг активности шаблона')
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='created_templates',
        verbose_name=_('Создал')
    )
    
    class Meta:
        verbose_name = _('Шаблон договора')
        verbose_name_plural = _('Шаблоны договоров')
        ordering = ['name']
        indexes = [
            models.Index(fields=['template_type', 'is_active']),
        ]
    
    def __str__(self):
        return self.name


class ContractComment(TimeStampedModel):
    """
    Comments and discussions on contracts
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    contract = models.ForeignKey(
        Contract,
        on_delete=models.CASCADE,
        related_name='comments',
        verbose_name=_('Договор')
    )
    author = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='contract_comments',
        verbose_name=_('Автор')
    )
    content = models.TextField(
        _('Содержание'),
        help_text=_('Текст комментария')
    )
    is_internal = models.BooleanField(
        _('Внутренний'),
        default=False,
        help_text=_('Флаг видимости комментария для клиентов')
    )
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='replies',
        verbose_name=_('Родительский комментарий')
    )
    
    class Meta:
        verbose_name = _('Комментарий к договору')
        verbose_name_plural = _('Комментарии к договорам')
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['contract', 'created_at']),
            models.Index(fields=['author', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.contract.title} - {self.author.get_full_name()}"