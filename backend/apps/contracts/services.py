from django.core.files.base import ContentFile
from django.utils import timezone

from apps.contracts.models import (
    Contract,
    ContractDocument,
    ContractSignature,
    ContractTemplate,
)


class ContractService:
    def create_contract(self, user, validated_data):
        return Contract.objects.create(**validated_data)

    def sign_contract(self, contract, user, signature_data, ip_address=None, user_agent=None):
        signature = self.create_signature(
            contract=contract,
            user=user,
            signature_data=signature_data,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        if contract.status == 'pending_signature':
            contract.status = 'signed'
            contract.signing_date = timezone.now().date()
            contract.save(update_fields=['status', 'signing_date', 'updated_at'])

        return signature

    def create_signature(self, contract, user, signature_data, ip_address=None, user_agent=None):
        active_roles = set()
        if hasattr(user, 'roles'):
            active_roles = set(user.roles.filter(is_active=True).values_list('role', flat=True))

        if contract.seller_id == user.id:
            signature_type = 'seller'
        elif contract.buyer_id == user.id:
            signature_type = 'buyer'
        elif 'notary' in active_roles:
            signature_type = 'notary'
        else:
            signature_type = 'witness'

        signature, _ = ContractSignature.objects.update_or_create(
            contract=contract,
            signer=user,
            signature_type=signature_type,
            defaults={
                'certificate_data': {},
                'signature_data': signature_data or '',
                'ip_address': ip_address or '127.0.0.1',
                'user_agent': user_agent or '',
                'is_valid': True,
                'validated_at': timezone.now(),
            },
        )
        return signature

    def get_contract_history(self, contract):
        events = [
            {
                'type': 'created',
                'title': 'Contract created',
                'timestamp': contract.created_at,
                'actor': None,
            }
        ]

        for stage in contract.stages.all().order_by('order'):
            events.append({
                'type': 'stage_completed' if stage.is_completed else 'stage_pending',
                'title': stage.name,
                'timestamp': stage.completed_at or stage.created_at,
                'actor': None,
            })

        for document in contract.documents.all().order_by('created_at'):
            events.append({
                'type': 'document_uploaded',
                'title': document.title,
                'timestamp': document.created_at,
                'actor': None,
            })

        for signature in contract.signatures.select_related('signer').all().order_by('created_at'):
            events.append({
                'type': 'signature_created',
                'title': signature.get_signature_type_display(),
                'timestamp': signature.created_at,
                'actor': signature.signer.full_name,
            })

        return sorted(events, key=lambda event: event['timestamp'])

    def generate_document(self, contract, template_id, user):
        template = None
        if template_id:
            template = ContractTemplate.objects.get(id=template_id, is_active=True)

        if template:
            content = self.preview_template(template, self._contract_template_data(contract))
            title = f'{template.name} - {contract.title}'
        else:
            content = self._default_document_content(contract)
            title = f'Document for {contract.title}'

        encoded = content.encode('utf-8')
        file_name = f'contract-{contract.id}-{timezone.now().strftime("%Y%m%d%H%M%S")}.html'

        document = ContractDocument(
            contract=contract,
            title=title,
            document_type='draft',
            file_size=len(encoded),
            mime_type='text/html',
            is_required=False,
            is_signed=False,
        )
        document.file.save(file_name, ContentFile(encoded), save=True)
        return document

    def complete_stage(self, stage, user):
        stage.is_completed = True
        stage.completed_at = timezone.now()
        stage.save(update_fields=['is_completed', 'completed_at', 'updated_at'])
        return stage

    def preview_template(self, template, data):
        content = template.content
        for key, value in data.items():
            content = content.replace('{{ ' + key + ' }}', str(value))
            content = content.replace('{{' + key + '}}', str(value))
        return content

    def _contract_template_data(self, contract):
        return {
            'contract_title': contract.title,
            'contract_description': contract.description,
            'seller_name': contract.seller.full_name,
            'buyer_name': contract.buyer.full_name,
            'cadastral_number': contract.land_plot.cadastral_number,
            'price': contract.price,
            'currency': contract.currency,
            'total_amount': contract.total_amount,
            'start_date': contract.start_date,
            'end_date': contract.end_date,
            'payment_terms': contract.payment_terms,
            'special_conditions': contract.special_conditions,
        }

    def _default_document_content(self, contract):
        data = self._contract_template_data(contract)
        return f"""
<!doctype html>
<html lang="ru">
<head><meta charset="utf-8"><title>{data['contract_title']}</title></head>
<body>
  <h1>{data['contract_title']}</h1>
  <p>{data['contract_description']}</p>
  <dl>
    <dt>Seller</dt><dd>{data['seller_name']}</dd>
    <dt>Buyer</dt><dd>{data['buyer_name']}</dd>
    <dt>Land plot</dt><dd>{data['cadastral_number']}</dd>
    <dt>Total amount</dt><dd>{data['total_amount']} {data['currency']}</dd>
    <dt>Period</dt><dd>{data['start_date']} - {data['end_date']}</dd>
  </dl>
  <h2>Payment terms</h2>
  <p>{data['payment_terms'] or '-'}</p>
  <h2>Special conditions</h2>
  <p>{data['special_conditions'] or '-'}</p>
</body>
</html>
"""
