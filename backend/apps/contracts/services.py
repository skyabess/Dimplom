from django.utils import timezone

from apps.contracts.models import Contract, ContractSignature


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
        signature_type = 'seller' if contract.seller_id == user.id else 'buyer'
        return ContractSignature.objects.create(
            contract=contract,
            signer=user,
            signature_type=signature_type,
            certificate_data={},
            signature_data=signature_data,
            ip_address=ip_address or '127.0.0.1',
            user_agent=user_agent or '',
            validated_at=timezone.now(),
        )

    def get_contract_history(self, contract):
        return []

    def generate_document(self, contract, template_id, user):
        raise NotImplementedError('Генерация документов пока не реализована')

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
