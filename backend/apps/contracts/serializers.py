import hashlib

from rest_framework import serializers

from apps.users.models import User
from apps.contracts.models import (
    Contract,
    ContractComment,
    ContractDocument,
    ContractSignature,
    ContractStage,
    ContractTask,
    ContractTemplate,
)


def get_or_create_party(full_name):
    normalized_name = (full_name or '').strip() or 'Участник сделки'
    parts = normalized_name.split()
    first_name = parts[1] if len(parts) > 1 else normalized_name
    last_name = parts[0] if len(parts) > 1 else ''
    digest = hashlib.sha1(normalized_name.lower().encode('utf-8')).hexdigest()[:10]
    email = f'party-{digest}@land-contract.local'

    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            'username': email,
            'first_name': first_name[:150],
            'last_name': last_name[:150],
        },
    )
    if created:
        user.set_unusable_password()
        user.save(update_fields=['password'])

    return user


class ContractSerializer(serializers.ModelSerializer):
    total_amount = serializers.DecimalField(max_digits=12, decimal_places=2, read_only=True)
    seller_name = serializers.CharField(source='seller.full_name', read_only=True)
    buyer_name = serializers.CharField(source='buyer.full_name', read_only=True)
    seller_full_name = serializers.CharField(write_only=True, required=False, allow_blank=True)
    buyer_full_name = serializers.CharField(write_only=True, required=False, allow_blank=True)
    land_plot_cadastral_number = serializers.CharField(
        source='land_plot.cadastral_number',
        read_only=True
    )
    documents_count = serializers.IntegerField(source='documents.count', read_only=True)

    class Meta:
        model = Contract
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at', 'is_deleted', 'deleted_at')

    def create(self, validated_data):
        seller_full_name = validated_data.pop('seller_full_name', '')
        buyer_full_name = validated_data.pop('buyer_full_name', '')

        if not validated_data.get('seller') and seller_full_name:
            validated_data['seller'] = get_or_create_party(seller_full_name)

        if not validated_data.get('buyer') and buyer_full_name:
            validated_data['buyer'] = get_or_create_party(buyer_full_name)

        return super().create(validated_data)

    def update(self, instance, validated_data):
        seller_full_name = validated_data.pop('seller_full_name', '')
        buyer_full_name = validated_data.pop('buyer_full_name', '')

        if seller_full_name:
            validated_data['seller'] = get_or_create_party(seller_full_name)

        if buyer_full_name:
            validated_data['buyer'] = get_or_create_party(buyer_full_name)

        return super().update(instance, validated_data)


class ContractDetailSerializer(ContractSerializer):
    documents = serializers.SerializerMethodField()
    stages = serializers.SerializerMethodField()
    signatures = serializers.SerializerMethodField()
    comments = serializers.SerializerMethodField()

    def get_documents(self, obj):
        return ContractDocumentSerializer(obj.documents.all(), many=True).data

    def get_stages(self, obj):
        return ContractStageSerializer(obj.stages.all(), many=True).data

    def get_signatures(self, obj):
        return ContractSignatureSerializer(obj.signatures.all(), many=True).data

    def get_comments(self, obj):
        return ContractCommentSerializer(obj.comments.all(), many=True).data


class ContractCreateSerializer(ContractSerializer):
    def validate(self, attrs):
        seller = attrs.get('seller')
        buyer = attrs.get('buyer')
        seller_full_name = attrs.get('seller_full_name')
        buyer_full_name = attrs.get('buyer_full_name')
        start_date = attrs.get('start_date')
        end_date = attrs.get('end_date')

        if seller and buyer and seller == buyer:
            raise serializers.ValidationError('Seller and buyer must be different users.')

        if not seller and not seller_full_name:
            raise serializers.ValidationError('Seller or seller_full_name is required.')

        if not buyer and not buyer_full_name:
            raise serializers.ValidationError('Buyer or buyer_full_name is required.')

        if start_date and end_date and end_date < start_date:
            raise serializers.ValidationError('End date must be later than start date.')

        return attrs


class ContractDocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContractDocument
        fields = '__all__'
        read_only_fields = (
            'id',
            'contract',
            'file_size',
            'mime_type',
            'created_at',
            'updated_at',
        )


class ContractSignatureSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContractSignature
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')


class ContractStageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContractStage
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at')


class ContractTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContractTemplate
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')


class ContractCommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContractComment
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')


class ContractTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContractTask
        fields = '__all__'
        read_only_fields = ('id', 'created_by', 'created_at', 'updated_at')
