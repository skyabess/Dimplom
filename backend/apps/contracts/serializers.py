from rest_framework import serializers

from apps.contracts.models import (
    Contract,
    ContractComment,
    ContractDocument,
    ContractSignature,
    ContractStage,
    ContractTemplate,
)


class ContractSerializer(serializers.ModelSerializer):
    total_amount = serializers.DecimalField(max_digits=12, decimal_places=2, read_only=True)

    class Meta:
        model = Contract
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at', 'is_deleted', 'deleted_at')


class ContractDetailSerializer(ContractSerializer):
    pass


class ContractCreateSerializer(ContractSerializer):
    pass


class ContractDocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContractDocument
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')


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
