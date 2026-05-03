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
    seller_name = serializers.CharField(source='seller.full_name', read_only=True)
    buyer_name = serializers.CharField(source='buyer.full_name', read_only=True)
    land_plot_cadastral_number = serializers.CharField(
        source='land_plot.cadastral_number',
        read_only=True
    )
    documents_count = serializers.IntegerField(source='documents.count', read_only=True)

    class Meta:
        model = Contract
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at', 'is_deleted', 'deleted_at')


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
        start_date = attrs.get('start_date')
        end_date = attrs.get('end_date')

        if seller and buyer and seller == buyer:
            raise serializers.ValidationError('Seller and buyer must be different users.')

        if start_date and end_date and end_date < start_date:
            raise serializers.ValidationError('End date must be later than start date.')

        return attrs


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
