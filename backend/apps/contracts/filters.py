import django_filters

from apps.contracts.models import Contract


class ContractFilter(django_filters.FilterSet):
    start_date_from = django_filters.DateFilter(field_name='start_date', lookup_expr='gte')
    start_date_to = django_filters.DateFilter(field_name='start_date', lookup_expr='lte')
    end_date_from = django_filters.DateFilter(field_name='end_date', lookup_expr='gte')
    end_date_to = django_filters.DateFilter(field_name='end_date', lookup_expr='lte')

    class Meta:
        model = Contract
        fields = {
            'status': ['exact'],
            'currency': ['exact'],
            'seller': ['exact'],
            'buyer': ['exact'],
            'land_plot': ['exact'],
        }
