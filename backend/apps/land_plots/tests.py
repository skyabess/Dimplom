from django.contrib.auth import get_user_model
from django.contrib.gis.geos import Polygon
from rest_framework import status
from rest_framework.test import APITestCase

from apps.land_plots.models import (
    District,
    LandCategory,
    LandPlot,
    LandPurpose,
    Region,
    Settlement,
)
from apps.users.models import UserRole


User = get_user_model()


class LandPlotApiTests(APITestCase):
    def setUp(self):
        self.manager = User.objects.create_user(
            username='manager',
            email='manager@test.local',
            password='StrongPass123!',
            first_name='Manager',
            last_name='User',
        )
        UserRole.objects.create(user=self.manager, role='company_admin')

        self.client_user = User.objects.create_user(
            username='client',
            email='client@test.local',
            password='StrongPass123!',
            first_name='Client',
            last_name='User',
        )
        UserRole.objects.create(user=self.client_user, role='client')

        self.region = Region.objects.create(name='Moscow Region', code='50', okato_code='46000000000')
        self.district = District.objects.create(region=self.region, name='Istra', code='001')
        self.settlement = Settlement.objects.create(
            district=self.district,
            name='Dedovsk',
            type='city',
        )
        self.category = LandCategory.objects.create(name='Settlement lands', code='settle')
        self.purpose = LandPurpose.objects.create(name='Individual housing', code='izhs')
        self.geometry = Polygon((
            (37.6000, 55.7000),
            (37.6010, 55.7000),
            (37.6010, 55.7010),
            (37.6000, 55.7010),
            (37.6000, 55.7000),
        ))

    def create_plot(self, cadastral_number='50:21:0040201:814'):
        return LandPlot.objects.create(
            cadastral_number=cadastral_number,
            region=self.region,
            district=self.district,
            settlement=self.settlement,
            address='Test address, 1',
            area='1840.00',
            category=self.category,
            purpose=self.purpose,
            geometry=self.geometry,
            centroid=self.geometry.centroid,
            ownership_type='private',
            created_by=self.manager,
        )

    def test_land_plot_list_requires_authentication(self):
        response = self.client.get('/api/land-plots/plots/')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_authenticated_user_can_list_land_plots(self):
        plot = self.create_plot()
        self.client.force_authenticate(self.client_user)

        response = self.client.get('/api/land-plots/plots/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['cadastral_number'], plot.cadastral_number)

    def test_manager_can_create_land_plot_with_reference_names(self):
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            '/api/land-plots/plots/',
            {
                'cadastral_number': '77:18:0004028:221',
                'address': 'Moscow, Test street, 10',
                'area': '620.00',
                'ownership_type': 'municipal',
                'region_name': 'Moscow',
                'district_name': 'Central',
                'settlement_name': 'Moscow',
                'category_name': 'Settlement lands',
                'purpose_name': 'Lease',
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            LandPlot.objects.filter(cadastral_number='77:18:0004028:221').exists()
        )

    def test_client_cannot_create_land_plot(self):
        self.client.force_authenticate(self.client_user)

        response = self.client.post(
            '/api/land-plots/plots/',
            {
                'cadastral_number': '77:18:0004028:222',
                'address': 'Moscow, Test street, 11',
                'area': '620.00',
                'ownership_type': 'private',
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
