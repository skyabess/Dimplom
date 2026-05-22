from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.gis.geos import Polygon
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.test import APITestCase

from apps.contracts.models import Contract, ContractDocument, ContractTask
from apps.contracts.views import ContractDocumentViewSet
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


class ContractApiTests(APITestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@test.local',
            password='StrongPass123!',
            first_name='Admin',
            last_name='User',
        )
        UserRole.objects.create(user=self.admin, role='company_admin')

        self.seller = User.objects.create_user(
            username='seller',
            email='seller@test.local',
            password='StrongPass123!',
            first_name='Seller',
            last_name='User',
        )
        UserRole.objects.create(user=self.seller, role='client')

        self.buyer = User.objects.create_user(
            username='buyer',
            email='buyer@test.local',
            password='StrongPass123!',
            first_name='Buyer',
            last_name='User',
        )
        UserRole.objects.create(user=self.buyer, role='client')

        self.land_plot = self.create_plot()

    def create_plot(self):
        region = Region.objects.create(name='Moscow Region', code='50', okato_code='46000000000')
        district = District.objects.create(region=region, name='Istra', code='001')
        settlement = Settlement.objects.create(district=district, name='Dedovsk', type='city')
        category = LandCategory.objects.create(name='Settlement lands', code='settle')
        purpose = LandPurpose.objects.create(name='Individual housing', code='izhs')
        geometry = Polygon((
            (37.6000, 55.7000),
            (37.6010, 55.7000),
            (37.6010, 55.7010),
            (37.6000, 55.7010),
            (37.6000, 55.7000),
        ))

        return LandPlot.objects.create(
            cadastral_number='50:21:0040201:814',
            region=region,
            district=district,
            settlement=settlement,
            address='Test address, 1',
            area='1840.00',
            category=category,
            purpose=purpose,
            geometry=geometry,
            centroid=geometry.centroid,
            ownership_type='private',
            created_by=self.admin,
        )

    def create_contract(self, status_value='active'):
        return Contract.objects.create(
            title='Sale of land plot',
            description='Contract description',
            seller=self.seller,
            buyer=self.buyer,
            land_plot=self.land_plot,
            price='8500000.00',
            currency='RUB',
            additional_fees='15000.00',
            start_date='2026-05-01',
            end_date='2026-06-05',
            status=status_value,
        )

    def test_contract_list_requires_authentication(self):
        response = self.client.get('/api/contracts/')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_admin_can_list_all_contracts(self):
        contract = self.create_contract()
        self.client.force_authenticate(self.admin)

        response = self.client.get('/api/contracts/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['id'], str(contract.id))

    def test_participant_can_see_own_contract(self):
        contract = self.create_contract()
        self.client.force_authenticate(self.seller)

        response = self.client.get('/api/contracts/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['id'], str(contract.id))

    def test_unrelated_client_cannot_see_contract(self):
        self.create_contract()
        other = User.objects.create_user(
            username='other',
            email='other@test.local',
            password='StrongPass123!',
            first_name='Other',
            last_name='Client',
        )
        UserRole.objects.create(user=other, role='client')
        self.client.force_authenticate(other)

        response = self.client.get('/api/contracts/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 0)

    def test_client_cannot_delete_foreign_contract(self):
        contract = self.create_contract()
        other = User.objects.create_user(
            username='other-delete',
            email='other-delete@test.local',
            password='StrongPass123!',
            first_name='Other',
            last_name='Client',
        )
        UserRole.objects.create(user=other, role='client')
        self.client.force_authenticate(other)

        response = self.client.delete(f'/api/contracts/{contract.id}/')

        self.assertIn(
            response.status_code,
            (status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND),
        )
        self.assertTrue(Contract.objects.filter(id=contract.id).exists())

    def test_admin_can_create_contract_with_named_parties(self):
        self.client.force_authenticate(self.admin)

        response = self.client.post(
            '/api/contracts/',
            {
                'title': 'Lease of municipal land',
                'description': 'Lease contract description',
                'seller_full_name': 'Orlova Maria Sergeevna',
                'buyer_full_name': 'Kovalev Artem Mihailovich',
                'land_plot': str(self.land_plot.id),
                'price': '1938000.00',
                'currency': 'RUB',
                'additional_fees': '0.00',
                'start_date': '2026-05-01',
                'end_date': '2027-05-01',
                'status': 'active',
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Contract.objects.filter(title='Lease of municipal land').exists())

    def test_task_can_be_created_for_contract(self):
        contract = self.create_contract()
        self.client.force_authenticate(self.admin)

        response = self.client.post(
            '/api/contracts/tasks/',
            {
                'contract': str(contract.id),
                'title': 'Check seller documents',
                'due_date': '2026-05-03',
                'assignee': 'Lawyer',
                'priority': 'high',
                'is_completed': False,
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        task = ContractTask.objects.get(title='Check seller documents')
        self.assertEqual(task.created_by, self.admin)
        self.assertEqual(task.contract, contract)

    def test_upload_too_large_contract_document(self):
        contract = self.create_contract()
        view = ContractDocumentViewSet()
        view.kwargs = {'contract_pk': str(contract.id)}
        uploaded_file = SimpleNamespace(
            size=100 * 1024 * 1024 + 1,
            content_type='application/pdf',
        )
        serializer = SimpleNamespace(validated_data={'file': uploaded_file})

        with self.assertRaises(ValidationError) as context:
            view.perform_create(serializer)

        self.assertIn('file', context.exception.detail)
        self.assertFalse(ContractDocument.objects.filter(contract=contract).exists())

    def test_upload_forbidden_file_type(self):
        contract = self.create_contract()
        self.client.force_authenticate(self.admin)
        uploaded_file = SimpleUploadedFile(
            'script.exe',
            b'MZ',
            content_type='application/x-msdownload',
        )

        response = self.client.post(
            f'/api/contracts/{contract.id}/documents/',
            {
                'title': 'Executable file',
                'document_type': 'draft',
                'file': uploaded_file,
            },
            format='multipart',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('file', response.data)
        self.assertFalse(ContractDocument.objects.filter(contract=contract).exists())
