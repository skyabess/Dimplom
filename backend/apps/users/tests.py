from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from apps.users.models import UserActivityLog, UserProfile, UserRole, UserSession


User = get_user_model()


class UserAuthApiTests(APITestCase):
    def setUp(self):
        self.password = 'StrongPass123!'
        self.user = User.objects.create_user(
            username='admin1',
            email='admin1@test.local',
            password=self.password,
            first_name='Ivan',
            last_name='Adminov',
        )
        UserRole.objects.create(user=self.user, role='system_admin')

    def test_login_returns_tokens_and_profile(self):
        response = self.client.post(
            '/api/auth/login/',
            {'email': self.user.email, 'password': self.password},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertEqual(response.data['user']['email'], self.user.email)
        self.assertEqual(response.data['user']['roles'][0]['role'], 'system_admin')
        self.assertTrue(UserProfile.objects.filter(user=self.user).exists())
        self.assertTrue(UserSession.objects.filter(user=self.user, is_active=True).exists())
        self.assertTrue(UserActivityLog.objects.filter(user=self.user, action='login').exists())

    def test_login_with_wrong_password_returns_400(self):
        response = self.client.post(
            '/api/auth/login/',
            {'email': self.user.email, 'password': 'wrong-password'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn('access', response.data)

    def test_profile_requires_authentication(self):
        response = self.client.get('/api/auth/profile/')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_authenticated_user_can_read_profile(self):
        self.client.force_authenticate(self.user)

        response = self.client.get('/api/auth/profile/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user.email)
        self.assertIn('roles', response.data)
