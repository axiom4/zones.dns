from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from .security import mfa


@override_settings(LOGIN_ENCRYPTION='off', MFA_REQUIRED=True)
class LoginEnrolmentTests(TestCase):
    def setUp(self):
        cache.clear()
        self.u = User.objects.create_user('enrol', password='Password123!', is_staff=True)
        self.c = APIClient()

    def test_totp_enrolment_at_login_returns_token(self):
        r = self.c.post('/api/token/', {'username': 'enrol', 'password': 'Password123!'}, format='json')
        self.assertEqual(r.data['mfa'], 'setup')
        t = r.data['ticket']
        s = self.c.post('/api/mfa/totp/setup/', {'ticket': t}, format='json').data['secret']
        import time
        code = mfa.totp_code(s, int(time.time() // 30))
        r = self.c.post('/api/mfa/totp/confirm/', {'ticket': t, 'code': code}, format='json')
        self.assertEqual(r.status_code, 200, r.data)
        self.assertIn('token', r.data)


class BlockedRegexTakesOverListTests(TestCase):
    def test_regex_entry_with_the_name_of_a_list_entry(self):
        from .models import BlockedDomain
        BlockedDomain.objects.create(name='ads.example.com', source='list', list_name='x')
        c = APIClient()
        c.force_authenticate(User.objects.create_user('b', password='x', is_staff=True))
        r = c.post('/api/blocked/', {'name': 'ads.example.com', 'regex': True}, format='json')
        self.assertEqual(r.status_code, 201, r.data)
        self.assertFalse(BlockedDomain.objects.filter(source='list').exists())


@override_settings(LOGIN_ENCRYPTION='off')
class MalformedMfaInputTests(TestCase):
    def setUp(self):
        cache.clear()
        from .models import TotpDevice
        self.u = User.objects.create_user('m', password='Password123!', is_staff=True)
        TotpDevice.objects.create(user=self.u, secret=mfa.new_secret(), confirmed=True)
        self.c = APIClient()

    def test_non_ascii_code_and_non_string_ticket_are_400(self):
        t = mfa.make_ticket(self.u, 'verify')
        self.assertEqual(self.c.post('/api/mfa/totp/', {'ticket': t, 'code': 'éééééé'}, format='json').status_code, 400)
        self.assertEqual(self.c.post('/api/mfa/totp/', {'ticket': {'a': 1}, 'code': '123456'}, format='json').status_code, 400)
        self.assertEqual(self.c.post('/api/mfa/passkey/options/', {'ticket': 5}, format='json').status_code, 400)

    def test_non_string_grant_is_refused(self):
        for g in (None, 5, {'a': 1}):
            with self.assertRaises(mfa.MfaError):
                mfa.use_grant(self.u, 'admin', g)

    def test_json_array_body_is_400(self):
        self.assertEqual(self.c.post('/api/token/', [], format='json').status_code, 400)
        self.assertEqual(self.c.post('/api/mfa/totp/', [1], format='json').status_code, 400)
