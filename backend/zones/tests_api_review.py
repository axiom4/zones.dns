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


@override_settings(LOGIN_ENCRYPTION='off', MFA_REQUIRED=False)
class TokenCookieTests(TestCase):
    """The GUI's token lives in an HttpOnly cookie; requests that change something with it need the CSRF header."""
    def setUp(self):
        cache.clear()
        User.objects.create_user('gui', password='Password123!', is_staff=True)
        self.c = APIClient(enforce_csrf_checks=True)

    def _login(self):
        r = self.c.post('/api/token/', {'username': 'gui', 'password': 'Password123!'}, format='json')
        self.assertEqual(r.status_code, 200)
        return r

    def test_cookie_signs_in_and_changes_need_csrf(self):
        r = self._login()
        cookie = r.cookies['dns_token']
        self.assertTrue(cookie['httponly'])
        self.assertEqual(cookie['samesite'], 'Strict')
        self.assertEqual(cookie.value, r.data['token'])  # scripts still get it in the body
        self.assertEqual(self.c.get('/api/zones/').status_code, 200)
        self.assertEqual(self.c.post('/api/zones/', {'name': 'a.lan'}, format='json').status_code, 403)  # no X-CSRFToken: a cross-site form
        csrf = self.c.cookies['csrftoken'].value
        self.assertEqual(self.c.post('/api/zones/', {'name': 'a.lan'}, format='json', HTTP_X_CSRFTOKEN=csrf).status_code, 201)

    def test_header_token_needs_no_csrf(self):
        key = self._login().data['token']
        api = APIClient(enforce_csrf_checks=True)
        self.assertEqual(api.post('/api/zones/', {'name': 'b.lan'}, format='json', HTTP_AUTHORIZATION=f'Token {key}').status_code, 201)

    def test_logout_ends_the_token_and_deletes_the_cookie(self):
        self._login()
        csrf = self.c.cookies['csrftoken'].value
        r = self.c.post('/api/logout/', HTTP_X_CSRFTOKEN=csrf)
        self.assertEqual(r.status_code, 204)
        self.assertEqual(r.cookies['dns_token'].value, '')
        from rest_framework.authtoken.models import Token
        self.assertFalse(Token.objects.exists())

    def test_stale_cookie_does_not_block_sign_in(self):
        self.c.cookies['dns_token'] = 'stale'
        self.assertEqual(self.c.get('/api/zones/').status_code, 401)
        self._login()


class ReviewFixesTests(TestCase):
    def test_client_ip_trusts_header_only_from_trusted_proxy(self):
        from django.test import RequestFactory
        from .views.token import client_ip
        with override_settings(BEHIND_PROXY=True):
            self.assertEqual(client_ip(RequestFactory().get('/', REMOTE_ADDR='198.51.100.9', HTTP_X_REAL_IP='1.2.3.4')), '198.51.100.9')
            self.assertEqual(client_ip(RequestFactory().get('/', REMOTE_ADDR='127.0.0.1', HTTP_X_REAL_IP='1.2.3.4')), '1.2.3.4')

    def test_delete_chunked(self):
        from .models import QueryLog
        from .stats import rollup
        QueryLog.objects.bulk_create([QueryLog(name='a', type='A', outcome='local', client='c', ms=1) for _ in range(5)])
        self.assertEqual(rollup.delete_chunked(QueryLog.objects.all(), size=2), 5)
        self.assertFalse(QueryLog.objects.exists())

    def test_zone_rename_needs_grant_and_is_case_unique(self):
        from django.contrib.auth import get_user_model
        from rest_framework.test import APIClient
        from .models import Zone
        Zone.objects.create(name='a.lan')
        z = Zone.objects.create(name='b.lan')
        c = APIClient()
        c.force_authenticate(get_user_model().objects.create_user('u', password='x', is_staff=True))
        self.assertEqual(c.patch(f'/api/zones/{z.pk}/', {'name': 'A.LAN'}, format='json').status_code, 400)
        self.assertEqual(c.patch(f'/api/zones/{z.pk}/', {'name': 'c.lan'}, format='json').status_code, 200)
