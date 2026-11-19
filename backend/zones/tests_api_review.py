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


class RecordDuplicateTests(TestCase):
    def setUp(self):
        from .models import Zone
        self.z = Zone.objects.create(name='dup.lan')
        self.c = APIClient()
        self.c.force_authenticate(User.objects.create_user('dup', is_staff=True))

    def test_second_identical_record_and_an_edit_into_one_are_refused(self):
        body = {'zone': self.z.id, 'name': 'www', 'type': 'A', 'value': '192.0.2.1', 'ttl': 300}
        self.assertEqual(self.c.post('/api/records/', body, format='json').status_code, 201)
        self.assertEqual(self.c.post('/api/records/', body, format='json').status_code, 400)
        other = self.c.post('/api/records/', {**body, 'value': '192.0.2.2'}, format='json').data['id']
        self.assertEqual(self.c.patch(f'/api/records/{other}/', {'value': '192.0.2.1'}, format='json').status_code, 400)


class RecordPagesTests(TestCase):
    def setUp(self):
        from .models import Record, Zone
        self.z = Zone.objects.create(name='pg.lan')
        for i in (10, 9, 100, 2):
            Record.objects.create(zone=self.z, name=f'h{i}', type='A', value=f'10.0.0.{i}')
        Record.objects.create(zone=self.z, name='mail', type='MX', value='10 h2.pg.lan.', note='the relay')
        self.c = APIClient()
        self.c.force_authenticate(User.objects.create_user('pg', is_staff=True))

    def get(self, **q):
        return self.c.get('/api/records/', {'zone': self.z.id, **q}).data

    def test_default_order_is_by_ip_and_pages_slice_it(self):
        d = self.get()
        self.assertEqual(d['count'], 5)
        self.assertEqual([r['value'] for r in d['results'][:4]], ['10.0.0.2', '10.0.0.9', '10.0.0.10', '10.0.0.100'])  # numbers, not text
        self.assertEqual(d['results'][4]['type'], 'MX')  # not an IPv4 address: after them
        d = self.get(limit=2, offset=2)
        self.assertEqual([r['value'] for r in d['results']], ['10.0.0.10', '10.0.0.100'])
        self.assertEqual(d['count'], 5)

    def test_search_by_words_and_reverse_sort(self):
        self.assertEqual([r['name'] for r in self.get(q='relay mx')['results']], ['mail'])
        self.assertEqual(self.get(q='nothing')['count'], 0)
        self.assertEqual(self.get(sort='name', desc=1)['results'][0]['name'], 'mail')


class QueryLogHourlyTests(TestCase):
    def test_counts_every_hour_of_a_busy_client_not_only_the_newest_rows(self):
        from datetime import timedelta

        from django.utils import timezone

        from .models import QueryLog
        now = timezone.now()
        QueryLog.objects.bulk_create(
            [QueryLog(time=now - timedelta(hours=20), name='a.example', domain='example', type='A', outcome='blocked', client='10.0.0.5', ms=1)] * 2
            + [QueryLog(time=now - timedelta(minutes=5), name='b.example', domain='example', type='A', outcome='forwarded', client='10.0.0.5', ms=1)] * 600
            + [QueryLog(time=now - timedelta(hours=20), name='c.example', domain='example', type='A', outcome='forwarded', client='10.0.0.6', ms=1)])
        c = APIClient()
        c.force_authenticate(User.objects.create_user('hr', is_staff=True))
        rows = c.get('/api/logs/hourly/', {'client': '10.0.0.5', 'hours': 24}).data
        self.assertEqual(sum(r['count'] for r in rows), 602)
        old = [r for r in rows if r['blocked']]
        self.assertEqual((len(old), old[0]['count'], old[0]['blocked']), (1, 2, 2))


class QueryLogTimeRangeTests(TestCase):
    def test_since_and_until_cut_the_list_and_the_groups(self):
        from datetime import timedelta

        from django.utils import timezone

        from .models import QueryLog
        h = timezone.now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=5)
        QueryLog.objects.bulk_create([
            QueryLog(time=h + timedelta(minutes=m), name='a.example', domain='example', type='A', outcome='forwarded', client='10.0.0.5', ms=1) for m in (5, 20, 70)])
        c = APIClient()
        c.force_authenticate(User.objects.create_user('tr', is_staff=True))
        q = {'client': '10.0.0.5', 'since': h.isoformat(), 'until': (h + timedelta(hours=1)).isoformat()}
        self.assertEqual(c.get('/api/logs/', q).data['count'], 2)
        self.assertEqual(c.get('/api/logs/grouped/', {**q, 'by': 'domain'}).data['results'][0]['count'], 2)
        self.assertEqual(c.get('/api/logs/', {**q, 'since': 'yesterday'}).status_code, 400)
