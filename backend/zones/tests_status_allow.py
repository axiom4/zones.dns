"""The proxy log's Allow across DNS and the proxy, the daemon heartbeats and /api/status/, and the device setup files without signing in."""
import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from . import heartbeat
from .dnsd import resolver
from .models import PERSONAL_BLOCKS, BlockedDomain, DataVersion, Setting
from .views.proxy import RULES_KEY


def _rules():
    return Setting.objects.filter(key=RULES_KEY).values_list('value', flat=True).first() or ''


class AllowTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.api.force_authenticate(get_user_model().objects.create_user('admin_a', password='x', is_staff=True))
        resolver._data = None

    def allow(self, host, url=''):
        resolver._data = None  # the tests run in one transaction: no DataVersion bump tells the resolver the data changed
        r = self.api.post('/api/proxy/allow/', {'host': host, 'url': url}, format='json')
        self.assertEqual(r.status_code, 200, r.content)
        return r.json()

    def undo(self, done):
        r = self.api.post('/api/proxy/allow/undo/', done, format='json')
        self.assertEqual(r.status_code, 204, r.content)
        resolver._data = None

    def test_dns_block_gets_a_personal_allow_entry_only(self):
        BlockedDomain.objects.create(name='tracker.example', source='list', list_name='easylist')
        done = self.allow('ads.tracker.example', 'https://ads.tracker.example/x.js')
        self.assertEqual((done['dns_block'], done['proxy_rule'], done['dns_prev'], done['dns_list']), ('tracker.example (easylist)', '', None, ''))
        entry = BlockedDomain.objects.get(pk=done['dns_id'])
        self.assertEqual((entry.name, entry.allow, entry.source), ('ads.tracker.example', True, 'manual'))
        resolver._data = None
        self.assertIsNone(resolver.blocked_entry('ads.tracker.example'))
        self.undo(done)
        self.assertFalse(BlockedDomain.objects.filter(pk=done['dns_id']).exists())
        self.assertEqual(resolver.blocked_entry('ads.tracker.example'), ('tracker.example', 'easylist'))

    def test_bypass_adds_only_the_proxy_exception_and_leaves_dns_blocked(self):
        BlockedDomain.objects.create(name='cr.example', source='list', list_name='hagezi')
        resolver._data = None
        r = self.api.post('/api/proxy/allow/', {'host': 'crs.cr.example', 'url': 'https://crs.cr.example/p', 'bypass': True}, format='json')
        self.assertEqual(r.status_code, 200, r.content)
        done = r.json()
        self.assertEqual((done['dns_id'], done['dns_block'], done['proxy_rule']), (None, '', '@@crs.cr.example'))
        self.assertEqual(_rules(), '@@crs.cr.example')
        resolver._data = None
        self.assertEqual(resolver.blocked_entry('crs.cr.example'), ('cr.example', 'hagezi'))
        self.undo(done)
        self.assertEqual(_rules(), '')

    def test_proxy_rule_gets_an_exception_and_undo_removes_only_it(self):
        Setting.objects.create(key=RULES_KEY, value='##.promo\n/banner-x/')
        done = self.allow('cdn.example', 'https://cdn.example/banner-x/a.png')
        self.assertEqual((done['dns_id'], done['proxy_block'], done['proxy_rule']), (None, 'custom-rule: /banner-x/', '@@cdn.example'))
        self.assertEqual(_rules(), '##.promo\n/banner-x/\n@@cdn.example')
        Setting.objects.filter(key=RULES_KEY).update(value=_rules() + '\n##.later')  # edited meanwhile: kept
        self.undo(done)
        self.assertEqual(_rules(), '##.promo\n/banner-x/\n##.later')

    def test_both_layers(self):
        BlockedDomain.objects.create(name='pagead.example', source='manual')
        done = self.allow('pagead.example', 'https://pagead.example/pagead/show.js')
        self.assertEqual((done['dns_block'], done['proxy_block'][:7], done['proxy_rule']), ('pagead.example (personal)', 'ad-url:', '@@pagead.example'))
        entry = BlockedDomain.objects.get(name='pagead.example')
        self.assertTrue(entry.allow)  # the personal block itself became the exception
        self.assertEqual(done['dns_prev'], {'allow': False, 'enabled': True, 'regex': False, 'expires': None})
        self.undo(done)
        entry.refresh_from_db()
        self.assertFalse(entry.allow)
        self.assertEqual(_rules(), '')

    def test_public_list_entry_of_the_same_name_gives_way_and_comes_back(self):
        BlockedDomain.objects.create(name='ads.example', source='list', list_name='hosts')
        done = self.allow('ads.example')
        self.assertEqual(done['dns_list'], 'hosts')
        self.assertEqual(BlockedDomain.objects.get(name='ads.example').source, 'manual')
        self.undo(done)
        self.assertEqual(BlockedDomain.objects.get(name='ads.example').list_name, 'hosts')

    def test_not_blocked_falls_back_to_the_proxy_exception_once(self):
        done = self.allow('shop.example')
        self.assertEqual((done['dns_id'], done['proxy_block'], done['proxy_rule']), (None, '', '@@shop.example'))
        again = self.allow('www.shop.example')  # already covered by @@shop.example: nothing to do
        self.assertEqual((again['dns_id'], again['proxy_rule']), (None, ''))
        self.assertEqual(_rules(), '@@shop.example')

    def test_personal_blocks_off_is_said(self):
        BlockedDomain.objects.create(name='t.example', source='list', list_name='l')
        Setting.set_flag(PERSONAL_BLOCKS, False)
        self.assertIn('switched off', self.allow('t.example')['note'])

    def test_bad_input_is_refused(self):
        self.assertEqual(self.api.post('/api/proxy/allow/', {'host': 'a b'}, format='json').status_code, 400)
        mine = BlockedDomain.objects.create(name='keep.example', source='manual', allow=True)
        r = self.api.post('/api/proxy/allow/undo/', {'host': 'other.example', 'dns_id': mine.pk, 'proxy_rule': '##.x'}, format='json')
        self.assertEqual(r.status_code, 400)  # only the @@ rule of that host
        self.api.post('/api/proxy/allow/undo/', {'host': 'other.example', 'dns_id': mine.pk}, format='json')
        self.assertTrue(BlockedDomain.objects.filter(pk=mine.pk).exists())  # an entry of another name is not touched
        self.assertEqual(APIClient().post('/api/proxy/allow/', {'host': 'x.example'}, format='json').status_code, 401)


class StatusTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.api.force_authenticate(get_user_model().objects.create_user('admin_st', password='x', is_staff=True))

    def test_status(self):
        heartbeat.beat('dns')
        Setting.objects.create(key=heartbeat.key('proxy'), value=json.dumps({'at': (timezone.now() - timedelta(seconds=200)).isoformat(), 'pid': 7}))
        with override_settings(DHCP=False, DHCP6=False, DHCP_RA=True, PROXY=True):
            self.assertFalse(self.api.get('/api/status/').json()['dhcp']['enabled'])  # RA alone: rundhcp waits for DHCPv4, it serves nothing
        with override_settings(DHCP=True, DHCP6=False, DHCP_RA=False, PROXY=True):
            d = self.api.get('/api/status/').json()
        self.assertEqual((d['dns']['enabled'], d['dns']['running'], d['dns']['command']), (True, True, 'rundns'))
        self.assertEqual((d['dhcp']['enabled'], d['dhcp']['running'], d['dhcp']['last_seen']), (True, False, None))
        self.assertEqual((d['proxy']['enabled'], d['proxy']['running'], d['proxy']['pid']), (True, False, 7))
        with override_settings(DHCP=False, DHCP6=False, DHCP_RA=False, PROXY=False):
            d = self.api.get('/api/status/').json()
        self.assertEqual((d['dhcp']['enabled'], d['proxy']['enabled']), (False, False))
        self.assertEqual(APIClient().get('/api/status/').status_code, 401)

    def test_beat_raises_no_data_version_and_updates_in_place(self):
        v = DataVersion.version()
        with self.captureOnCommitCallbacks(execute=True) as cbs:
            heartbeat.beat('dhcp')
            heartbeat.beat('dhcp')
        self.assertEqual((cbs, DataVersion.version()), ([], v))
        self.assertEqual(Setting.objects.filter(key='heartbeat:dhcp').count(), 1)

    def test_garbage_heartbeat_is_not_running(self):
        Setting.objects.create(key=heartbeat.key('dns'), value='nonsense')
        self.assertEqual(heartbeat.read()['dns']['running'], False)


@override_settings(GUI_URL='https://dns.example/', SECURE_PROXY_SSL_HEADER=None)
class SetupFilesTests(TestCase):
    def test_profile_and_root_ca_need_no_sign_in_over_https(self):
        for path, ctype in (('/proxy.mobileconfig', 'application/x-apple-aspen-config'), ('/proxy-ca.crt', 'application/x-x509-ca-cert')):
            r = self.client.get(path, secure=True, HTTP_HOST='dns.example')
            self.assertEqual((r.status_code, r['Content-Type']), (200, ctype), path)
            r = self.client.get(path, HTTP_HOST='dns.example')  # plain http: to the https GUI
            self.assertEqual((r.status_code, r['Location']), (302, f'https://dns.example{path}'))

    def test_proxy_info_names_the_gui_url(self):
        api = APIClient()
        api.force_authenticate(get_user_model().objects.create_user('admin_i', password='x', is_staff=True))
        self.assertEqual(api.get('/api/proxy/info/').json()['gui_url'], 'https://dns.example')
