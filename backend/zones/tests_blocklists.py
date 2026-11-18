"""Blacklist > Public lists managed in the GUI: the list of lists, the per-list sync status, a failed list keeping its entries, the lock."""
import io
import time
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from . import blocklists
from .models import BlockedDomain, Setting

CMD = 'zones.management.commands.import_blocklist'


def fake_download(pages):
    """download() that serves `pages` {url: text}; an Exception value is raised (a list that is down)."""
    def get(url):
        v = pages[url]
        if isinstance(v, Exception):
            raise v
        return v
    return get


def run(**kw):
    call_command('import_blocklist', stdout=io.StringIO(), stderr=io.StringIO(), **kw)


@mock.patch('zones.proxy.rules.sync_all', return_value=[])
class ImportTests(TestCase):
    def setUp(self):
        blocklists.save([('a', 'https://l.example/a'), ('b', 'https://l.example/b')])

    def listed(self):
        return sorted(BlockedDomain.objects.filter(source='list').values_list('name', 'list_name'))

    def test_saved_lists_win_over_the_env_default(self, _):
        with override_settings(BLOCKLISTS=['x=https://env.example/x']):
            self.assertEqual(blocklists.configured(), [('a', 'https://l.example/a'), ('b', 'https://l.example/b')])
            Setting.objects.filter(key=blocklists.KEY).delete()
            self.assertEqual(blocklists.configured(), [('x', 'https://env.example/x')])

    def test_a_failed_list_keeps_its_old_entries_and_the_others_update(self, _):
        with mock.patch(f'{CMD}.download', fake_download({'https://l.example/a': 'one.example\ntwo.example\n', 'https://l.example/b': 'b.example\n'})):
            run()
        self.assertEqual(self.listed(), [('b.example', 'b'), ('one.example', 'a'), ('two.example', 'a')])
        first = blocklists.status()['lists']['a']['synced']
        with mock.patch(f'{CMD}.download', fake_download({'https://l.example/a': OSError('timed out'), 'https://l.example/b': 'b2.example\n'})):
            with self.assertRaises(CommandError):
                run()
        self.assertEqual(self.listed(), [('b2.example', 'b'), ('one.example', 'a'), ('two.example', 'a')])
        st = blocklists.status()
        self.assertEqual((st['lists']['a']['error'], st['lists']['a']['domains'], st['lists']['a']['synced']), ('timed out', 2, first))
        self.assertEqual((st['lists']['b']['error'], st['lists']['b']['domains'], st['failed']), ('', 1, 1))
        self.assertTrue(st['finished'])
        self.assertFalse(blocklists.running())  # released after a failure too

    def test_an_empty_download_counts_as_a_failure(self, _):
        BlockedDomain.objects.create(name='old.example', source='list', list_name='a')
        with mock.patch(f'{CMD}.download', fake_download({'https://l.example/a': '# nothing\n', 'https://l.example/b': 'b.example\n'})):
            with self.assertRaises(CommandError):
                run()
        self.assertEqual(self.listed(), [('b.example', 'b'), ('old.example', 'a')])

    def test_a_removed_list_loses_its_entries(self, _):
        BlockedDomain.objects.create(name='gone.example', source='list', list_name='c')
        with mock.patch(f'{CMD}.download', fake_download({'https://l.example/a': 'a.example\n', 'https://l.example/b': 'b.example\n'})):
            run()
        self.assertEqual(self.listed(), [('a.example', 'a'), ('b.example', 'b')])

    def test_only_one_run_at_a_time(self, _):
        self.assertTrue(blocklists.acquire())
        self.assertFalse(blocklists.acquire())
        with self.assertRaisesMessage(CommandError, 'another import_blocklist is running'):
            run()
        with mock.patch(f'{CMD}.download', fake_download({'https://l.example/a': 'a.example\n', 'https://l.example/b': 'b.example\n'})):
            run(locked=True)  # the GUI's sync holds the lock for it
        self.assertFalse(blocklists.running())
        self.assertTrue(blocklists.acquire())

    def test_a_dead_run_is_taken_over(self, _):
        Setting.objects.create(key=blocklists.LOCK, value=str(int(time.time()) - blocklists.LOCK_TTL - 5))
        self.assertFalse(blocklists.running())
        self.assertTrue(blocklists.acquire())
        self.assertTrue(blocklists.running())


class ValidationTests(TestCase):
    def test_rules(self):
        ok = blocklists.split_lists('a=https://l.example/a\n\nhttps://l.example/x/hosts.txt\n')
        self.assertEqual(ok, [('a', 'https://l.example/a'), ('hosts.txt', 'https://l.example/x/hosts.txt')])
        for text, field in [('a=http://l.example/a', 'url'), ('a=ftp://l.example', 'url'), ('Bad=https://l.example', 'name'),
                            ('a=https://l.example/1 a=https://l.example/2', 'name'), ('a=https://' + 'x' * 2000, 'url'), ('a=https://', 'url'),
                            (' '.join(f'l{i}=https://l.example/{i}' for i in range(51)), 'text')]:
            with self.assertRaises(blocklists.ListError) as e:
                blocklists.split_lists(text)
            self.assertEqual(e.exception.field, field, text[:40])


class ApiTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.api.force_authenticate(get_user_model().objects.create_user('a', password='x', is_staff=True))

    @override_settings(BLOCKLISTS=['x=https://env.example/x'])
    def test_get_put_and_field_errors(self):
        r = self.api.get('/api/blocked/sources/').json()
        self.assertEqual((r['saved'], [x['name'] for x in r['lists']], r['running']), (False, ['x'], False))
        r = self.api.put('/api/blocked/sources/', {'text': 'a=https://l.example/a\nb=https://l.example/b'}, format='json')
        self.assertEqual(r.status_code, 200)
        self.assertEqual((r.json()['saved'], [x['name'] for x in r.json()['lists']]), (True, ['a', 'b']))
        r = self.api.patch('/api/blocked/sources/', {'text': 'a=http://l.example/a'}, format='json')
        self.assertEqual((r.status_code, list(r.json())), (400, ['url']))
        r = self.api.patch('/api/blocked/sources/', {'text': ''}, format='json')  # no list at all is allowed: the next import empties Public lists
        self.assertEqual((r.status_code, r.json()['lists']), (200, []))

    def test_sync_starts_one_background_import(self):
        with mock.patch('zones.views.blocked_domain.subprocess.Popen') as popen:
            r = self.api.post('/api/blocked/sources/sync/')
            self.assertEqual((r.status_code, r.json()['running']), (202, True))
            self.assertEqual(popen.call_args[0][0][-2:], ['import_blocklist', '--locked'])
            self.assertTrue(popen.call_args[1]['start_new_session'])
            self.assertEqual(self.api.post('/api/blocked/sources/sync/').status_code, 409)
            self.assertEqual(popen.call_count, 1)
        blocklists.release()  # what the import does when it ends
        self.assertFalse(self.api.get('/api/blocked/sources/').json()['running'])

    def test_sync_releases_the_lock_when_the_process_cannot_start(self):
        with mock.patch('zones.views.blocked_domain.subprocess.Popen', side_effect=OSError('no python')), self.assertRaises(OSError):
            self.api.post('/api/blocked/sources/sync/')
        self.assertFalse(blocklists.running())

    def test_admins_only(self):
        c = APIClient()
        c.force_authenticate(get_user_model().objects.create_user('u', password='x'))
        self.assertEqual(c.get('/api/blocked/sources/').status_code, 403)
        self.assertEqual(c.post('/api/blocked/sources/sync/').status_code, 403)
