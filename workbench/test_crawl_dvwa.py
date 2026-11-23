from email.message import Message
from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs
from urllib.request import BaseHandler, build_opener
from urllib.response import addinfourl

import crawl_dvwa
from imports import read_document


LOGIN_FORM = '''
<title>DVWA Login</title><form action="/login.php" method="POST">
<input name="username"><input name="password" type="password">
<input name="Login" type="submit" value="Login">
<input name="user_token" type="hidden" value="fixture-csrf">
</form>
'''
HOME_PAGE = '''
<title>DVWA Home</title>
<a href="/instructions.php">Instructions</a>
<a href="/about.php?return=fixture-query-value">About</a>
<a href="/logout.php">Logout</a>
<a href="http://127.0.0.1:9000/instructions.php">Another port</a>
<a href="/vulnerabilities/sqli/">SQL Injection</a>
'''
SQL_PAGE = '''
<title>SQL Injection</title>
<form method="GET"><input name="id" value="fixture-form-value"></form>
'''


class SimulatedDVWA(BaseHandler):
    def __init__(self):
        self.requests = []
        self.login_form = None
        self.accept_login = True

    def default_open(self, request):
        path = request.selector
        method = request.get_method()
        cookie = request.get_header('Cookie', '')
        self.requests.append((method, request.full_url, cookie))
        if path == crawl_dvwa.LOGIN:
            if method == 'GET':
                return self.response(request, 200, LOGIN_FORM, cookie='sid=fixture-before; Path=/')
            self.login_form = parse_qs(request.data.decode('ascii'))
            if self.accept_login and 'sid=fixture-before' in cookie:
                return self.response(request, 302, location=crawl_dvwa.HOME,
                                     cookie='sid=fixture-after; Path=/')
            return self.response(request, 302, location=crawl_dvwa.LOGIN)
        if 'sid=fixture-after' not in cookie:
            return self.response(request, 302, location=crawl_dvwa.LOGIN)
        if path == crawl_dvwa.HOME:
            return self.response(request, 200, HOME_PAGE)
        if path == '/vulnerabilities/sqli/':
            return self.response(request, 200, SQL_PAGE)
        if path == '/vulnerabilities/sqli_blind/':
            return self.response(request, 200, '<title>SQL Injection (Blind)</title>')
        if path == '/instructions.php':
            return self.response(request, 302, location='http://127.0.0.1:9000/outside')
        self.assert_unexpected_request(request.full_url)

    @staticmethod
    def assert_unexpected_request(url):
        raise AssertionError(f'Unexpected crawl request: {url}')

    @staticmethod
    def response(request, status, body='', location='', cookie=''):
        headers = Message()
        headers['Content-Type'] = 'text/html; charset=utf-8'
        if location:
            headers['Location'] = location
        if cookie:
            headers['Set-Cookie'] = cookie
        response = addinfourl(BytesIO(body.encode('utf-8')), headers, request.full_url, status)
        response.msg = 'fixture response'
        return response


class DvwaCrawlerTests(unittest.TestCase):
    def setUp(self):
        self.dvwa = SimulatedDVWA()
        opener = patch.object(crawl_dvwa, 'build_opener',
                              side_effect=lambda *handlers: build_opener(*handlers, self.dvwa))
        opener.start()
        self.addCleanup(opener.stop)

    def test_authenticated_inventory_is_scoped_and_can_be_imported(self):
        document = crawl_dvwa.crawl_dvwa('fixture-user', 'fixture-password')
        self.assertEqual(self.dvwa.login_form, {
            'username': ['fixture-user'], 'password': ['fixture-password'],
            'Login': ['Login'], 'user_token': ['fixture-csrf'],
        })
        self.assertEqual([(method, url.removeprefix(crawl_dvwa.ORIGIN))
                          for method, url, _ in self.dvwa.requests], [
            ('GET', '/login.php'), ('POST', '/login.php'), ('GET', '/index.php'),
            ('GET', '/vulnerabilities/sqli/'), ('GET', '/vulnerabilities/sqli_blind/'),
            ('GET', '/instructions.php'),
        ])
        imported = read_document(document)
        pages = {page['url'].removeprefix(crawl_dvwa.ORIGIN): page for page in imported['pages']}
        self.assertEqual(len(pages), 5)
        self.assertEqual(pages['/instructions.php']['statuses'], [302])
        self.assertIn(crawl_dvwa.ORIGIN + '/instructions.php', pages['/index.php']['links'])
        self.assertEqual(pages['/vulnerabilities/sqli/']['forms'][0]['fields'],
                         [{'name': 'id', 'type': 'text'}])
        self.assertEqual(pages['/vulnerabilities/sqli_blind/']['title'], 'SQL Injection (Blind)')
        output = json.dumps(document)
        for value in ('fixture-csrf', 'fixture-password', 'fixture-user', 'fixture-after',
                      'fixture-before', 'fixture-form-value', 'fixture-query-value'):
            self.assertNotIn(value, output)

    def test_rejected_login_stops_before_experiment_pages(self):
        self.dvwa.accept_login = False
        with self.assertRaisesRegex(crawl_dvwa.CrawlProblem, '未能进入 DVWA 首页'):
            crawl_dvwa.crawl_dvwa('fixture-user', 'fixture-password')
        self.assertEqual(len(self.dvwa.requests), 3)

    def test_saved_record_is_complete_and_replaces_earlier_report(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / 'dvwa-live-pages.json'
            output.write_text('previous report', encoding='utf-8')
            document = crawl_dvwa.crawl_dvwa('fixture-user', 'fixture-password')
            with patch.object(crawl_dvwa, 'OUTPUT', output):
                crawl_dvwa.save_document(document)
            self.assertEqual(json.loads(output.read_text(encoding='utf-8')), document)
            self.assertEqual(list(output.parent.iterdir()), [output])
