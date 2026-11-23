"""Collect ordinary page metadata from the existing loopback DVWA instance."""

from collections import deque
from datetime import datetime, timezone
from getpass import getpass
from html.parser import HTMLParser
from http.client import HTTPException
from http.cookiejar import CookieJar
import json
from pathlib import Path
import sys
from tempfile import NamedTemporaryFile
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import (
    HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request, build_opener,
)

from imports import Scope, join_url, page_html


ORIGIN = 'http://127.0.0.1:8085'
LOGIN = '/login.php'
HOME = '/index.php'
ENTRY_PAGES = (HOME, '/vulnerabilities/sqli/', '/vulnerabilities/sqli_blind/')
NAVIGATION_PAGES = frozenset((*ENTRY_PAGES, '/instructions.php', '/about.php'))
SCOPE = Scope(ORIGIN)
OUTPUT = Path(__file__).resolve().parent / 'evidence' / 'dvwa-live-pages.json'
MAX_HTML_BYTES = 1024 * 1024


class CrawlProblem(ValueError):
    pass


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LoginToken(HTMLParser):
    value = ''

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == 'input' and attributes.get('name') == 'user_token':
            self.value = attributes.get('value') or ''


def navigation_path(url):
    if not SCOPE.includes(url):
        return None
    parsed = urlsplit(url)
    if parsed.query:
        return None
    path = parsed.path
    if path.endswith('/index.php') and path != HOME:
        path = path.removesuffix('index.php')
    return path if path in NAVIGATION_PAGES else None


def read_page(opener, path, form=None):
    url = ORIGIN + path
    body = None if form is None else urlencode(form).encode('utf-8')
    request = Request(url, data=body, headers={'Accept': 'text/html'})
    try:
        response = opener.open(request, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        status = response.getcode()
        redirect = join_url(url, response.headers.get('Location', '')) if 300 <= status < 400 else ''
        source = ''
        if (200 <= status < 300 and response.headers.get_content_type()
                in ('text/html', 'application/xhtml+xml')):
            content = response.read(MAX_HTML_BYTES + 1)
            if len(content) > MAX_HTML_BYTES:
                raise CrawlProblem(f'{path} 的 HTML 超过 1 MB，已停止采集。')
            charset = response.headers.get_content_charset() or 'utf-8'
            try:
                source = content.decode(charset, errors='replace')
            except LookupError:
                source = content.decode('utf-8', errors='replace')
    page = {'url': url, 'title': '', 'statuses': [status],
            'forms': [], 'links': [], 'has_html': False}
    if source:
        page.update(page_html(source, url, SCOPE))
    return page, source, redirect


def login(opener, username, password):
    page, source, _ = read_page(opener, LOGIN)
    required = {'username', 'password', 'Login', 'user_token'}
    expected_form = any(
        form['action'] == ORIGIN + LOGIN and form['method'] == 'POST'
        and required <= {field['name'] for field in form['fields']}
        for form in page['forms']
    )
    if not expected_form:
        raise CrawlProblem('无法识别本机 DVWA 的登录表单，请检查 8085 上的登录页。')
    token = LoginToken()
    token.feed(source)
    token.close()
    if not token.value:
        raise CrawlProblem('DVWA 登录表单缺少会话令牌，请刷新登录页再检查。')
    response, _, _ = read_page(opener, LOGIN, {
        'username': username, 'password': password, 'Login': 'Login', 'user_token': token.value,
    })
    if not 200 <= response['statuses'][0] < 400:
        raise CrawlProblem('DVWA 登录请求未成功，请检查本机站点。')
    return page


def crawl_dvwa(username, password):
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()), NoRedirects())
    pages = [login(opener, username, password)]
    pending = deque(ENTRY_PAGES)
    scheduled = set(ENTRY_PAGES)
    while pending:
        path = pending.popleft()
        page, _, redirect = read_page(opener, path)
        if path == HOME and (page['statuses'] != [200] or not page['has_html']):
            raise CrawlProblem('未能进入 DVWA 首页，请核对账号、密码和站点状态。')
        if SCOPE.includes(redirect) and urlsplit(redirect).path == LOGIN:
            raise CrawlProblem('DVWA 会话已失效，请重新运行采集。')
        pages.append(page)
        for link in page['links']:
            target = navigation_path(link)
            if target is not None and target not in scheduled:
                scheduled.add(target)
                pending.append(target)

    return {
        'schema': 'course-evidence/v1',
        'provenance': {
            'target': 'DVWA',
            'scope': ORIGIN,
            'method': '本机在线页面采集',
            'collected_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        },
        'pages': sorted(pages, key=lambda page: page['url']),
    }


def save_document(document):
    staged_file = NamedTemporaryFile(mode='w', encoding='utf-8', dir=OUTPUT.parent,
                                     suffix='.tmp', delete=False)
    staged_path = Path(staged_file.name)
    try:
        with staged_file:
            json.dump(document, staged_file, ensure_ascii=False, indent=2)
            staged_file.write('\n')
        staged_path.replace(OUTPUT)
    finally:
        staged_path.unlink(missing_ok=True)


def main():
    if not sys.stdin.isatty():
        sys.exit('请在 PowerShell 或终端中交互运行采集脚本。')
    print(f'采集本机 DVWA 页面 ({ORIGIN})')
    try:
        username = input('DVWA 用户名: ').strip()
        password = getpass('DVWA 密码: ')
        if not username or not password:
            raise CrawlProblem('请填写 DVWA 用户名和密码。')
        document = crawl_dvwa(username, password)
        save_document(document)
    except (CrawlProblem, OSError, HTTPException) as error:
        sys.exit(f'采集失败：{error}')
    except (EOFError, KeyboardInterrupt):
        sys.exit('\n已取消采集。')
    print(f'共记录 {len(document["pages"])} 个页面。')
    print(f'在工作台点击「导入文件」，选择 {OUTPUT}')


if __name__ == '__main__':
    main()
