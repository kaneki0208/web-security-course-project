"""Read existing evidence files without connecting to recorded sites."""

import base64
import binascii
from html.parser import HTMLParser
import posixpath
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlsplit


SCAN_TOOLS = ('OWASP ZAP', 'sqlmap', '长亭 xray')
TOOLS = (*SCAN_TOOLS, '静态代码审查')
TARGETS = ('DVWA', '校园设备借用管理系统')
COVERAGE_STATES = ('已有报告', '已核对覆盖范围', '未覆盖')
REVIEWS = ('待复核', '已确认', '误报', '漏报')
RISK = {'0': '信息', '1': '低', '2': '中', '3': '高'}
CWE_TYPES = {
    '79': '跨站脚本', '89': 'SQL 注入', '352': '跨站请求伪造',
    '434': '不安全文件上传', '639': '访问控制',
}


class ImportProblem(ValueError):
    pass


def record(value):
    return value if isinstance(value, dict) else {}


def items(value):
    return value if isinstance(value, list) else []


def text(value, limit=300):
    return value.strip()[:limit] if isinstance(value, str) else ''


def parts(url):
    if not isinstance(url, str) or not url or any(ord(char) < 32 for char in url):
        return None
    try:
        parsed = urlsplit(url)
        if parsed.scheme in ('http', 'https') and parsed.hostname and parsed.username is None:
            return parsed, parsed.port
    except ValueError:
        pass
    return None


def origin_path(url):
    valid = parts(url)
    if not valid:
        return None
    parsed, port = valid
    host = parsed.hostname
    if ':' in host:
        host = f'[{host}]'
    default_port = 443 if parsed.scheme == 'https' else 80
    suffix = f':{port}' if port is not None and port != default_port else ''
    return f'{parsed.scheme}://{host}{suffix}', parsed.path or '/'


def query_names(url):
    parsed, _ = parts(url)
    return sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name})


def clean_url(url):
    location = origin_path(url)
    if not location:
        return ''
    origin, path = location
    names = query_names(url)
    return origin + path + ('?' + '&'.join(quote(name, safe='') for name in names) if names else '')


def join_url(base, reference):
    try:
        return urljoin(base, reference)
    except ValueError:
        return ''


def scoped_path(path):
    return posixpath.normpath('/' + unquote(path).replace('\\', '/').lstrip('/'))


class Scope:
    def __init__(self, url):
        location = origin_path(url)
        if not location or urlsplit(url).query or urlsplit(url).fragment:
            raise ImportProblem('导入 HAR 需要填写范围，例如 http://127.0.0.1:8080/dvwa/。')
        self.origin, path = location
        self.path = scoped_path(path)

    def includes(self, url):
        location = origin_path(url)
        if not location:
            return False
        origin, path = location
        path = scoped_path(path)
        return origin == self.origin and (self.path == '/' or path == self.path or path.startswith(self.path + '/'))


class PageHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ''
        self.in_title = False
        self.base = None
        self.links = []
        self.forms = []
        self.form_ids = {}
        self.active_form = None
        self.controls = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'title' and not self.title:
            self.in_title = True
        elif tag == 'base' and self.base is None and attrs.get('href') is not None:
            self.base = attrs['href']
        elif tag in ('a', 'area') and attrs.get('href'):
            self.links.append(attrs['href'])
        elif tag == 'form' and self.active_form is None:
            self.active_form = len(self.forms)
            self.forms.append({'action': attrs.get('action') or '',
                               'method': form_method(attrs.get('method')), 'fields': []})
            if attrs.get('id'):
                self.form_ids.setdefault(attrs['id'], self.active_form)
        elif tag in ('input', 'select', 'textarea', 'button') and attrs.get('name'):
            kind = (attrs.get('type') or 'text').lower() if tag == 'input' else tag
            self.controls.append((self.active_form, attrs.get('form'), {'name': attrs['name'], 'type': kind}))

    def handle_endtag(self, tag):
        if tag == 'title':
            self.in_title = False
        elif tag == 'form':
            self.active_form = None

    def handle_data(self, data):
        if self.in_title and len(self.title) < 300:
            self.title += data[:300]


def form_method(value):
    method = text(value, 12).upper()
    return method if method in ('GET', 'POST', 'DIALOG') else 'GET'


def html_text(content):
    source = content.get('text')
    if not isinstance(source, str) or not source:
        return ''
    if content.get('encoding') == 'base64':
        try:
            return base64.b64decode(source, validate=True).decode('utf-8', errors='replace')
        except (ValueError, binascii.Error):
            return ''
    return source


def valid_status(status):
    return type(status) is int and 100 <= status <= 599


def page_html(source, url, scope):
    parsed = PageHTML()
    try:
        parsed.feed(source)
        parsed.close()
    except AssertionError:
        # Older HTMLParser versions can fail on unrecognized marked sections.
        return {}
    for index, owner, field in parsed.controls:
        box = parsed.form_ids.get(owner) if owner is not None else index
        if box is not None:
            parsed.forms[box]['fields'].append(field)

    base = join_url(url, parsed.base) if parsed.base is not None else url
    if not parts(base):
        base = url
    page_url = clean_url(url)
    links = set()
    for href in parsed.links:
        target = join_url(base, href)
        if scope.includes(target):
            target = clean_url(target)
            if target != page_url:
                links.add(target)
    for form in parsed.forms:
        target = join_url(base, form['action']) if form['action'] else url
        form['action'] = clean_url(target) if scope.includes(target) else ''
    return {'title': ' '.join(parsed.title.split())[:240], 'forms': parsed.forms,
            'links': sorted(links), 'has_html': True}


def read_har(data, scope_url):
    entries = record(data.get('log')).get('entries')
    if not isinstance(entries, list):
        raise ImportProblem('HAR 文件缺少 log.entries。')
    scope = Scope(scope_url)
    pages = {}
    for entry in map(record, entries):
        url = record(entry.get('request')).get('url')
        if not scope.includes(url):
            continue
        response = record(entry.get('response'))
        content = record(response.get('content'))
        mime = text(content.get('mimeType')).split(';')[0].strip().lower()
        is_html = mime in ('text/html', 'application/xhtml+xml')
        resource = entry.get('_resourceType')
        if resource not in ('document', None) or (resource is None and not is_html):
            continue
        key = clean_url(url)
        page = pages.setdefault(key, {'url': key, 'title': '', 'query': query_names(url),
                                     'statuses': [], 'forms': [], 'links': [], 'has_html': False})
        status = response.get('status')
        if valid_status(status) and status not in page['statuses']:
            page['statuses'].append(status)
        source = html_text(content) if is_html else ''
        if source:
            page.update(page_html(source, url, scope))

    result = sorted(pages.values(), key=lambda page: page['url'])
    notes = []
    if not result:
        notes.append('该范围内未找到页面记录，请检查 HAR 和范围。')
    missing = sum(not page['has_html'] for page in result)
    if missing:
        notes.append(f'{missing} 个页面没有可解析的 HTML 正文。')
    return {'kind': 'HAR 页面记录', 'pages': result, 'findings': [], 'coverage': [], 'notes': notes}


def clean_page(raw):
    raw = record(raw)
    url = clean_url(raw.get('url'))
    if not url:
        raise ImportProblem('课程 JSON 的页面必须包含有效的 HTTP 或 HTTPS URL。')
    forms = []
    for form in map(record, items(raw.get('forms'))):
        fields = []
        for field in map(record, items(form.get('fields'))):
            if name := text(field.get('name')):
                fields.append({'name': name, 'type': text(field.get('type'), 30) or 'text'})
        forms.append({'action': clean_url(form.get('action')), 'method': form_method(form.get('method')),
                      'fields': fields})
    links = {clean_url(link) for link in items(raw.get('links'))}
    return {'url': url, 'title': text(raw.get('title'), 240), 'query': query_names(url),
            'statuses': list(dict.fromkeys(x for x in items(raw.get('statuses')) if valid_status(x))),
            'forms': forms, 'links': sorted(links - {'', url}), 'has_html': raw.get('has_html', True) is True}


def course_finding(raw, default_target):
    raw = record(raw)
    tool = text(raw.get('tool'))
    review = text(raw.get('review')) or '待复核'
    title, category = text(raw.get('title')), text(raw.get('type'))
    url = clean_url(raw.get('url'))
    if tool not in TOOLS or review not in REVIEWS or not (title and category and url):
        raise ImportProblem('课程 JSON 的结果需要有效的工具、复核状态、名称、漏洞类型和 URL。')
    finding = {key: text(raw.get(key), limit) for key, limit in (
        ('severity', 15), ('method', 12), ('parameter', 300), ('reference', 300), ('evidence', 1800), ('source', 300),
    )}
    target = text(raw.get('target')) or default_target
    if target and target not in TARGETS:
        raise ImportProblem('检测目标必须为 DVWA 或校园设备借用管理系统。')
    finding.update(tool=tool, review=review, title=title, type=category, url=url, target=target)
    return finding


def course_coverage(raw):
    raw = record(raw)
    target, tool, state = (text(raw.get(key)) for key in ('target', 'tool', 'state'))
    scope, reference = text(raw.get('scope'), 1800), text(raw.get('reference'))
    if target not in TARGETS or tool not in SCAN_TOOLS or state not in COVERAGE_STATES:
        raise ImportProblem('覆盖记录需要有效的目标、扫描工具和覆盖状态。')
    if state != '已有报告' and not (scope and reference):
        raise ImportProblem('核对覆盖范围或标记未覆盖时，请填写范围和依据。')
    return {'target': target, 'tool': tool, 'state': state, 'scope': scope, 'reference': reference,
            'source': text(raw.get('source'))}


def read_zap(data, target):
    findings = []
    sites = set()
    for site in map(record, data['site']):
        if url := clean_url(site.get('@name')):
            sites.add(url)
        for alert in map(record, items(site.get('alerts'))):
            title = text(alert.get('alert')) or text(alert.get('name'))
            cwe = str(alert.get('cweid', ''))
            rule = text(alert.get('alertRef')) or str(alert.get('pluginid', ''))
            if not title:
                continue
            for instance in map(record, items(alert.get('instances')) or [{}]):
                url = clean_url(instance.get('uri')) or clean_url(site.get('@name'))
                if not url:
                    continue
                has_evidence = bool(instance.get('evidence'))
                findings.append({
                    'tool': 'OWASP ZAP', 'title': title, 'type': CWE_TYPES.get(cwe, title), 'url': url,
                    'severity': RISK.get(str(alert.get('riskcode')), ''), 'review': '待复核',
                    'target': target,
                    'method': text(instance.get('method'), 12), 'parameter': text(instance.get('param')),
                    'reference': f'ZAP 规则 {rule}' if rule else '',
                    'evidence': '原报告含检测证据，请对照该规则和 URL 复核。' if has_evidence else '',
                })
    notes = [] if findings else ['报告中没有可导入的告警。']
    coverage = []
    if target:
        coverage.append({'target': target, 'tool': 'OWASP ZAP', 'state': '已有报告',
                         'scope': '、'.join(sorted(sites))[:1800], 'reference': 'ZAP Traditional JSON'})
    else:
        notes.append('导入 ZAP 报告时可选择目标，便于在覆盖对照中登记。')
    return {'kind': 'ZAP Traditional JSON', 'pages': [], 'findings': findings, 'coverage': coverage, 'notes': notes}


def read_document(data, scope='', target=''):
    data = record(data)
    if 'log' in data:
        return read_har(data, scope)
    if target and target not in TARGETS:
        raise ImportProblem('请选择有效的检测目标。')
    if isinstance(data.get('site'), list):
        return read_zap(data, target)
    if data.get('schema') == 'course-evidence/v1':
        pages, findings, coverage = (data.get(key, []) for key in ('pages', 'findings', 'coverage'))
        if not all(isinstance(section, list) for section in (pages, findings, coverage)):
            raise ImportProblem('课程 JSON 的 pages、findings 和 coverage 必须是数组。')
        return {'kind': '课程 JSON', 'pages': [clean_page(page) for page in pages],
                'findings': [course_finding(finding, target) for finding in findings],
                'coverage': [course_coverage(row) for row in coverage], 'notes': []}
    raise ImportProblem('请选择 HAR、ZAP Traditional JSON 或 course-evidence/v1 文件。')
