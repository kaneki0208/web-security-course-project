import base64
from io import BytesIO
import json
import unittest

from app import app, MAX_BYTES
from imports import ImportProblem, read_document


SCOPE = 'http://localhost:8080/lab/'


def entry(path, *, source='', status=200, resource='document', mime='text/html', encoded=False):
    content = {'mimeType': mime, 'text': source}
    if encoded:
        content.update(encoding='base64', text=base64.b64encode(source.encode()).decode())
    return {
        '_resourceType': resource,
        'request': {'url': f'http://localhost:8080{path}', 'cookies': [{'value': 'cookie-secret'}],
                    'postData': {'text': 'password=post-secret'}},
        'response': {'status': status, 'content': content},
    }


class ImportTests(unittest.TestCase):
    def test_har_tracks_page_links_and_fields_without_values(self):
        html = '''<title> 设备 &amp; 记录 </title><base href="./children/">
        <a href="../records?view=private-value#section">记录</a>
        <a href="../records?view=x">重复</a>
        <a href="http://localhost:8081/lab/records">其他端口</a>
        <a href="https://outside.test/">范围外</a><a href="javascript:void(0)">脚本</a>
        <a href="../../../lab-other/">相似前缀</a>
        <a href="/lab/%2e%2e/private">编码越界</a>
        <form id="lookup" method="post"><input name="token" type="hidden" value="hidden-secret">
        <select name="category"><option value="choice-secret">分类</option></select></form>
        <input name="search" form="lookup"><form action="../records?mode=value-secret"></form>
        <form action="https://outside.test/process"><input name="comment"></form>'''
        data = {'log': {'entries': [
            entry('/lab/index?q=query-secret', source=html, encoded=True),
            entry('/lab/index?q=another-secret', status=304, mime=''),
            entry('/lab/records?view=session-secret', status=302, mime=''),
            entry('/lab/index?other=secret', resource='xhr', source='<title>XHR</title>'),
            entry('/lab-other/', source='<title>Outside</title>'),
        ]}}
        document = read_document(data, SCOPE)
        first, second = document['pages']
        self.assertEqual(first['url'], 'http://localhost:8080/lab/index?q')
        self.assertEqual(first['title'], '设备 & 记录')
        self.assertEqual(first['statuses'], [200, 304])
        self.assertEqual(first['query'], ['q'])
        self.assertEqual(first['links'], [second['url']])
        self.assertFalse(second['has_html'])
        self.assertEqual(first['forms'][0], {'method': 'POST', 'action': first['url'], 'fields': [
            {'name': 'token', 'type': 'hidden'}, {'name': 'category', 'type': 'select'},
            {'name': 'search', 'type': 'text'},
        ]})
        self.assertEqual(first['forms'][1]['action'], 'http://localhost:8080/lab/records?mode')
        self.assertEqual(first['forms'][2]['action'], '')
        self.assertNotIn('secret', json.dumps(document))

    def test_har_requires_scope_and_handles_empty_range(self):
        data = {'log': {'entries': [entry('/elsewhere/')]}}
        with self.assertRaises(ImportProblem):
            read_document(data)
        result = read_document(data, SCOPE)
        self.assertEqual(result['pages'], [])
        self.assertTrue(result['notes'])

    def test_har_keeps_malformed_document_row(self):
        data = {'log': {'entries': [entry('/lab/info', source='<![unknown]><title>测试</title>')]}}
        page = read_document(data, SCOPE)['pages'][0]
        self.assertEqual(page['statuses'], [200])
        self.assertEqual(page['url'], 'http://localhost:8080/lab/info')

    def test_zap_keeps_alert_instances_and_evidence_reference(self):
        data = {'site': [{'@name': 'http://localhost:8080', 'alerts': [{
            'pluginid': '99999', 'alert': '测试规则', 'cweid': '89', 'riskcode': '3',
            'instances': [{'uri': 'http://localhost:8080/lab?q=private', 'method': 'GET',
                           'param': 'q', 'evidence': '<script>secret</script>', 'attack': 'attack-secret'}],
        }]}]}
        result, = read_document(data)['findings']
        self.assertEqual(result['tool'], 'OWASP ZAP')
        self.assertEqual(result['url'], 'http://localhost:8080/lab?q')
        self.assertEqual(result['type'], 'SQL 注入')
        self.assertEqual(result['severity'], '高')
        self.assertEqual(result['review'], '待复核')
        self.assertIn('99999', result['reference'])
        self.assertTrue(result['evidence'])
        self.assertNotIn('secret', str(result))

    def test_course_report_preserves_review_and_validates_tools(self):
        row = {'tool': 'OWASP ZAP', 'title': '配置检查', 'type': '响应头', 'review': '误报',
               'url': 'http://LOCALHOST:80/lab?q=secret#private', 'evidence': '复核摘要'}
        raw = {'schema': 'course-evidence/v1', 'findings': [row]}
        result, = read_document(raw)['findings']
        self.assertEqual(result['url'], 'http://localhost/lab?q')
        self.assertEqual(result['review'], '误报')
        self.assertEqual(result['evidence'], '复核摘要')
        row['tool'] = 'invalid'
        with self.assertRaises(ImportProblem):
            read_document(raw)

    def test_zap_no_alerts_can_register_report_without_claiming_coverage(self):
        raw = {'site': [{'@name': 'http://localhost:8080', 'alerts': []}]}
        report = read_document(raw, target='DVWA')
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['coverage'], [{
            'target': 'DVWA', 'tool': 'OWASP ZAP', 'state': '已有报告',
            'scope': 'http://localhost:8080/', 'reference': 'ZAP Traditional JSON',
        }])

    def test_course_coverage_preserves_evidence_and_requires_review_basis(self):
        row = {'target': 'DVWA', 'tool': '长亭 xray', 'state': '已核对覆盖范围',
               'scope': '课程主页', 'reference': '脱敏记录第 1 条', 'source': 'original.json'}
        document = {'schema': 'course-evidence/v1', 'coverage': [row]}
        self.assertEqual(read_document(document)['coverage'], [row])
        row['reference'] = ''
        with self.assertRaises(ImportProblem):
            read_document(document)


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_dashboard_and_example(self):
        page = self.client.get('/')
        self.assertEqual(page.status_code, 200)
        self.assertIn("default-src 'none'", page.headers['Content-Security-Policy'])
        for asset in ('workspace.js', 'workspace.css'):
            with self.client.get('/static/' + asset) as response:
                self.assertEqual(response.status_code, 200)
        data = self.client.get('/api/example').get_json()
        self.assertEqual(len(data['pages']), 4)
        self.assertEqual(len(data['findings']), 3)
        self.assertEqual(page.text.count('待补证据'), 6)

    def test_source_audit_has_five_findings_and_no_scanner_coverage(self):
        data = self.client.get('/api/source-audit').get_json()
        self.assertEqual(len(data['findings']), 5)
        self.assertEqual(data['coverage'], [])
        focus, *other = data['findings']
        self.assertEqual((focus['parameter'], focus['type']), ('q', 'SQL 注入'))
        self.assertIn('第 192 行', focus['evidence'])
        self.assertTrue(all(row['tool'] == '静态代码审查' for row in [focus, *other]))

    def test_import_returns_400_for_unknown_file(self):
        response = self.client.post('/api/import', data={'document': (BytesIO(b'{}'), 'bogus.json')})
        self.assertEqual(response.status_code, 400)
        self.assertIn('HAR', response.get_json()['error'])

    def test_import_rejects_oversized_file(self):
        data = {'document': (BytesIO(b' ' * (MAX_BYTES + 1)), 'large.json')}
        with self.client.post('/api/import', data=data) as response:
            self.assertEqual(response.status_code, 413)

    def test_import_parses_utf8_bom_and_har_scope(self):
        har = {'log': {'entries': [entry('/lab/index', source='<title>记录</title>')]}}
        content = json.dumps(har, ensure_ascii=False).encode('utf-8-sig')
        response = self.client.post('/api/import', data={'document': (BytesIO(content), 'lab.har'), 'scope': SCOPE})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['pages'][0]['title'], '记录')

    def test_import_can_assign_zap_target(self):
        content = b'{"site":[{"@name":"http://localhost:8080","alerts":[]}]}'
        response = self.client.post('/api/import', data={
            'document': (BytesIO(content), 'zap.json'), 'target': 'DVWA',
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['coverage'][0]['target'], 'DVWA')


if __name__ == '__main__':
    unittest.main()
