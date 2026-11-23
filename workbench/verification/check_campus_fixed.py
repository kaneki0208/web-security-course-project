"""Record ordinary business responses from the campus app's fixed mode."""

import argparse
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import secrets
import sys
from tempfile import TemporaryDirectory
from urllib.parse import urlencode


WORKBENCH = Path(__file__).resolve().parents[1]
SOURCE = WORKBENCH.parent / 'campus' / 'app.py'
ORIGIN = 'http://127.0.0.1:5001'


def load_source():
    spec = spec_from_file_location('course_campus_fixed_app', SOURCE)
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def recorded_response(path, response):
    return {
        'request': {'url': ORIGIN + path},
        'response': {'status': response.status_code, 'content': {
            'mimeType': response.mimetype, 'text': response.text,
        }},
    }


def session_csrf(client):
    with client.session_transaction() as session:
        return session['csrf']


def run_business_checks():
    campus = load_source()
    with TemporaryDirectory(prefix='campus_fixed_business_') as directory:
        password = secrets.token_urlsafe(18)
        app = campus.create_app('fixed', directory, demo_password=password)
        app.testing = True
        client = app.test_client()
        assert client.get('/health').get_json()['mode'] == 'fixed', '未进入修复模式'


        gated = client.get('/equipment')
        assert gated.status_code == 302, '未登录时未跳转'
        login = client.get('/login')
        assert login.status_code == 200, '登录页未正常返回'
        signed_in = client.post('/login', data={
            'username': 'alice', 'password': password, 'csrf': session_csrf(client),
        })
        assert signed_in.status_code == 302, '测试账号登录失败'

        dashboard = client.get('/')
        catalog = client.get('/equipment')
        params = urlencode({'q': 'Sony', 'category': '影像设备'})
        search_path = '/equipment?' + params
        search = client.get(search_path)
        assert search.status_code == 200 and 'Sony A6400' in search.text, '设备搜索未返回预期设备'
        assert 'Epson' not in search.text, '设备搜索返回了其他设备'

        token = session_csrf(client)
        created = client.post('/api/bookings', json={'equipment_id': 1, 'purpose': '课程业务回归'},
                              headers={'X-CSRF-Token': token})
        assert created.status_code == 201, '借用申请创建失败'
        booking = client.get('/api/bookings/' + str(created.get_json()['id']))
        assert booking.get_json()['purpose'] == '课程业务回归', 'SQLite 回读不一致'
        bookings = client.get('/bookings')
        assert all(page.status_code == 200 for page in (dashboard, catalog, bookings)), '业务页面未正常返回'

        captures = [recorded_response(path, response) for path, response in (
            ('/login', login), ('/equipment', gated), ('/', dashboard),
            ('/equipment', catalog), (search_path, search), ('/bookings', bookings),
        )]
        return captures, (password, token)


def build_record():
    sys.path.insert(0, str(WORKBENCH))
    from imports import read_document

    captures, secrets_to_check = run_business_checks()
    parsed = read_document({'log': {'entries': captures}}, ORIGIN)
    pages = parsed['pages']
    assert len(pages) == 5 and all(page['title'] for page in pages), '页面清单解析不完整'
    equipment = next(page for page in pages if page['url'] == ORIGIN + '/equipment')
    assert equipment['statuses'] == [302, 200], '设备目录的状态记录不完整'
    search = next(page for page in pages if page['url'] == ORIGIN + '/equipment?category&q')
    assert search['query'] == ['category', 'q'], '查询参数名解析不完整'
    assert any({field['name'] for field in form['fields']} >= {'q', 'category'}
               for form in search['forms']), '搜索表单解析不完整'
    assert ORIGIN + '/bookings' in search['links'], '借用列表链接未识别'

    record = {
        'schema': 'course-evidence/v1',
        'provenance': {
            'target': '校园设备借用管理系统',
            'mode': 'fixed',
            'method': 'Flask 测试客户端进程内业务回归',
            'source': SOURCE.relative_to(WORKBENCH.parent).as_posix(),
            'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        },
        'pages': pages,
    }
    serialized = json.dumps(record, ensure_ascii=False, indent=2) + '\n'
    assert 'q=Sony' not in serialized and all(value not in serialized for value in secrets_to_check), '证据包含测试值'
    assert read_document(json.loads(serialized))['pages'] == pages, '证据重新导入后页面记录不同'
    return serialized, len(pages)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='可选的 JSON 输出文件，要求路径是新文件')
    args = parser.parse_args()
    serialized, count = build_record()
    if args.output:
        with args.output.open('x', encoding='utf-8', newline='\n') as output:
            output.write(serialized)
    print(f'修复模式业务回归通过，{count} 个页面的归档解析和重新导入通过。')


if __name__ == '__main__':
    main()
