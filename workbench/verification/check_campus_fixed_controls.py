"""Verify defensive controls in the campus app's fixed mode."""

import argparse
from contextlib import closing
import hashlib
from html import unescape
from io import BytesIO
import json
from pathlib import Path
import secrets
import sqlite3
from tempfile import TemporaryDirectory

from check_campus_fixed import SOURCE, WORKBENCH, load_source, session_csrf


def run_checks():
    results = []

    def record(check, expected, observed):
        results.append({'check': check, 'expected': expected, 'observed': observed,
                        'passed': expected == observed})

    campus = load_source()
    with TemporaryDirectory(prefix='campus_fixed_controls_') as directory:
        password = secrets.token_urlsafe(18)
        app = campus.create_app('fixed', directory, demo_password=password)
        app.testing = True
        client = app.test_client()
        if client.get('/health').get_json()['mode'] != 'fixed':
            raise RuntimeError('回归测试要求 fixed 模式。')

        equipment_name = "O'Reilly 教学设备"
        with closing(sqlite3.connect(app.config['DATABASE'])) as db, db:
            db.execute('INSERT INTO equipment (name, category, location, stock) VALUES (?, ?, ?, ?)',
                       (equipment_name, '课堂测试', '测试库房', 1))
            rows = db.execute('SELECT u.username, b.id FROM bookings b JOIN users u ON u.id = b.user_id')
            bookings = dict(rows)

        record('设备目录要求登录', 302, client.get('/equipment').status_code)
        client.get('/login')
        login = client.post('/login', data={
            'username': 'alice', 'password': password, 'csrf': session_csrf(client),
        })
        if login.status_code != 302:
            raise RuntimeError('无法登录临时数据库中的测试账号。')
        token = session_csrf(client)

        search = client.get('/equipment', query_string={'q': "O'Reilly"})
        record('包含撇号的正常设备名可以搜索', {'状态码': 200, '匹配设备': True},
               {'状态码': search.status_code, '匹配设备': equipment_name in unescape(search.text)})

        record('学生可以读取自己的借用单', 200,
               client.get(f"/api/bookings/{bookings['alice']}").status_code)
        record('学生读取其他账号的借用单被拒绝', 403,
               client.get(f"/api/bookings/{bookings['bob']}").status_code)
        record('学生访问管理员页面被拒绝', 403, client.get('/admin').status_code)

        email = 'classroom-check@example.test'
        record('邮箱修改入口拒绝 GET', 405, client.get('/profile/email').status_code)
        no_token = client.post('/profile/email', data={'email': email})
        record('邮箱修改要求 CSRF 令牌', {'状态码': 403, '邮箱已修改': False},
               {'状态码': no_token.status_code, '邮箱已修改': email in client.get('/profile').text})
        changed = client.post('/profile/email', data={'email': email, 'csrf': token})
        record('带有效令牌的正常邮箱修改成功', {'状态码': 302, '邮箱已修改': True},
               {'状态码': changed.status_code, '邮箱已修改': email in client.get('/profile').text})

        message = '<b>课程记录</b>'
        posted = client.post('/notices', data={'body': message, 'csrf': token})
        notices = client.get('/notices').text
        record('留言按文本转义普通 HTML 格式标签', {'状态码': 302, '已转义': True},
               {'状态码': posted.status_code,
                '已转义': '&lt;b&gt;课程记录&lt;/b&gt;' in notices and message not in notices})

        contents = '课程附件回归记录'.encode('utf-8')
        rejected = client.post('/attachments', data={
            'csrf': token, 'file': (BytesIO(contents), 'classroom-sample.csv'),
        })
        record('附件拒绝 .csv 文件', 400, rejected.status_code)
        uploaded = client.post('/attachments', data={
            'csrf': token, 'file': (BytesIO(contents), 'classroom-sample.txt'),
        })
        with closing(sqlite3.connect(app.config['DATABASE'])) as db:
            saved = db.execute('SELECT stored_name FROM attachments WHERE original_name = ?',
                               ('classroom-sample.txt',)).fetchone()
        record('附件接受并保存 UTF-8 文本', {'状态码': 302, '附件已入库': True},
               {'状态码': uploaded.status_code, '附件已入库': saved is not None})
        if saved:
            download = client.get(f'/uploads/{saved[0]}')
            try:
                record('文本文件按附件下载', {'状态码': 200, '类型': 'text/plain', '附件下载': True, '内容一致': True},
                       {'状态码': download.status_code, '类型': download.mimetype,
                        '附件下载': download.headers.get('Content-Disposition', '').startswith('attachment'),
                        '内容一致': download.data == contents})
            finally:
                download.close()

        record('设备搜索页面设置安全响应头', {'CSP': True, 'X-Content-Type-Options': 'nosniff'},
               {'CSP': bool(search.headers.get('Content-Security-Policy')),
                'X-Content-Type-Options': search.headers.get('X-Content-Type-Options')})

    return {
        'experiment': '校园设备借用管理系统修复版安全回归',
        'mode': 'fixed',
        'method': 'Flask 测试客户端与临时 SQLite 数据库',
        'source': SOURCE.relative_to(WORKBENCH.parent).as_posix(),
        'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'checks': results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='可选的 JSON 输出文件，要求路径是新文件')
    args = parser.parse_args()
    report = run_checks()
    if args.output:
        with args.output.open('x', encoding='utf-8', newline='\n') as output:
            json.dump(report, output, ensure_ascii=False, indent=2)
            output.write('\n')
    checks = report['checks']
    passed = sum(check['passed'] for check in checks)
    for check in checks:
        status = '通过' if check['passed'] else '失败'
        print(f"{status} · {check['check']}")
    print(f'修复版安全回归 {passed}/{len(checks)} 项通过。')
    return int(passed != len(checks))


if __name__ == '__main__':
    raise SystemExit(main())
