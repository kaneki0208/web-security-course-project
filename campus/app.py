"""Local demonstration of the repaired campus equipment lending system."""
import argparse
import functools
import os
from pathlib import Path
import secrets
import sqlite3
import uuid

from flask import (Flask, abort, g, jsonify, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

ROOT = Path(__file__).resolve().parent


def create_app(mode='fixed', data_dir=None, *, demo_password=None):
    if mode != 'fixed':
        raise ValueError('Only the fixed application is available')
    app = Flask(__name__)
    data = Path(data_dir or os.environ.get('LAB_DATA', ROOT / 'instance' / mode))
    data.mkdir(parents=True, exist_ok=True)
    uploads = data / 'uploads'
    uploads.mkdir(exist_ok=True)
    app.config.update(SECRET_KEY=os.environ.get('LAB_SECRET') or secrets.token_hex(32),
                      DATABASE=str(data / 'lab.sqlite3'), MODE=mode,
                      MAX_CONTENT_LENGTH=1024 * 1024, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_NAME='lab_' + mode)

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DATABASE'])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(error=None):
        conn = g.pop('db', None)
        if conn:
            conn.close()

    with app.app_context():
        db().executescript('''
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT,
          display_name TEXT, role TEXT, email TEXT);
        CREATE TABLE IF NOT EXISTS equipment (
          id INTEGER PRIMARY KEY, name TEXT, category TEXT, location TEXT, stock INTEGER);
        CREATE TABLE IF NOT EXISTS bookings (
          id INTEGER PRIMARY KEY, user_id INTEGER, equipment_id INTEGER,
          purpose TEXT, status TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS notices (
          id INTEGER PRIMARY KEY, user_id INTEGER, body TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS attachments (
          id INTEGER PRIMARY KEY, user_id INTEGER, original_name TEXT, stored_name TEXT);
        ''')
        if db().execute('SELECT count(*) FROM users').fetchone()[0] == 0:
            password = demo_password or os.environ.get('CAMPUS_DEMO_PASSWORD')
            if not password:
                raise RuntimeError('Set CAMPUS_DEMO_PASSWORD before initializing the sample database.')
            for uid, username, name, role in [(1, 'alice', '林同学', 'student'),
                                              (2, 'bob', '陈同学', 'student'),
                                              (3, 'admin', '设备管理员', 'admin')]:
                db().execute('INSERT INTO users VALUES (?,?,?,?,?,?)',
                             (uid, username, generate_password_hash(password), name,
                              role, username + '@example.test'))
            db().executemany('INSERT INTO equipment VALUES (?,?,?,?,?)', [
                (1, 'Sony A6400 相机', '影像设备', '综合楼 A201', 4),
                (2, 'Epson 便携投影仪', '展示设备', '综合楼 A202', 3),
                (3, 'DJI 无线麦克风', '音频设备', '综合楼 A201', 6),
                (4, 'ThinkPad 实验笔记本', '计算设备', '实验楼 B305', 8),
                (5, '三脚架套装', '影像设备', '综合楼 A201', 10)])
            db().executemany('INSERT INTO bookings (id,user_id,equipment_id,purpose,status) VALUES (?,?,?,?,?)', [
                (1001, 1, 1, '学生社团宣传片拍摄', '待审批'),
                (1002, 2, 2, '小组课程答辩', '已批准')])
            db().execute('INSERT INTO notices (user_id,body) VALUES (?,?)',
                         (3, '请提前提交设备借用申请，并写明使用用途。借用结束后，请联系管理员登记归还。'))
            db().commit()

    def login_required(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not g.user:
                if request.path.startswith('/api/'):
                    return jsonify(error='请先登录'), 401
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return wrapper

    @app.before_request
    def load_user_and_check_csrf():
        g.user = db().execute('SELECT * FROM users WHERE id=?', (session.get('uid'),)).fetchone()
        session.setdefault('csrf', secrets.token_hex(24))
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            supplied = request.headers.get('X-CSRF-Token') or request.form.get('csrf', '')
            if not supplied.isascii() or not secrets.compare_digest(supplied, session['csrf']):
                abort(403, 'CSRF token missing or invalid')

    @app.context_processor
    def common():
        return dict(user=g.user, csrf=session.get('csrf', ''))

    @app.template_filter('local_time')
    def local_time(value):
        from datetime import datetime, timedelta
        try:
            return (datetime.strptime(value, '%Y-%m-%d %H:%M:%S') + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M')
        except (TypeError, ValueError):
            return value or '—'

    statuses = ('待审批', '已批准', '已归还', '已拒绝')

    def find_bookings(all_users=False, limit=None):
        conditions, params = [], []
        if not all_users:
            conditions.append('b.user_id=?')
            params.append(g.user['id'])
        q = request.args.get('q', '').strip()[:200]
        status = request.args.get('status', '')
        if status not in statuses:
            status = ''
        if q:
            conditions.append('(e.name LIKE ? OR b.purpose LIKE ? OR CAST(b.id AS TEXT) LIKE ?)')
            params.extend(['%' + q + '%'] * 3)
        if status:
            conditions.append('b.status=?')
            params.append(status)
        sql = 'SELECT b.*,e.name,u.display_name FROM bookings b JOIN equipment e ON e.id=b.equipment_id JOIN users u ON u.id=b.user_id'
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)
        sql += ' ORDER BY b.id DESC'
        if limit:
            sql += ' LIMIT ?'
            params.append(limit)
        rows = db().execute(sql, params).fetchall()
        scope = '' if all_users else ' WHERE user_id=?'
        scope_params = () if all_users else (g.user['id'],)
        counts = dict(db().execute('SELECT status,count(*) FROM bookings' + scope + ' GROUP BY status', scope_params).fetchall())
        return dict(rows=rows, q=q, selected_status=status, counts=counts,
                    total=sum(counts.values()), statuses=statuses)

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        return response

    @app.get('/health')
    def health():
        return jsonify(status='ok', mode=mode)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        if request.method == 'POST':
            row = db().execute('SELECT * FROM users WHERE username=?', (request.form.get('username', ''),)).fetchone()
            if row and check_password_hash(row['password'], request.form.get('password', '')):
                session.clear()
                session.update(uid=row['id'], csrf=secrets.token_hex(24))
                return redirect(url_for('dashboard'))
            error = '账号或密码错误'
        return render_template('login.html', error=error)

    @app.post('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.get('/')
    @login_required
    def dashboard():
        data = find_bookings(all_users=g.user['role'] == 'admin', limit=6)
        items = db().execute('SELECT * FROM equipment ORDER BY id').fetchall()
        return render_template('dashboard.html', items=items, **data)

    @app.get('/equipment')
    @login_required
    def equipment():
        q = request.args.get('q', '')[:300]
        category = request.args.get('category', '')
        categories = [r[0] for r in db().execute('SELECT DISTINCT category FROM equipment ORDER BY category')]
        error = None
        try:
            rows = db().execute(
                'SELECT id,name,category,location,stock FROM equipment WHERE name LIKE ?',
                ('%' + q + '%',),
            ).fetchall()
        except sqlite3.Error:
            app.logger.exception('Equipment search failed')
            rows, error = [], '暂时无法搜索设备。'
        if category:
            rows = [r for r in rows if r['category'] == category]
        return render_template('equipment.html', rows=rows, q=q, error=error,
                               category=category, categories=categories)

    @app.route('/notices', methods=['GET', 'POST'])
    @login_required
    def notices():
        if request.method == 'POST':
            body = request.form.get('body', '').strip()[:2000]
            if body:
                db().execute('INSERT INTO notices(user_id,body) VALUES (?,?)', (g.user['id'], body))
                db().commit()
            return redirect(url_for('notices'))
        rows = db().execute('SELECT n.*,u.display_name FROM notices n JOIN users u ON n.user_id=u.id ORDER BY n.id DESC').fetchall()
        return render_template('notices.html', rows=rows)

    @app.get('/bookings')
    @login_required
    def bookings():
        items = db().execute('SELECT * FROM equipment').fetchall()
        selected = request.args.get('equipment_id', type=int)
        return render_template('bookings.html', items=items, selected_equipment=selected,
                               open_form=request.args.get('new') == '1',
                               created=request.args.get('created', type=int), **find_bookings())

    @app.post('/api/bookings')
    @login_required
    def create_booking():
        body = request.get_json(silent=True) or {}
        equipment_id, purpose = body.get('equipment_id'), str(body.get('purpose', '')).strip()[:200]
        if not purpose or not db().execute('SELECT id FROM equipment WHERE id=?', (equipment_id,)).fetchone():
            return jsonify(error='请选择设备并填写用途'), 400
        cur = db().execute('INSERT INTO bookings(user_id,equipment_id,purpose,status) VALUES (?,?,?,?)', (g.user['id'], equipment_id, purpose, '待审批'))
        db().commit()
        return jsonify(id=cur.lastrowid, status='待审批'), 201

    @app.get('/api/bookings/<int:booking_id>')
    @login_required
    def booking_detail(booking_id):
        row = db().execute('SELECT b.*,e.name,u.username FROM bookings b JOIN equipment e ON e.id=b.equipment_id JOIN users u ON u.id=b.user_id WHERE b.id=?', (booking_id,)).fetchone()
        if row is None:
            abort(404)
        if row['user_id'] != g.user['id'] and g.user['role'] != 'admin':
            abort(403)
        return jsonify(dict(row))

    @app.route('/attachments', methods=['GET', 'POST'])
    @login_required
    def attachments():
        error = None
        if request.method == 'POST':
            uploaded = request.files.get('file')
            if not uploaded or not uploaded.filename:
                error = '请选择附件'
            else:
                original = secure_filename(uploaded.filename) or 'upload.bin'
                content = uploaded.read()
                if Path(original).suffix.lower() != '.txt' or b'\x00' in content:
                    abort(400, 'Only UTF-8 plain text .txt files are accepted')
                try:
                    content.decode('utf-8')
                except UnicodeDecodeError:
                    abort(400, 'Not UTF-8 text')
                stored = uuid.uuid4().hex + Path(original).suffix.lower()
                (uploads / stored).write_bytes(content)
                db().execute('INSERT INTO attachments(user_id,original_name,stored_name) VALUES (?,?,?)', (g.user['id'], original, stored))
                db().commit()
                return redirect(url_for('attachments'))
        rows = db().execute('SELECT * FROM attachments WHERE user_id=? ORDER BY id DESC', (g.user['id'],)).fetchall()
        return render_template('attachments.html', rows=rows, error=error)

    @app.get('/uploads/<name>')
    @login_required
    def uploaded_file(name):
        row = db().execute('SELECT * FROM attachments WHERE stored_name=?', (name,)).fetchone()
        if not row:
            abort(404)
        if row['user_id'] != g.user['id'] and g.user['role'] != 'admin':
            abort(403)
        return send_from_directory(uploads, name, as_attachment=True,
                                   mimetype='text/plain', download_name=row['original_name'])

    @app.get('/profile')
    @login_required
    def profile():
        return render_template('profile.html')

    @app.post('/profile/email')
    @login_required
    def change_email():
        email = request.values.get('email', '').strip()[:100]
        if '@' not in email or '\n' in email or '\r' in email:
            abort(400)
        db().execute('UPDATE users SET email=? WHERE id=?', (email, g.user['id']))
        db().commit()
        return redirect(url_for('profile', saved='1'))

    @app.route('/admin', methods=['GET', 'POST'])
    @login_required
    def admin():
        if g.user['role'] != 'admin':
            abort(403)
        if request.method == 'POST':
            status = request.form.get('status')
            if status not in ('已批准', '已归还', '已拒绝'):
                abort(400)
            db().execute('UPDATE bookings SET status=? WHERE id=?', (status, request.form.get('id')))
            db().commit()
            return redirect(url_for('admin'))
        return render_template('admin.html', **find_bookings(all_users=True))

    return app


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5001)
    args = parser.parse_args()
    create_app().run(host='127.0.0.1', port=args.port, debug=False, use_reloader=False, threaded=True)
