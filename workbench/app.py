from pathlib import Path
import json

from flask import Flask, jsonify, render_template, request

from imports import ImportProblem, SCAN_TOOLS, TARGETS, read_document


ROOT = Path(__file__).resolve().parent
MAX_BYTES = 24 * 1024 * 1024

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_BYTES + 64 * 1024


@app.after_request
def local_headers(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.get('/')
def index():
    return render_template('index.html', scan_tools=SCAN_TOOLS, targets=TARGETS)


@app.get('/api/example')
def example():
    data = json.loads((ROOT / 'examples' / 'demo.json').read_text(encoding='utf-8'))
    return jsonify(read_document(data))


@app.get('/api/source-audit')
def source_audit():
    data = json.loads((ROOT / 'evidence' / 'source-audit.json').read_text(encoding='utf-8'))
    return jsonify(read_document(data))


@app.post('/api/import')
def import_file():
    document = request.files.get('document')
    if not document or not document.filename:
        return jsonify(error='请选择 HAR 或 JSON 文件。'), 400
    content = document.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        return import_too_large(None)
    try:
        data = json.loads(content.decode('utf-8-sig'))
        return jsonify(read_document(data, request.form.get('scope', '').strip(), request.form.get('target', '')))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        return jsonify(error='无法读取文件，请使用 UTF-8 编码的 HAR 或 JSON。'), 400
    except ImportProblem as exc:
        return jsonify(error=str(exc)), 400


@app.errorhandler(413)
def import_too_large(_error):
    return jsonify(error='文件超过 24 MB，请缩小导出范围。'), 413


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5080)
