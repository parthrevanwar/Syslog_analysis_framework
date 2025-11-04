import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, render_template_string, request, jsonify
from collector.storage import Storage

app = Flask(__name__)
storage = Storage()

INDEX_HTML = '''
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Syslog Analysis Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="p-4">
<div class="container">
  <h1>Syslog Analysis Dashboard</h1>
  <form method="get" class="row g-2 mb-3">
    <div class="col-auto"><input class="form-control" name="ip" placeholder="src ip" value="{{ip}}"></div>
    <div class="col-auto"><input class="btn btn-primary" type="submit" value="Search"></div>
  </form>
  <h4>Recent Logs</h4>
  <table class="table table-sm">
    <thead><tr><th>TS</th><th>IP</th><th>Type</th><th>Host</th><th>Raw</th></tr></thead>
    <tbody>
    {% for r in rows %}
      <tr><td>{{r.ts|e}}</td><td>{{r.src_ip|e}}</td><td>{{r.event_type|e}}</td><td>{{r.host|e}}</td><td><code>{{r.raw|e}}</code></td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
</body>
</html>
'''

@app.route('/')
def index():
    ip = request.args.get('ip')
    rows = storage.search_recent(event_type=None, src_ip=ip)
    return render_template_string(INDEX_HTML, rows=rows, ip=ip or '')

@app.route('/api/search')
def api_search():
    ip = request.args.get('ip')
    rows = storage.search_recent(event_type=None, src_ip=ip)
    return jsonify(rows)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
