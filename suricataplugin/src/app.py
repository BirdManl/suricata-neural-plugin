"""
Suricata NN Plugin — Web UI
Запуск: source ~/nn_venv/bin/activate && pip install flask && python3 app.py
Открыть: http://localhost:5000
"""

import json
import threading
import time
from pathlib import Path
from datetime import datetime
from collections import Counter

from flask import Flask, render_template_string, jsonify, request

app = Flask(__name__)

# ── Состояние приложения ──────────────────────────────────────
state = {
    'mode': 'idle',        # idle | running | tail
    'processed': 0,
    'attacks': 0,
    'errors': 0,
    'alerts': [],          # последние 200 алертов
    'log': [],             # лог сообщений
    'eve_path': '/var/log/suricata/eve.json',
    'model_dir': '/home/vboxuser/suricataplugin/data/models',
}
state_lock = threading.Lock()
tail_thread = None
stop_tail = threading.Event()

# ── Загрузка модели ───────────────────────────────────────────
plugin = None

def load_plugin():
    global plugin
    try:
        import sys
        sys.path.insert(0, '/home/vboxuser/suricataplugin/src')
        from suricata_nn_plugin import SuricataPlugin
        plugin = SuricataPlugin(model_dir=state['model_dir'])
        add_log('✅ Модель загружена', 'success')
    except Exception as e:
        add_log(f'❌ Ошибка загрузки модели: {e}', 'error')

def add_log(msg, level='info'):
    with state_lock:
        state['log'].append({
            'time': datetime.now().strftime('%H:%M:%S'),
            'msg': msg,
            'level': level
        })
        if len(state['log']) > 100:
            state['log'] = state['log'][-100:]

# ── Анализ файла ──────────────────────────────────────────────
def analyze_file(eve_path):
    if not plugin:
        add_log('❌ Модель не загружена', 'error')
        return

    with state_lock:
        state['mode'] = 'running'
        state['processed'] = 0
        state['attacks'] = 0
        state['errors'] = 0
        state['alerts'] = []

    add_log(f'📂 Анализ файла: {eve_path}', 'info')

    try:
        from suricata_nn_plugin import extract_features
        import numpy as np

        batch, BATCH_SIZE = [], 512
        total = 0

        with open(eve_path, encoding='utf-8') as f:
            lines = f.readlines()

        total_lines = len(lines)
        add_log(f'📊 Строк в файле: {total_lines:,}', 'info')

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                batch.append(json.loads(line))
            except:
                continue

            if len(batch) >= BATCH_SIZE:
                process_batch(batch)
                batch = []

        if batch:
            process_batch(batch)

    except Exception as e:
        add_log(f'❌ Ошибка: {e}', 'error')
    finally:
        with state_lock:
            s = state
            add_log(
                f'✅ Готово: обработано {s["processed"]:,}, '
                f'атак {s["attacks"]:,} ({s["attacks"]/max(s["processed"],1)*100:.1f}%)',
                'success'
            )
            state['mode'] = 'idle'


def process_batch(events):
    global plugin
    if not plugin:
        return

    from suricata_nn_plugin import extract_features
    import numpy as np

    vectors, meta = [], []
    for ev in events:
        try:
            vec = extract_features(ev)
            if vec is not None:
                vectors.append(vec)
                meta.append(ev)
        except:
            with state_lock:
                state['errors'] += 1

    if not vectors:
        return

    X = plugin.scaler.transform(np.array(vectors)).astype('float32')
    probas = plugin.session.run(None, {plugin.input_name: X})[0].flatten()

    with state_lock:
        state['processed'] += len(vectors)
        for ev, proba in zip(meta, probas):
            if proba >= plugin.threshold:
                state['attacks'] += 1
                alert = {
                    'time': ev.get('timestamp', '')[:19].replace('T', ' '),
                    'src':  f"{ev.get('src_ip')}:{ev.get('src_port')}",
                    'dst':  f"{ev.get('dest_ip')}:{ev.get('dest_port')}",
                    'proto': ev.get('proto', ''),
                    'conf': round(float(proba) * 100, 1),
                }
                state['alerts'].append(alert)
                if len(state['alerts']) > 200:
                    state['alerts'] = state['alerts'][-200:]


# ── Tail режим ────────────────────────────────────────────────
def tail_worker(eve_path):
    add_log(f'👁 Слежение за: {eve_path}', 'info')
    with state_lock:
        state['mode'] = 'tail'

    batch = []
    last_flush = time.time()

    try:
        with open(eve_path, encoding='utf-8') as f:
            f.seek(0, 2)
            while not stop_tail.is_set():
                line = f.readline()
                if line:
                    try:
                        batch.append(json.loads(line.strip()))
                    except:
                        pass
                else:
                    time.sleep(0.05)

                now = time.time()
                if len(batch) >= 64 or (batch and now - last_flush >= 2.0):
                    process_batch(batch)
                    batch = []
                    last_flush = now
    except Exception as e:
        add_log(f'❌ Ошибка tail: {e}', 'error')
    finally:
        with state_lock:
            state['mode'] = 'idle'
        add_log('⏹ Слежение остановлено', 'info')


# ── API ───────────────────────────────────────────────────────
@app.route('/api/status')
def api_status():
    with state_lock:
        s = dict(state)
        s['alerts'] = s['alerts'][-50:]  # последние 50
        s['log'] = s['log'][-20:]
    return jsonify(s)

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.json or {}
    eve_path = data.get('eve_path', state['eve_path'])
    if state['mode'] != 'idle':
        return jsonify({'error': 'Уже запущено'}), 400
    t = threading.Thread(target=analyze_file, args=(eve_path,), daemon=True)
    t.start()
    return jsonify({'ok': True})

@app.route('/api/tail/start', methods=['POST'])
def api_tail_start():
    global tail_thread
    data = request.json or {}
    eve_path = data.get('eve_path', state['eve_path'])
    if state['mode'] != 'idle':
        return jsonify({'error': 'Уже запущено'}), 400
    stop_tail.clear()
    tail_thread = threading.Thread(target=tail_worker, args=(eve_path,), daemon=True)
    tail_thread.start()
    return jsonify({'ok': True})

@app.route('/api/tail/stop', methods=['POST'])
def api_tail_stop():
    stop_tail.set()
    return jsonify({'ok': True})

@app.route('/api/clear', methods=['POST'])
def api_clear():
    with state_lock:
        state['alerts'] = []
        state['processed'] = 0
        state['attacks'] = 0
        state['errors'] = 0
        state['log'] = []
    return jsonify({'ok': True})

# ── HTML ──────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Suricata NN Plugin</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #0a0c0f;
  --surface: #111318;
  --card: #161a21;
  --border: #1e2530;
  --accent: #00ff88;
  --accent2: #ff3860;
  --accent3: #ffb800;
  --text: #e2e8f0;
  --muted: #4a5568;
  --mono: 'JetBrains Mono', monospace;
  --sans: 'Syne', sans-serif;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; }

/* Сетка */
.grid { display: grid; grid-template-columns: 280px 1fr; grid-template-rows: auto 1fr; min-height: 100vh; }

/* Заголовок */
header {
  grid-column: 1/-1;
  padding: 18px 28px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 16px;
  background: var(--surface);
}
.logo { font-size: 20px; font-weight: 800; letter-spacing: -0.5px; }
.logo span { color: var(--accent); }
.badge {
  font-family: var(--mono); font-size: 11px;
  padding: 3px 8px; border-radius: 4px;
  background: var(--border); color: var(--muted);
}
.badge.running { background: #00ff8820; color: var(--accent); animation: pulse 1.5s infinite; }
.badge.tail { background: #ffb80020; color: var(--accent3); animation: pulse 1.5s infinite; }
.badge.error { background: #ff386020; color: var(--accent2); }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }

/* Сайдбар */
aside {
  background: var(--surface);
  border-right: 1px solid var(--border);
  padding: 24px 20px;
  display: flex; flex-direction: column; gap: 20px;
}
.section-title {
  font-size: 10px; font-weight: 700; letter-spacing: 2px;
  color: var(--muted); text-transform: uppercase; margin-bottom: 10px;
}
input[type=text] {
  width: 100%; background: var(--card); border: 1px solid var(--border);
  color: var(--text); font-family: var(--mono); font-size: 11px;
  padding: 8px 10px; border-radius: 6px; outline: none;
  transition: border-color .2s;
}
input[type=text]:focus { border-color: var(--accent); }

.btn {
  width: 100%; padding: 10px; border-radius: 6px; border: none;
  font-family: var(--sans); font-size: 13px; font-weight: 700;
  cursor: pointer; transition: all .15s; letter-spacing: 0.3px;
}
.btn-primary { background: var(--accent); color: #000; }
.btn-primary:hover { filter: brightness(1.1); }
.btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }
.btn-warn { background: var(--accent3); color: #000; }
.btn-warn:hover { filter: brightness(1.1); }
.btn-danger { background: var(--accent2); color: #fff; }
.btn-danger:hover { filter: brightness(1.1); }
.btn-ghost {
  background: transparent; color: var(--muted);
  border: 1px solid var(--border);
}
.btn-ghost:hover { border-color: var(--muted); color: var(--text); }

.divider { border: none; border-top: 1px solid var(--border); }

/* Статы */
.stats { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.stat-card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 8px; padding: 12px 10px; text-align: center;
}
.stat-val {
  font-family: var(--mono); font-size: 22px; font-weight: 700;
  line-height: 1;
}
.stat-val.green { color: var(--accent); }
.stat-val.red { color: var(--accent2); }
.stat-val.yellow { color: var(--accent3); }
.stat-lbl { font-size: 10px; color: var(--muted); margin-top: 4px; letter-spacing: 1px; }

/* Лог */
.log-box {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 8px; padding: 10px; height: 160px;
  overflow-y: auto; font-family: var(--mono); font-size: 11px;
}
.log-line { padding: 2px 0; border-bottom: 1px solid var(--border); }
.log-line:last-child { border: none; }
.log-time { color: var(--muted); margin-right: 6px; }
.log-line.success .log-msg { color: var(--accent); }
.log-line.error .log-msg { color: var(--accent2); }
.log-line.info .log-msg { color: var(--text); }

/* Основная область */
main { padding: 24px; overflow-y: auto; display: flex; flex-direction: column; gap: 20px; }

.panel {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 10px; overflow: hidden;
}
.panel-header {
  padding: 14px 20px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
}
.panel-title { font-size: 13px; font-weight: 700; letter-spacing: 0.5px; }
.alert-count {
  font-family: var(--mono); font-size: 11px;
  background: #ff386020; color: var(--accent2);
  padding: 2px 8px; border-radius: 4px;
}

/* Таблица алертов */
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th {
  text-align: left; padding: 10px 16px;
  font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase;
  color: var(--muted); border-bottom: 1px solid var(--border);
  font-family: var(--mono);
}
td { padding: 9px 16px; border-bottom: 1px solid var(--border); font-family: var(--mono); }
tr:last-child td { border: none; }
tr:hover td { background: #ffffff05; }
.conf-high { color: var(--accent2); font-weight: 700; }
.conf-med  { color: var(--accent3); }
.conf-low  { color: var(--accent); }
.proto-tag {
  display: inline-block; padding: 1px 6px; border-radius: 3px;
  font-size: 10px; background: var(--border);
}
.empty-state {
  padding: 48px; text-align: center; color: var(--muted);
  font-size: 13px;
}

/* Скроллбар */
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
</style>
</head>
<body>
<div class="grid">

<header>
  <div class="logo">Suricata <span>NN</span> Plugin</div>
  <div class="badge" id="status-badge">IDLE</div>
  <div style="margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)" id="clock"></div>
</header>

<aside>
  <div>
    <div class="section-title">Пути</div>
    <div style="margin-bottom:8px">
      <div style="font-size:11px;color:var(--muted);margin-bottom:4px">eve.json</div>
      <input type="text" id="eve-path" value="/var/log/suricata/eve.json">
    </div>
  </div>

  <div>
    <div class="section-title">Анализ файла</div>
    <button class="btn btn-primary" id="btn-file" onclick="analyzeFile()">▶ Запустить анализ</button>
  </div>

  <hr class="divider">

  <div>
    <div class="section-title">Реальное время</div>
    <button class="btn btn-warn" id="btn-tail-start" onclick="startTail()">👁 Начать слежение</button>
    <button class="btn btn-danger" id="btn-tail-stop" onclick="stopTail()" style="margin-top:8px;display:none">⏹ Остановить</button>
  </div>

  <hr class="divider">

  <div>
    <div class="section-title">Статистика</div>
    <div class="stats">
      <div class="stat-card">
        <div class="stat-val green" id="stat-processed">0</div>
        <div class="stat-lbl">FLOWS</div>
      </div>
      <div class="stat-card">
        <div class="stat-val red" id="stat-attacks">0</div>
        <div class="stat-lbl">АТАК</div>
      </div>
      <div class="stat-card" style="grid-column:1/-1">
        <div class="stat-val yellow" id="stat-rate">0%</div>
        <div class="stat-lbl">ПРОЦЕНТ АТАК</div>
      </div>
    </div>
  </div>

  <hr class="divider">

  <div>
    <div class="section-title">Лог</div>
    <div class="log-box" id="log-box"></div>
  </div>

  <button class="btn btn-ghost" onclick="clearAll()">🗑 Очистить всё</button>
</aside>

<main>
  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">🚨 Обнаруженные атаки</div>
      <div class="alert-count" id="alert-count">0 алертов</div>
    </div>
    <div id="alerts-container">
      <div class="empty-state">Запустите анализ или начните слежение</div>
    </div>
  </div>
</main>

</div>

<script>
let lastAlertCount = 0;

function analyzeFile() {
  const eve = document.getElementById('eve-path').value;
  fetch('/api/analyze', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({eve_path: eve})
  });
}

function startTail() {
  const eve = document.getElementById('eve-path').value;
  fetch('/api/tail/start', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({eve_path: eve})
  });
  document.getElementById('btn-tail-start').style.display = 'none';
  document.getElementById('btn-tail-stop').style.display = 'block';
}

function stopTail() {
  fetch('/api/tail/stop', {method:'POST'});
  document.getElementById('btn-tail-start').style.display = 'block';
  document.getElementById('btn-tail-stop').style.display = 'none';
}

function clearAll() {
  fetch('/api/clear', {method:'POST'});
}

function confClass(c) {
  if (c >= 90) return 'conf-high';
  if (c >= 70) return 'conf-med';
  return 'conf-low';
}

function renderAlerts(alerts) {
  const c = document.getElementById('alerts-container');
  if (!alerts.length) {
    c.innerHTML = '<div class="empty-state">Атак не обнаружено</div>';
    return;
  }
  const rows = [...alerts].reverse().map(a => `
    <tr>
      <td>${a.time}</td>
      <td>${a.src}</td>
      <td>${a.dst}</td>
      <td><span class="proto-tag">${a.proto}</span></td>
      <td class="${confClass(a.conf)}">${a.conf}%</td>
    </tr>`).join('');
  c.innerHTML = `<table>
    <thead><tr>
      <th>Время</th><th>Источник</th><th>Назначение</th><th>Протокол</th><th>Уверенность</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderLog(logs) {
  const box = document.getElementById('log-box');
  box.innerHTML = logs.map(l => `
    <div class="log-line ${l.level}">
      <span class="log-time">${l.time}</span>
      <span class="log-msg">${l.msg}</span>
    </div>`).join('');
  box.scrollTop = box.scrollHeight;
}

function updateBadge(mode) {
  const b = document.getElementById('status-badge');
  b.className = 'badge';
  if (mode === 'running') { b.textContent = 'АНАЛИЗ'; b.classList.add('running'); }
  else if (mode === 'tail') { b.textContent = 'СЛЕЖЕНИЕ'; b.classList.add('tail'); }
  else { b.textContent = 'IDLE'; }
}

function updateBtns(mode) {
  document.getElementById('btn-file').disabled = mode !== 'idle';
  if (mode === 'tail') {
    document.getElementById('btn-tail-start').style.display = 'none';
    document.getElementById('btn-tail-stop').style.display = 'block';
  } else if (mode === 'idle') {
    document.getElementById('btn-tail-start').style.display = 'block';
    document.getElementById('btn-tail-stop').style.display = 'none';
  }
}

async function poll() {
  try {
    const r = await fetch('/api/status');
    const s = await r.json();

    document.getElementById('stat-processed').textContent = s.processed.toLocaleString('ru');
    document.getElementById('stat-attacks').textContent = s.attacks.toLocaleString('ru');
    const rate = s.processed > 0 ? (s.attacks/s.processed*100).toFixed(1) : '0';
    document.getElementById('stat-rate').textContent = rate + '%';
    document.getElementById('alert-count').textContent = s.alerts.length + ' алертов';

    renderAlerts(s.alerts);
    renderLog(s.log);
    updateBadge(s.mode);
    updateBtns(s.mode);
  } catch(e) {}
}

// Часы
setInterval(() => {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString('ru');
}, 1000);

// Поллинг каждые 1.5 сек
setInterval(poll, 1500);
poll();
</script>
</body>
</html>"""

@app.route('/')
def index():
    return HTML

if __name__ == '__main__':
    print('🔄 Загрузка модели...')
    load_plugin()
    print('🌐 Открой в браузере: http://localhost:5000')
    app.run(host='0.0.0.0', port=5000, debug=False)
